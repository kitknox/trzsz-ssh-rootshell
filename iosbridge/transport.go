/*
MIT License

Copyright (c) 2023-2026 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package iosbridge

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trzsz/tsshd/tsshd"
)

// TransportConfig holds connection parameters for the UDP transport.
// These values come from the tsshd JSON output after SSH spawn.
//
// This struct is gomobile-compatible and uses simple types.
type TransportConfig struct {
	// Host is the IP address or hostname to connect to
	Host string

	// Port is the UDP port tsshd is listening on
	Port int

	// ServerVersion is the tsshd version string
	ServerVersion string

	// Mode is the transport mode: "KCP" or "QUIC"
	Mode string

	// For KCP mode: hex-encoded password and salt for AES-GCM
	// Note: Named "KcpPass" not "KcpPass" to work around gomobile binding bug
	// with consecutive capitals
	KcpPass string
	KcpSalt string

	// For QUIC mode: hex-encoded certificates
	ServerCert string
	ClientCert string
	ClientKey  string

	// Proxy authentication (common to both modes)
	ProxyKey string
	ClientID int64
	ServerID int64

	// ProxyMode for NAT traversal (optional)
	ProxyMode string

	// Timeouts (optional, uses defaults if zero)
	ConnectTimeoutSec   int
	AliveTimeoutSec     int
	HeartbeatTimeoutSec int

	// InitialSerialNumber seeds the roaming auth serial for resume across app termination.
	// If zero, default behavior is unchanged.
	InitialSerialNumber int64

	// Debug enables verbose logging
	Debug bool
}

// NewTransportConfig creates a new TransportConfig with default values.
func NewTransportConfig() *TransportConfig {
	return &TransportConfig{
		ConnectTimeoutSec:   30,
		AliveTimeoutSec:     24 * 3600, // 24 hours
		HeartbeatTimeoutSec: 3,
	}
}

// SetKcpCredentials sets the KCP password and salt.
// Use this method instead of setting properties directly due to gomobile binding issues.
func (c *TransportConfig) SetKcpCredentials(pass, salt string) {
	c.KcpPass = pass
	c.KcpSalt = salt
}

// SetQuicCredentials sets the QUIC certificates.
func (c *TransportConfig) SetQuicCredentials(serverCert, clientCert, clientKey string) {
	c.ServerCert = serverCert
	c.ClientCert = clientCert
	c.ClientKey = clientKey
}

// ParseFromJSON parses a TransportConfig from tsshd JSON output.
// The JSON should contain the ServerInfo fields from tsshd spawn output.
func ParseTransportConfig(jsonStr string) (*TransportConfig, error) {
	var raw struct {
		ServerVer  string `json:"ServerVer"`
		Port       int    `json:"Port"`
		Mode       string `json:"Mode"`
		Pass       string `json:"Pass"`
		Salt       string `json:"Salt"`
		ServerCert string `json:"ServerCert"`
		ClientCert string `json:"ClientCert"`
		ClientKey  string `json:"ClientKey"`
		ProxyKey   string `json:"ProxyKey"`
		ClientID   int64  `json:"ClientID"`
		ServerID   int64  `json:"ServerID"`
		ProxyMode  string `json:"ProxyMode"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil, fmt.Errorf("failed to parse server info JSON: %w", err)
	}

	if raw.Mode == "" {
		return nil, fmt.Errorf("missing Mode in server info")
	}
	if raw.Port == 0 {
		return nil, fmt.Errorf("missing Port in server info")
	}

	cfg := NewTransportConfig()
	cfg.ServerVersion = raw.ServerVer
	cfg.Port = raw.Port
	cfg.Mode = raw.Mode
	cfg.KcpPass = raw.Pass
	cfg.KcpSalt = raw.Salt
	cfg.ServerCert = raw.ServerCert
	cfg.ClientCert = raw.ClientCert
	cfg.ClientKey = raw.ClientKey
	cfg.ProxyKey = raw.ProxyKey
	cfg.ClientID = raw.ClientID
	cfg.ServerID = raw.ServerID
	cfg.ProxyMode = raw.ProxyMode

	return cfg, nil
}

// Validate checks if the TransportConfig has required fields.
func (c *TransportConfig) Validate() string {
	if c.Host == "" {
		return "host is required"
	}
	if c.Port < 1 || c.Port > 65535 {
		return "port must be between 1 and 65535"
	}
	if c.Mode != "KCP" && c.Mode != "QUIC" {
		return "mode must be KCP or QUIC"
	}
	if c.Mode == "KCP" {
		if c.KcpPass == "" || c.KcpSalt == "" {
			return "KCP mode requires Pass and Salt"
		}
	}
	if c.Mode == "QUIC" {
		if c.ServerCert == "" || c.ClientCert == "" || c.ClientKey == "" {
			return "QUIC mode requires ServerCert, ClientCert, and ClientKey"
		}
	}
	return ""
}

// toServerInfo converts to tsshd.ServerInfo
func (c *TransportConfig) toServerInfo() *tsshd.ServerInfo {
	return &tsshd.ServerInfo{
		ServerVer:  c.ServerVersion,
		Port:       c.Port,
		Mode:       c.Mode,
		Pass:       c.KcpPass,
		Salt:       c.KcpSalt,
		ServerCert: c.ServerCert,
		ClientCert: c.ClientCert,
		ClientKey:  c.ClientKey,
		ProxyKey:   c.ProxyKey,
		ClientID:   uint64(c.ClientID),
		ServerID:   uint64(c.ServerID),
		ProxyMode:  c.ProxyMode,
	}
}

// Transport wraps a tsshd UDP client for iOS.
// Use ConnectTransport() to create a Transport after SSH spawns tsshd.
//
// This provides KCP/QUIC transport without any SSH authentication logic.
// SSH is handled entirely on the Swift side.
type Transport struct {
	client  *tsshd.SshUdpClient
	config  *TransportConfig
	session *TransportSession

	mu     sync.Mutex
	closed atomic.Bool

	// Callback for state changes
	stateCallback TransportStateCallback

	// Pending discard marker to clear server-side pending input discard state.
	pendingDiscardMarker []byte
}

// TransportStateCallback receives transport state changes.
type TransportStateCallback interface {
	// OnStateChange is called when transport state changes.
	// States: "connecting", "connected", "reconnecting", "disconnected"
	OnStateChange(state string)

	// OnReconnecting is called during reconnection attempts.
	OnReconnecting(attempt int)

	// OnError is called when a transport error occurs.
	OnError(message string)
}

// noOpTransportStateCallback is a no-op implementation.
type noOpTransportStateCallback struct{}

func (n *noOpTransportStateCallback) OnStateChange(state string) {}
func (n *noOpTransportStateCallback) OnReconnecting(attempt int) {}
func (n *noOpTransportStateCallback) OnError(message string)     {}

// ConnectTransport establishes a KCP/QUIC transport connection.
// This should be called AFTER SSH has spawned tsshd and returned the server info.
//
// config contains the connection parameters from tsshd JSON output.
// Returns a Transport that can create sessions.
func ConnectTransport(config *TransportConfig) (*Transport, error) {
	if err := config.Validate(); err != "" {
		return nil, fmt.Errorf("invalid config: %s", err)
	}

	transport := &Transport{
		config:        config,
		stateCallback: &noOpTransportStateCallback{},
	}

	serverInfo := config.toServerInfo()
	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)

	// Set timeouts
	connectTimeout := time.Duration(config.ConnectTimeoutSec) * time.Second
	if connectTimeout == 0 {
		connectTimeout = 30 * time.Second
	}
	aliveTimeout := time.Duration(config.AliveTimeoutSec) * time.Second
	if aliveTimeout == 0 {
		aliveTimeout = 24 * time.Hour
	}
	heartbeatTimeout := time.Duration(config.HeartbeatTimeoutSec) * time.Second
	if heartbeatTimeout == 0 {
		heartbeatTimeout = 3 * time.Second
	}
	intervalTime := min(aliveTimeout/10, min(heartbeatTimeout, 15*time.Second)/3)

	opts := &tsshd.UdpClientOptions{
		EnableDebugging:  config.Debug,
		EnableWarning:    true,
		TsshdAddr:        addr,
		ServerInfo:       serverInfo,
		AliveTimeout:     aliveTimeout,
		IntervalTime:     intervalTime,
		ConnectTimeout:   connectTimeout,
		HeartbeatTimeout: heartbeatTimeout,
		DiscardCallback: func(discardMarker, discardedInput []byte) {
			if len(discardMarker) > 0 {
				transport.enqueueDiscardMarker(discardMarker)
			}
			// We don't buffer local input in the bridge, so discardedInput can be ignored.
		},
	}
	if config.InitialSerialNumber > 0 {
		opts.InitialSerialNumber = uint64(config.InitialSerialNumber)
	}

	if config.Debug {
		opts.DebugFunc = func(msec int64, msg string) {
			fmt.Printf("[tsshd %d] %s\n", msec, msg)
		}
	}
	opts.WarningFunc = func(msg string) {
		fmt.Printf("[tsshd WARN] %s\n", msg)
	}

	client, err := tsshd.NewSshUdpClient(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect transport: %w", err)
	}

	transport.client = client
	return transport, nil
}

// SetStateCallback sets the callback for transport state changes.
func (t *Transport) SetStateCallback(callback TransportStateCallback) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if callback != nil {
		t.stateCallback = callback
	} else {
		t.stateCallback = &noOpTransportStateCallback{}
	}
}

// NewSession creates a new transport session for running a shell.
// Only one session can be active at a time per transport.
func (t *Transport) NewSession() (*TransportSession, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed.Load() {
		return nil, fmt.Errorf("transport is closed")
	}

	if t.session != nil && !t.session.closed.Load() {
		return nil, fmt.Errorf("session already exists")
	}

	session, err := t.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	ts := &TransportSession{
		session:   session,
		transport: t,
		stopChan:  make(chan struct{}),
		callback:  &noOpOutputCallback{},
	}

	t.session = ts
	return ts, nil
}

func (t *Transport) enqueueDiscardMarker(marker []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// If we have an active session with stdin, write immediately.
	if t.session != nil && t.session.stdin != nil && t.session.started.Load() && !t.session.closed.Load() {
		_, _ = t.session.stdin.Write(marker)
		return
	}

	// Otherwise store it to send once the session starts.
	t.pendingDiscardMarker = append([]byte(nil), marker...)
}

func (t *Transport) flushPendingDiscardMarker() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.pendingDiscardMarker) == 0 {
		return
	}
	if t.session == nil || t.session.stdin == nil || !t.session.started.Load() || t.session.closed.Load() {
		return
	}
	_, _ = t.session.stdin.Write(t.pendingDiscardMarker)
	t.pendingDiscardMarker = nil
}

// Close closes the transport connection.
func (t *Transport) Close() error {
	if !t.closed.CompareAndSwap(false, true) {
		return nil
	}

	t.mu.Lock()
	if t.session != nil {
		_ = t.session.Close()
	}
	t.mu.Unlock()

	return t.client.Close()
}

// IsClosed returns true if the transport has been closed.
func (t *Transport) IsClosed() bool {
	return t.closed.Load()
}

// GetMode returns the transport mode ("KCP" or "QUIC").
func (t *Transport) GetMode() string {
	return t.config.Mode
}

// GetLastActiveTime returns the last confirmed activity time (Unix milliseconds).
func (t *Transport) GetLastActiveTime() int64 {
	return t.client.GetLastActiveTime()
}

// IsTimeout returns true if the transport is currently in a timeout state
// (i.e., no activity for longer than the heartbeat timeout).
func (t *Transport) IsTimeout() bool {
	lastActive := t.client.GetLastActiveTime()
	if lastActive <= 0 {
		return false
	}
	// Use heartbeat timeout from config (default 3 seconds)
	heartbeatMs := int64(t.config.HeartbeatTimeoutSec * 1000)
	if heartbeatMs <= 0 {
		heartbeatMs = 3000
	}
	now := time.Now().UnixMilli()
	return (now - lastActive) > heartbeatMs
}

// GetLastReconnectError returns the last error encountered during reconnection.
// Returns nil if no reconnection error occurred.
func (t *Transport) GetLastReconnectError() error {
	return t.client.GetLastReconnectError()
}

// TransportSession represents a shell session over the transport.
type TransportSession struct {
	session   *tsshd.SshUdpSession
	transport *Transport

	stdin  io.WriteCloser
	stdout io.Reader

	callback TSSHOutputCallback
	mu       sync.Mutex
	closed   atomic.Bool
	started  atomic.Bool

	stopChan chan struct{}
	wg       sync.WaitGroup

	// Track last send time for stuck stream detection
	lastSendTime atomic.Int64
}

// Setenv sets an environment variable for the session.
// Must be called before Shell() or Start().
func (s *TransportSession) Setenv(name, value string) error {
	if s.closed.Load() {
		return fmt.Errorf("session is closed")
	}
	if s.started.Load() {
		return fmt.Errorf("session already started")
	}
	return s.session.Setenv(name, value)
}

// RequestPty requests a pseudo-terminal.
func (s *TransportSession) RequestPty(term string, rows, cols int) error {
	if s.closed.Load() {
		return fmt.Errorf("session is closed")
	}
	if s.started.Load() {
		return fmt.Errorf("session already started")
	}
	return s.session.RequestPty(term, rows, cols, nil)
}

// Shell starts an interactive shell.
func (s *TransportSession) Shell() error {
	if s.closed.Load() {
		return fmt.Errorf("session is closed")
	}
	if !s.started.CompareAndSwap(false, true) {
		return fmt.Errorf("session already started")
	}

	var err error
	s.stdin, err = s.session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	s.stdout, err = s.session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	if err := s.session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}

	s.startOutputForwarding()
	s.transport.flushPendingDiscardMarker()
	return nil
}

// Write sends input to the shell.
// Thread-safe: uses mutex to prevent interleaving with WindowChange.
func (s *TransportSession) Write(data []byte) error {
	if s.closed.Load() {
		return fmt.Errorf("session is closed")
	}
	if !s.started.Load() {
		return fmt.Errorf("session not started")
	}
	if s.stdin == nil {
		return fmt.Errorf("stdin not available")
	}

	// Track when we last sent data for stuck stream detection
	s.lastSendTime.Store(time.Now().UnixMilli())

	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.stdin.Write(data)
	return err
}

// WindowChange notifies the remote host of a terminal size change.
// Thread-safe: uses mutex to prevent interleaving with Write.
func (s *TransportSession) WindowChange(rows, cols int) error {
	if s.closed.Load() {
		return fmt.Errorf("session is closed")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session.WindowChange(rows, cols)
}

// SetOutputCallback sets the callback for receiving session output.
func (s *TransportSession) SetOutputCallback(callback TSSHOutputCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if callback != nil {
		s.callback = callback
	} else {
		s.callback = &noOpOutputCallback{}
	}
}

// Close closes the session.
func (s *TransportSession) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(s.stopChan)

	if s.stdin != nil {
		_ = s.stdin.Close()
	}

	err := s.session.Close()
	s.wg.Wait()

	s.mu.Lock()
	callback := s.callback
	s.mu.Unlock()
	callback.OnClose()

	return err
}

// Wait waits for the session to end.
func (s *TransportSession) Wait() error {
	return s.session.Wait()
}

// GetExitCode returns the exit code from the remote command.
func (s *TransportSession) GetExitCode() int {
	return s.session.GetExitCode()
}

// IsClosed returns true if the session has been closed.
func (s *TransportSession) IsClosed() bool {
	return s.closed.Load()
}

func (s *TransportSession) startOutputForwarding() {
	if s.stdout != nil {
		s.wg.Add(1)
		go s.forwardOutput()
	}
}

func (s *TransportSession) forwardOutput() {
	defer s.wg.Done()

	buf := make([]byte, 32*1024)
	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		n, err := s.stdout.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])

			s.mu.Lock()
			callback := s.callback
			s.mu.Unlock()

			callback.OnOutput(data)
		}

		if err != nil {
			s.mu.Lock()
			callback := s.callback
			s.mu.Unlock()

			if err == io.EOF {
				// Graceful end of output - wait for session to get exit code
				_ = s.session.Wait()
				exitCode := s.session.GetExitCode()
				callback.OnExit(exitCode)
			} else {
				// Error during read
				callback.OnError(fmt.Sprintf("read error: %v", err))
			}
			return
		}
	}
}
