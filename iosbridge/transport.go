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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trzsz/tsshd/tsshd"
)

// ROOTSHELL: DebugLogger allows the host app (Swift) to receive tsshd debug and warning
// messages for file-based logging. Set via SetDebugLogger() before ConnectTransport().
// When set, debug logging is always enabled regardless of TransportConfig.Debug.

// DebugLogger receives debug and warning messages from the transport layer.
type DebugLogger interface {
	// OnDebug is called for debug messages. Called from background goroutines.
	OnDebug(msg string)
}

// globalDebugLogger is the package-level debug logger set by the host app.
var globalDebugLogger struct {
	sync.RWMutex
	logger DebugLogger
}

// SetDebugLogger sets a global debug logger for all transports.
// Call this before ConnectTransport(). Pass nil to disable.
func SetDebugLogger(logger DebugLogger) {
	globalDebugLogger.Lock()
	defer globalDebugLogger.Unlock()
	globalDebugLogger.logger = logger
}

func getDebugLogger() DebugLogger {
	globalDebugLogger.RLock()
	defer globalDebugLogger.RUnlock()
	return globalDebugLogger.logger
}

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

	// Mtu overrides the default packet MTU (1400) for KCP/QUIC.
	// Zero means use default. Both client and server must match.
	Mtu int

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
		MTU        int    `json:"MTU"`
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
	cfg.Mtu = raw.MTU

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
		MTU:        uint16(c.Mtu),
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

	// Agent forwarding stop channel — closed in Close() to stop the agent goroutine.
	agentStopChan chan struct{}

	// Pending discard marker to clear server-side pending input discard state.
	pendingDiscardMarker []byte

	// Last sent discard marker, used to deduplicate. The server has a race
	// condition where enablePendingInputDiscard() spawns goroutines that
	// capture discardPendingInputMarker by reference, causing the same marker
	// to be sent via bus multiple times. Without deduplication, the server
	// finds the first copy, clears the flag, and the second copy passes
	// through to the shell as garbage characters.
	lastSentMarker []byte
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
			// Send the marker back through the session stdin so the server's
			// discardPendingInput() finds it and clears discardPendingInputFlag.
			// Without this, the server discards ALL input forever after reconnect.
			// Any marker bytes that leak into output are stripped by discardMarkerFilter.
			if len(discardMarker) > 0 {
				transport.enqueueDiscardMarker(discardMarker)
			}
		},
	}
	// MTU is now on ServerInfo in upstream, set it there
	if config.Mtu > 0 {
		serverInfo.MTU = uint16(config.Mtu)
	}

	// ROOTSHELL: Route debug/warning output through the global DebugLogger when set,
	// enabling file-based logging on iOS where stdout goes nowhere.
	if dl := getDebugLogger(); dl != nil {
		opts.EnableDebugging = true
		opts.DebugFunc = func(msec int64, msg string) {
			dl.OnDebug(fmt.Sprintf("[tsshd %d] %s", msec, msg))
		}
		opts.WarningFunc = func(msg string) {
			dl.OnDebug(fmt.Sprintf("[tsshd WARN] %s", msg))
		}
	} else if config.Debug {
		opts.DebugFunc = func(msec int64, msg string) {
			fmt.Printf("[tsshd %d] %s\n", msec, msg)
		}
		opts.WarningFunc = func(msg string) {
			fmt.Printf("[tsshd WARN] %s\n", msg)
		}
	} else {
		opts.WarningFunc = func(msg string) {
			fmt.Printf("[tsshd WARN] %s\n", msg)
		}
	}

	client, err := tsshd.NewSshUdpClient(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect transport: %w", err)
	}

	transport.client = client

	// In attachable mode (ClientID == 0), mark the client so forwardInput
	// won't send CloseWrite on exit, preserving the server session.
	if config.ClientID == 0 {
		client.SetAttachable(true)
	}

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

// AttachSession creates a new session stream and attaches to an existing
// server-side session by ID. Use this to resume a session after app restart.
// The sessionID should have been saved from GetSessionID() on a previous session.
func (t *Transport) AttachSession(sessionID int64, term string, rows, cols int) (*TransportSession, error) {
	// Create a fresh session (new SMUX stream)
	ts, err := t.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session for attach: %w", err)
	}

	// Request PTY before attach
	if err := ts.RequestPty(term, rows, cols); err != nil {
		_ = ts.Close()
		return nil, fmt.Errorf("failed to request pty for attach: %w", err)
	}

	// Set up I/O pipes BEFORE Attach — startSession() only starts forwarding
	// goroutines if stdin/stdout are already set when it runs.
	ts.stdin, err = ts.session.StdinPipe()
	if err != nil {
		_ = ts.Close()
		return nil, fmt.Errorf("failed to get stdin pipe: %w", err)
	}
	ts.stdout, err = ts.session.StdoutPipe()
	if err != nil {
		_ = ts.Close()
		return nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	// Attach to existing session (starts forwarding goroutines internally)
	if err := ts.session.Attach(uint64(sessionID)); err != nil {
		_ = ts.Close()
		return nil, fmt.Errorf("failed to attach to session %d: %w", sessionID, err)
	}

	ts.started.Store(true)
	ts.startOutputForwarding()
	t.flushPendingDiscardMarker()
	return ts, nil
}

func (t *Transport) enqueueDiscardMarker(marker []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Deduplicate: the server may send the same marker multiple times due to
	// a race condition in enablePendingInputDiscard() goroutines.
	if bytes.Equal(t.lastSentMarker, marker) {
		return
	}
	t.lastSentMarker = append([]byte(nil), marker...)

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

// ROOTSHELL: WakeTransport sends an immediate keepalive to accelerate session
// resumption after the iOS app returns from background. This avoids the up to
// 3× intervalTime delay of waiting for keepAlive()'s normal cycle. The keepalive
// packet triggers onClientActive() on the server, immediately clearing the
// timeout and resuming output delivery.
// Best-effort: if the bus is dead, this is a no-op.
func (t *Transport) WakeTransport() {
	if t.client != nil {
		t.client.SendKeepAlive()
	}
}

// ROOTSHELL: SuppressRekey prevents the KCP rekey timer from firing while the
// iOS app is backgrounded. Call this when the app enters background. Without
// this, the Go time.Ticker accumulates ticks during process suspension and
// fires them all on resume, triggering a rekey handshake that races with
// pktCache replay and stale bus state — causing GCM auth failures.
func (t *Transport) SuppressRekey() {
	if t.client != nil {
		t.client.SuppressRekey()
	}
}

// ROOTSHELL: ResumeRekey re-enables the KCP rekey timer after the iOS app
// returns to foreground. Call this when the app enters foreground, BEFORE
// calling WakeTransport().
func (t *Transport) ResumeRekey() {
	if t.client != nil {
		t.client.ResumeRekey()
	}
}

// Close closes the transport connection and tells the server to shut down.
func (t *Transport) Close() error {
	if !t.closed.CompareAndSwap(false, true) {
		return nil
	}

	t.mu.Lock()
	if t.agentStopChan != nil {
		close(t.agentStopChan)
		t.agentStopChan = nil
	}
	if t.session != nil {
		_ = t.session.Close()
	}
	t.mu.Unlock()

	return t.client.Close()
}

// Abandon silently disconnects without sending ANY signals to the server.
// Use this when preserving the server session for future Attach().
// Does not close the session, bus stream, SMUX session, or KCP connection —
// any of those would send FIN/close frames that the server would interpret
// as the client explicitly disconnecting, killing the session.
// Resources are cleaned up when the process exits.
func (t *Transport) Abandon() {
	if !t.closed.CompareAndSwap(false, true) {
		return
	}
	// Intentionally do nothing. Don't close session (sends "exit" on bus),
	// don't close client (sends SMUX/KCP close frames).
	// Just mark as closed and let the process die silently.
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

// StartCommand starts a specific command (exec request) instead of an interactive shell.
// The remote server will exec the command directly with a PTY.
func (s *TransportSession) StartCommand(command string) error {
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

	if err := s.session.Start(command); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
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

// GetSessionID returns the session ID assigned by the server.
// This must be saved for future Attach() calls after app restart.
func (s *TransportSession) GetSessionID() int64 {
	return int64(s.session.GetID())
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

// discardMarkerMagic is the 4-byte prefix of discard markers (0xFF 0xC0 0xC1 0xFF).
// 0xFF is never valid UTF-8, so this cannot appear in legitimate terminal output.
var discardMarkerMagic = []byte{0xFF, 0xC0, 0xC1, 0xFF}

// discardMarkerFilter strips discard marker bytes from output data.
// Handles both raw markers (8 bytes) and ECHOCTL-expanded echoes (up to 12 bytes)
// where control chars in the index are expanded to ^X sequences.
// Handles markers that span across read boundaries using a holdback buffer.
type discardMarkerFilter struct {
	partial []byte // buffered bytes that might be part of a marker
}

// consumeMarkerIndex consumes 4 logical index bytes from data[pos:], accounting for
// ECHOCTL expansion where control chars (0x00-0x1F, 0x7F) are echoed as 2-byte ^X pairs.
// Returns the number of raw bytes consumed, or -1 if not enough data.
func consumeMarkerIndex(data []byte, pos int) int {
	consumed := 0
	for logicalBytes := 0; logicalBytes < 4; logicalBytes++ {
		if pos+consumed >= len(data) {
			return -1 // not enough data
		}
		b := data[pos+consumed]
		if b == 0x5E && pos+consumed+1 < len(data) {
			// Could be ECHOCTL expansion: ^@ through ^_ (0x5E 0x40-0x5F) or ^? (0x5E 0x3F)
			next := data[pos+consumed+1]
			if next >= 0x3F && next <= 0x5F {
				consumed += 2 // ECHOCTL pair
				continue
			}
		}
		consumed++ // raw byte
	}
	return consumed
}

// filter removes any discard markers from data, returning clean output.
func (f *discardMarkerFilter) filter(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	// Prepend any partial data from previous call
	if len(f.partial) > 0 {
		data = append(f.partial, data...)
		f.partial = nil
	}

	// Fast path: no 0xFF byte means no possible marker
	hasMagic := false
	for _, b := range data {
		if b == 0xFF {
			hasMagic = true
			break
		}
	}
	if !hasMagic {
		return data
	}

	result := make([]byte, 0, len(data))
	i := 0
	for i < len(data) {
		if data[i] != 0xFF {
			result = append(result, data[i])
			i++
			continue
		}

		remaining := len(data) - i

		// Check for partial magic prefix at end of buffer
		if remaining < 4 {
			match := true
			for j := 0; j < remaining; j++ {
				if data[i+j] != discardMarkerMagic[j] {
					match = false
					break
				}
			}
			if match {
				f.partial = append([]byte(nil), data[i:]...)
				return result
			}
			// Not a marker prefix, pass through
			result = append(result, data[i])
			i++
			continue
		}

		// Check for magic prefix
		if data[i] != discardMarkerMagic[0] ||
			data[i+1] != discardMarkerMagic[1] ||
			data[i+2] != discardMarkerMagic[2] ||
			data[i+3] != discardMarkerMagic[3] {
			// 0xFF but not a marker, pass through
			result = append(result, data[i])
			i++
			continue
		}

		// Magic prefix confirmed. Try to consume 4 logical index bytes.
		indexBytes := consumeMarkerIndex(data, i+4)
		if indexBytes < 0 {
			// Not enough data to determine full marker - hold back
			f.partial = append([]byte(nil), data[i:]...)
			return result
		}

		// Full marker (with possible ECHOCTL expansion) - skip it entirely
		i += 4 + indexBytes
	}

	return result
}

func (s *TransportSession) forwardOutput() {
	defer s.wg.Done()

	// Strip discard marker bytes (0xFF 0xC0 0xC1 0xFF + 4 index bytes) from output.
	// These can leak through when the server sends multiple markers due to race
	// conditions in enablePendingInputDiscard() goroutines. The first marker is
	// consumed by discardPendingInput(), but extras pass through to the shell
	// and echo back as garbage characters.
	filter := &discardMarkerFilter{}

	buf := make([]byte, 32*1024)
	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		n, err := s.stdout.Read(buf)
		if n > 0 {
			filtered := filter.filter(buf[:n])
			if len(filtered) > 0 {
				data := make([]byte, len(filtered))
				copy(data, filtered)

				s.mu.Lock()
				callback := s.callback
				s.mu.Unlock()

				callback.OnOutput(data)
			}
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
