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
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// ForwardCallback receives port forwarding events. All methods are called from
// background goroutines and must be safe for concurrent use.
type ForwardCallback interface {
	OnForwardReady(id string, actualPort int)
	OnForwardError(id string, message string)
	OnForwardStopped(id string)
	OnConnectionOpened(id string, connectionID int64)
	OnConnectionClosed(id string, connectionID int64, bytesIn int64, bytesOut int64)
}

// ForwardConfig describes a single port forward rule.
type ForwardConfig struct {
	ForwardID   string // Unique identifier (UUID from Swift)
	Direction   string // "local" or "remote"
	BindAddress string // Address to bind (empty = 127.0.0.1 for both local and remote)
	BindPort    int    // Port to listen on (must be explicit >0 for remote forwards)
	TargetHost  string // Host to connect to
	TargetPort  int    // Port to connect to
}

// NewForwardConfig creates a new ForwardConfig (gomobile constructor).
func NewForwardConfig() *ForwardConfig {
	return &ForwardConfig{}
}

// PortForwarder manages active port forwards over a TSSH transport.
type PortForwarder struct {
	transport *Transport
	callback  ForwardCallback

	mu       sync.Mutex
	forwards map[string]*activeForward
	closed   bool // guarded by mu
	ctx      context.Context
	cancel   context.CancelFunc

	nextConnID atomic.Int64
}

// activeForward tracks a single running forward.
type activeForward struct {
	config ForwardConfig // copied by value — safe from caller mutation
	cancel context.CancelFunc
	wg     sync.WaitGroup // tracks active bridged connections

	listenerMu sync.Mutex
	listener   net.Listener // local TCP listener (-L) or remote listener (-R)
}

func (af *activeForward) setListener(l net.Listener) {
	af.listenerMu.Lock()
	af.listener = l
	af.listenerMu.Unlock()
}

func (af *activeForward) closeListener() {
	af.listenerMu.Lock()
	l := af.listener
	af.listener = nil
	af.listenerMu.Unlock()
	if l != nil {
		_ = l.Close()
	}
}

// NewPortForwarder creates a PortForwarder that uses the given transport's
// underlying tsshd client for remote dial/listen operations.
func NewPortForwarder(transport *Transport, callback ForwardCallback) (*PortForwarder, error) {
	if transport == nil {
		return nil, fmt.Errorf("transport is nil")
	}
	if transport.client == nil {
		return nil, fmt.Errorf("transport has no client")
	}
	if callback == nil {
		return nil, fmt.Errorf("callback is nil")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &PortForwarder{
		transport: transport,
		callback:  callback,
		forwards:  make(map[string]*activeForward),
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

// StartForward starts a port forward described by config.
// The actual listener/accept loop runs in a background goroutine.
// Results are reported asynchronously via the ForwardCallback.
func (pf *PortForwarder) StartForward(config *ForwardConfig) error {
	if config == nil {
		return fmt.Errorf("config is nil")
	}
	if config.ForwardID == "" {
		return fmt.Errorf("forward ID is empty")
	}
	if config.Direction == "remote" && config.BindPort == 0 {
		return fmt.Errorf("remote forwards require an explicit bind port (port 0 is not supported)")
	}

	// Copy config by value to prevent caller mutation from affecting running goroutines
	cfgCopy := *config

	pf.mu.Lock()

	// Check closed under the lock to prevent race with Close
	if pf.closed {
		pf.mu.Unlock()
		return fmt.Errorf("port forwarder is closed")
	}

	if _, exists := pf.forwards[cfgCopy.ForwardID]; exists {
		pf.mu.Unlock()
		return fmt.Errorf("forward %s already running", cfgCopy.ForwardID)
	}

	ctx, cancel := context.WithCancel(pf.ctx)
	af := &activeForward{
		config: cfgCopy,
		cancel: cancel,
	}
	pf.forwards[cfgCopy.ForwardID] = af
	pf.mu.Unlock()

	switch cfgCopy.Direction {
	case "local":
		go pf.runLocalForward(ctx, af)
	case "remote":
		go pf.runRemoteForward(ctx, af)
	default:
		pf.mu.Lock()
		delete(pf.forwards, cfgCopy.ForwardID)
		pf.mu.Unlock()
		cancel()
		return fmt.Errorf("invalid direction: %s", cfgCopy.Direction)
	}

	return nil
}

// StopForward stops a single forward by ID.
func (pf *PortForwarder) StopForward(forwardID string) {
	pf.mu.Lock()
	af, exists := pf.forwards[forwardID]
	if !exists {
		pf.mu.Unlock()
		return
	}
	delete(pf.forwards, forwardID)
	pf.mu.Unlock()

	pf.stopForward(af)
	pf.callback.OnForwardStopped(forwardID)
}

// StopAll stops all active forwards. New forwards can still be started after this call.
// Use Close() to permanently shut down the forwarder.
func (pf *PortForwarder) StopAll() {
	pf.mu.Lock()
	allForwards := make(map[string]*activeForward, len(pf.forwards))
	for k, v := range pf.forwards {
		allForwards[k] = v
	}
	pf.forwards = make(map[string]*activeForward)
	pf.mu.Unlock()

	for id, af := range allForwards {
		pf.stopForward(af)
		pf.callback.OnForwardStopped(id)
	}
}

// Close permanently shuts down the forwarder: stops all active forwards
// and rejects any future StartForward calls.
func (pf *PortForwarder) Close() {
	pf.mu.Lock()
	if pf.closed {
		pf.mu.Unlock()
		return
	}
	pf.closed = true
	allForwards := make(map[string]*activeForward, len(pf.forwards))
	for k, v := range pf.forwards {
		allForwards[k] = v
	}
	pf.forwards = make(map[string]*activeForward)
	pf.mu.Unlock()

	pf.cancel()

	for id, af := range allForwards {
		pf.stopForward(af)
		pf.callback.OnForwardStopped(id)
	}
}

func (pf *PortForwarder) stopForward(af *activeForward) {
	af.cancel()
	af.closeListener()
	// Wait for active connections to drain (with timeout)
	done := make(chan struct{})
	go func() {
		af.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// Timed out waiting for connections to drain
	}
}

// runLocalForward implements -L: listen locally, dial remote via tsshd for each connection.
func (pf *PortForwarder) runLocalForward(ctx context.Context, af *activeForward) {
	cfg := &af.config
	bindAddr := cfg.BindAddress
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	listenAddr := net.JoinHostPort(bindAddr, strconv.Itoa(cfg.BindPort))
	targetAddr := net.JoinHostPort(cfg.TargetHost, strconv.Itoa(cfg.TargetPort))

	// Check for cancellation before blocking on Listen
	if ctx.Err() != nil {
		return
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		pf.callback.OnForwardError(cfg.ForwardID, fmt.Sprintf("Failed to listen on %s: %v", listenAddr, err))
		pf.removeForwardAndNotify(cfg.ForwardID)
		return
	}
	af.setListener(listener)

	// Check for cancellation between listen and reporting ready.
	// If cancelled, stopForward will close the listener.
	if ctx.Err() != nil {
		af.closeListener()
		return
	}

	// Report actual bound port (useful if BindPort was 0)
	actualPort := listener.Addr().(*net.TCPAddr).Port
	pf.callback.OnForwardReady(cfg.ForwardID, actualPort)

	// Close listener when context is cancelled
	go func() {
		<-ctx.Done()
		af.closeListener()
	}()

	for {
		local, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				// Context cancelled, clean shutdown — StopForward/StopAll/Close already cleaned up
				return
			}
			// Unexpected accept failure — clean up state and notify
			pf.callback.OnForwardError(cfg.ForwardID, fmt.Sprintf("Accept failed: %v", err))
			pf.removeForwardAndNotify(cfg.ForwardID)
			return
		}

		// Dial remote via tsshd smux stream
		remote, err := pf.transport.client.DialTimeout("tcp", targetAddr, 30*time.Second)
		if err != nil {
			_ = local.Close()
			pf.callback.OnForwardError(cfg.ForwardID, fmt.Sprintf("Remote dial %s failed: %v", targetAddr, err))
			continue
		}

		connID := pf.nextConnID.Add(1)
		pf.callback.OnConnectionOpened(cfg.ForwardID, connID)

		af.wg.Add(1)
		go func() {
			defer af.wg.Done()
			bytesIn, bytesOut := bridgeConnections(local, remote)
			pf.callback.OnConnectionClosed(cfg.ForwardID, connID, bytesIn, bytesOut)
		}()
	}
}

// runRemoteForward implements -R: listen on remote via tsshd, dial local for each connection.
func (pf *PortForwarder) runRemoteForward(ctx context.Context, af *activeForward) {
	cfg := &af.config
	bindAddr := cfg.BindAddress
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	remoteListenAddr := net.JoinHostPort(bindAddr, strconv.Itoa(cfg.BindPort))
	localTargetAddr := net.JoinHostPort(cfg.TargetHost, strconv.Itoa(cfg.TargetPort))

	// Check for cancellation before blocking on remote Listen
	if ctx.Err() != nil {
		return
	}

	listener, err := pf.transport.client.Listen("tcp", remoteListenAddr)
	if err != nil {
		pf.callback.OnForwardError(cfg.ForwardID, fmt.Sprintf("Remote listen on %s failed: %v", remoteListenAddr, err))
		pf.removeForwardAndNotify(cfg.ForwardID)
		return
	}
	af.setListener(listener)

	// Check for cancellation between listen and reporting ready
	if ctx.Err() != nil {
		af.closeListener()
		return
	}

	// Report the configured bind port (BindPort=0 is rejected in StartForward)
	pf.callback.OnForwardReady(cfg.ForwardID, cfg.BindPort)

	// Close listener when context is cancelled
	go func() {
		<-ctx.Done()
		af.closeListener()
	}()

	for {
		remote, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Unexpected accept failure — clean up state and notify
			pf.callback.OnForwardError(cfg.ForwardID, fmt.Sprintf("Remote accept failed: %v", err))
			pf.removeForwardAndNotify(cfg.ForwardID)
			return
		}

		// Dial local target
		local, err := net.DialTimeout("tcp", localTargetAddr, 30*time.Second)
		if err != nil {
			_ = remote.Close()
			pf.callback.OnForwardError(cfg.ForwardID, fmt.Sprintf("Local dial %s failed: %v", localTargetAddr, err))
			continue
		}

		connID := pf.nextConnID.Add(1)
		pf.callback.OnConnectionOpened(cfg.ForwardID, connID)

		af.wg.Add(1)
		go func() {
			defer af.wg.Done()
			bytesIn, bytesOut := bridgeConnections(local, remote)
			pf.callback.OnConnectionClosed(cfg.ForwardID, connID, bytesIn, bytesOut)
		}()
	}
}

// removeForwardAndNotify removes a forward from the map and fires OnForwardStopped.
// Used when accept loops exit unexpectedly to prevent the forward from being stuck
// in a "running" state that blocks restarts.
func (pf *PortForwarder) removeForwardAndNotify(id string) {
	pf.mu.Lock()
	_, existed := pf.forwards[id]
	delete(pf.forwards, id)
	pf.mu.Unlock()
	if existed {
		pf.callback.OnForwardStopped(id)
	}
}

// bridgeConnections bridges two connections bidirectionally, counting bytes.
// Returns (bytesFromB, bytesFromA) i.e. (bytesIn, bytesOut) from local perspective.
func bridgeConnections(a, b io.ReadWriteCloser) (int64, int64) {
	var wg sync.WaitGroup
	var bytesAtoB, bytesBtoA atomic.Int64

	wg.Add(2)

	// a -> b (local writes to remote = bytes out)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(b, a)
		bytesAtoB.Store(n)
		// Half-close: signal EOF to b
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		if cr, ok := a.(interface{ CloseRead() error }); ok {
			_ = cr.CloseRead()
		}
	}()

	// b -> a (remote writes to local = bytes in)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(a, b)
		bytesBtoA.Store(n)
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		if cr, ok := b.(interface{ CloseRead() error }); ok {
			_ = cr.CloseRead()
		}
	}()

	wg.Wait()
	_ = a.Close()
	_ = b.Close()

	return bytesBtoA.Load(), bytesAtoB.Load()
}
