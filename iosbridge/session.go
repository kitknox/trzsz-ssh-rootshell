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
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/trzsz/trzsz-ssh/tssh"
	"golang.org/x/crypto/ssh"
)

// TSSHSession wraps an SSH session for iOS.
// A session represents a single channel to the remote host,
// used for running a shell or command.
//
// Typical usage:
//  1. Create session via client.NewSession()
//  2. Call RequestPty() to allocate a pseudo-terminal
//  3. Set output callback via SetOutputCallback()
//  4. Call Shell() to start an interactive shell
//  5. Use Write() to send input
//  6. Call WindowChange() when terminal size changes
//  7. Call Close() when done
type TSSHSession struct {
	session tssh.SshSession
	client  *TSSHClient

	stdin  io.WriteCloser
	stdout io.Reader
	stderr io.Reader

	callback TSSHOutputCallback
	mu       sync.Mutex
	closed   atomic.Bool
	started  atomic.Bool

	// For cleanup
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// newTSSHSession creates a new session wrapper.
func newTSSHSession(session tssh.SshSession, client *TSSHClient) *TSSHSession {
	return &TSSHSession{
		session:  session,
		client:   client,
		stopChan: make(chan struct{}),
		callback: &noOpOutputCallback{},
	}
}

// RequestPty requests a pseudo-terminal from the server.
// This must be called before Shell() or Run() if you need terminal features.
//
// term is the terminal type (e.g., "xterm-256color").
// rows is the terminal height in lines.
// cols is the terminal width in columns.
func (s *TSSHSession) RequestPty(term string, rows, cols int) error {
	if s.closed.Load() {
		return fmt.Errorf("session is closed")
	}
	if s.started.Load() {
		return fmt.Errorf("session already started")
	}

	// Empty terminal modes - let the server use defaults
	modes := ssh.TerminalModes{}
	return s.session.RequestPty(term, rows, cols, modes)
}

// Shell starts an interactive login shell on the remote host.
// You must call RequestPty() before Shell() if you need PTY features.
// After calling Shell(), use Write() to send input and receive output
// via the callback set with SetOutputCallback().
func (s *TSSHSession) Shell() error {
	if s.closed.Load() {
		return fmt.Errorf("session is closed")
	}
	if !s.started.CompareAndSwap(false, true) {
		return fmt.Errorf("session already started")
	}

	// Set up I/O pipes
	var err error
	s.stdin, err = s.session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	s.stdout, err = s.session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	s.stderr, err = s.session.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to get stderr pipe: %w", err)
	}

	// Start the shell
	if err := s.session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}

	// Start I/O forwarding goroutines
	s.startOutputForwarding()

	return nil
}

// Run runs a command on the remote host.
// This is equivalent to Shell() but runs a single command instead.
// The session cannot be reused after Run() completes.
func (s *TSSHSession) Run(command string) error {
	if s.closed.Load() {
		return fmt.Errorf("session is closed")
	}
	if !s.started.CompareAndSwap(false, true) {
		return fmt.Errorf("session already started")
	}

	// Set up I/O pipes
	var err error
	s.stdout, err = s.session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	s.stderr, err = s.session.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to get stderr pipe: %w", err)
	}

	// Start I/O forwarding goroutines
	s.startOutputForwarding()

	// Run the command (blocks until complete)
	return s.session.Run(command)
}

// Start starts a command on the remote host without waiting for it to complete.
// Use this when you need to send input to the command.
func (s *TSSHSession) Start(command string) error {
	if s.closed.Load() {
		return fmt.Errorf("session is closed")
	}
	if !s.started.CompareAndSwap(false, true) {
		return fmt.Errorf("session already started")
	}

	// Set up I/O pipes
	var err error
	s.stdin, err = s.session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	s.stdout, err = s.session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	s.stderr, err = s.session.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to get stderr pipe: %w", err)
	}

	// Start I/O forwarding goroutines
	s.startOutputForwarding()

	// Start the command
	return s.session.Start(command)
}

// Write sends input data to the remote shell or command.
// The data is written to the session's stdin.
func (s *TSSHSession) Write(data []byte) error {
	if s.closed.Load() {
		return fmt.Errorf("session is closed")
	}
	if !s.started.Load() {
		return fmt.Errorf("session not started")
	}
	if s.stdin == nil {
		return fmt.Errorf("stdin not available")
	}

	_, err := s.stdin.Write(data)
	return err
}

// WindowChange notifies the remote host of a terminal size change.
// Call this when the terminal view is resized.
//
// rows is the new terminal height in lines.
// cols is the new terminal width in columns.
func (s *TSSHSession) WindowChange(rows, cols int) error {
	if s.closed.Load() {
		return fmt.Errorf("session is closed")
	}
	return s.session.WindowChange(rows, cols)
}

// SetOutputCallback sets the callback for receiving session output.
// The callback will receive stdout data via OnOutput() and error
// messages via OnError(). OnClose() is called when the session ends.
//
// This should be called before Shell() or Run().
// The callback may be invoked from background goroutines.
func (s *TSSHSession) SetOutputCallback(callback TSSHOutputCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if callback != nil {
		s.callback = callback
	} else {
		s.callback = &noOpOutputCallback{}
	}
}

// Close closes the session and releases resources.
// After Close(), the session cannot be reused.
func (s *TSSHSession) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Signal stop to I/O goroutines
	close(s.stopChan)

	// Close stdin to signal EOF
	if s.stdin != nil {
		_ = s.stdin.Close()
	}

	// Close the session
	err := s.session.Close()

	// Wait for I/O goroutines to finish
	s.wg.Wait()

	// Remove from client tracking
	if s.client != nil {
		s.client.removeSession(s)
	}

	// Notify callback
	s.mu.Lock()
	callback := s.callback
	s.mu.Unlock()
	callback.OnClose()

	return err
}

// Wait waits for the remote command or shell to exit.
// Returns after the session has terminated.
func (s *TSSHSession) Wait() error {
	return s.session.Wait()
}

// GetExitCode returns the exit code from the remote command.
// Only valid after Wait() returns.
func (s *TSSHSession) GetExitCode() int {
	return s.session.GetExitCode()
}

// IsClosed returns true if the session has been closed.
func (s *TSSHSession) IsClosed() bool {
	return s.closed.Load()
}

// startOutputForwarding starts goroutines to forward stdout/stderr to the callback.
func (s *TSSHSession) startOutputForwarding() {
	// Forward stdout
	if s.stdout != nil {
		s.wg.Add(1)
		go s.forwardOutput(s.stdout, false)
	}

	// Forward stderr
	if s.stderr != nil {
		s.wg.Add(1)
		go s.forwardOutput(s.stderr, true)
	}
}

// forwardOutput reads from a reader and sends to the callback.
func (s *TSSHSession) forwardOutput(r io.Reader, isStderr bool) {
	defer s.wg.Done()

	buf := make([]byte, 32*1024) // 32KB buffer
	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		n, err := r.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])

			s.mu.Lock()
			callback := s.callback
			s.mu.Unlock()

			if isStderr {
				callback.OnError(string(data))
			} else {
				callback.OnOutput(data)
			}
		}

		if err != nil {
			if err != io.EOF {
				s.mu.Lock()
				callback := s.callback
				s.mu.Unlock()
				callback.OnError(fmt.Sprintf("read error: %v", err))
			}
			return
		}
	}
}
