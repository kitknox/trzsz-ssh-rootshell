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
	"sync"

	"github.com/trzsz/trzsz-ssh/tssh"
)

// TSSHClient wraps an SSH client connection for iOS.
// Use Connect() or ConnectWithPassword() to create a TSSHClient.
//
// The client maintains the underlying SSH connection and can create
// multiple sessions. Call Close() when done to release resources.
type TSSHClient struct {
	client   tssh.SshClient
	args     *TSSHArgs
	mu       sync.Mutex
	closed   bool
	sessions []*TSSHSession
}

// Connect establishes an SSH connection using the provided arguments.
// Authentication will use SSH agent or keys specified in TSSHArgs.
// Returns an error if connection or authentication fails.
func Connect(args *TSSHArgs) (*TSSHClient, error) {
	if err := args.Validate(); err != "" {
		return nil, fmt.Errorf("invalid arguments: %s", err)
	}

	sshArgs := args.toSshArgs()
	client, err := tssh.SshLogin(sshArgs)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}

	return &TSSHClient{
		client: client,
		args:   args,
	}, nil
}

// ConnectWithPassword establishes an SSH connection using password authentication.
// This is a convenience method that sets up password auth in the SSH options.
func ConnectWithPassword(args *TSSHArgs, password string) (*TSSHClient, error) {
	if err := args.Validate(); err != "" {
		return nil, fmt.Errorf("invalid arguments: %s", err)
	}

	// Clone args and add password option
	argsCopy := *args
	if argsCopy.options == nil {
		argsCopy.options = make(map[string][]string)
	}
	// Set password via SSH option for keyboard-interactive auth
	argsCopy.options["password"] = []string{password}

	sshArgs := argsCopy.toSshArgs()
	client, err := tssh.SshLogin(sshArgs)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}

	return &TSSHClient{
		client: client,
		args:   &argsCopy,
	}, nil
}

// ConnectWithKey establishes an SSH connection using public key authentication.
// keyPath is the path to the private key file.
// passphrase is the key passphrase (empty string if unencrypted).
func ConnectWithKey(args *TSSHArgs, keyPath, passphrase string) (*TSSHClient, error) {
	if err := args.Validate(); err != "" {
		return nil, fmt.Errorf("invalid arguments: %s", err)
	}

	// Clone args and add identity
	argsCopy := *args
	argsCopy.identities = append(argsCopy.identities, keyPath)
	if argsCopy.options == nil {
		argsCopy.options = make(map[string][]string)
	}
	if passphrase != "" {
		// Store passphrase for the identity file
		argsCopy.options["passphrase"] = []string{passphrase}
	}

	sshArgs := argsCopy.toSshArgs()
	client, err := tssh.SshLogin(sshArgs)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}

	return &TSSHClient{
		client: client,
		args:   &argsCopy,
	}, nil
}

// NewSession creates a new SSH session for running commands or shells.
// Multiple sessions can be created from a single client connection.
// Each session should be closed when no longer needed.
func (c *TSSHClient) NewSession() (*TSSHSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, fmt.Errorf("client is closed")
	}

	session, err := c.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	tsshSession := newTSSHSession(session, c)
	c.sessions = append(c.sessions, tsshSession)
	return tsshSession, nil
}

// Close closes the SSH connection and all associated sessions.
// After calling Close, the client cannot be used.
func (c *TSSHClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	// Close all sessions first
	for _, s := range c.sessions {
		_ = s.Close()
	}
	c.sessions = nil

	return c.client.Close()
}

// Wait blocks until the SSH connection is closed.
// This can be used to wait for the connection to terminate.
func (c *TSSHClient) Wait() error {
	return c.client.Wait()
}

// IsClosed returns true if the client has been closed.
func (c *TSSHClient) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// GetDestination returns the destination this client is connected to.
func (c *TSSHClient) GetDestination() string {
	if c.args != nil {
		return c.args.Destination
	}
	return ""
}

// IsUDP returns true if this connection uses UDP transport (KCP or QUIC).
func (c *TSSHClient) IsUDP() bool {
	if c.args != nil {
		return c.args.UDP || c.args.KCP
	}
	return false
}

// removeSession removes a session from the client's tracking list.
// Called internally when a session is closed.
func (c *TSSHClient) removeSession(s *TSSHSession) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, session := range c.sessions {
		if session == s {
			c.sessions = append(c.sessions[:i], c.sessions[i+1:]...)
			break
		}
	}
}
