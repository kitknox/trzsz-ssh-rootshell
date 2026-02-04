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

// TSSHOutputCallback is the interface for receiving session output.
// Implement this interface in Swift to receive data from the SSH session.
//
// All methods may be called from background goroutines, so implementations
// must be thread-safe and dispatch to the main thread if needed.
type TSSHOutputCallback interface {
	// OnOutput is called when stdout data is received from the remote host.
	// The data parameter contains raw terminal output bytes.
	OnOutput(data []byte)

	// OnError is called when an error message needs to be displayed.
	// This includes stderr output and connection errors.
	OnError(message string)

	// OnClose is called when the session has ended.
	// After this callback, no more OnOutput or OnError calls will be made.
	OnClose()
}

// TSSHStateCallback is the interface for receiving connection state changes.
// Implement this interface in Swift to receive state updates for UI feedback.
type TSSHStateCallback interface {
	// OnStateChange is called when the connection state changes.
	// States include: "connecting", "authenticating", "connected", "disconnected", "reconnecting"
	OnStateChange(state string)

	// OnReconnecting is called when the UDP/KCP connection is attempting to reconnect.
	// The attempt parameter indicates which reconnection attempt this is (1-based).
	OnReconnecting(attempt int)
}

// TSSHHostKeyCallback is the interface for host key validation.
// Implement this interface to handle first-time connections and key changes.
type TSSHHostKeyCallback interface {
	// OnHostKey is called when a host key needs to be validated.
	// fingerprint is the SHA256 fingerprint of the host key.
	// keyType is the key algorithm (e.g., "ssh-ed25519", "ssh-rsa").
	// isNewHost is true if this host has never been connected to before.
	// isChanged is true if the host key differs from the previously stored key.
	//
	// Return true to accept the key, false to reject and abort connection.
	OnHostKey(fingerprint, keyType string, isNewHost, isChanged bool) bool
}

// TSSHPasswordCallback is the interface for password prompts.
// Implement this interface to handle keyboard-interactive authentication.
type TSSHPasswordCallback interface {
	// OnPasswordPrompt is called when the server requests a password.
	// prompt is the text to display (e.g., "Password: ").
	// Return the password string, or empty string to cancel.
	OnPasswordPrompt(prompt string) string
}

// TSSHAuthCallback combines host key and password callbacks.
// This is the main callback interface for interactive authentication.
type TSSHAuthCallback interface {
	TSSHHostKeyCallback
	TSSHPasswordCallback
}

// noOpOutputCallback is a no-op implementation of TSSHOutputCallback.
type noOpOutputCallback struct{}

func (n *noOpOutputCallback) OnOutput(data []byte) {}
func (n *noOpOutputCallback) OnError(message string) {}
func (n *noOpOutputCallback) OnClose() {}

// noOpStateCallback is a no-op implementation of TSSHStateCallback.
type noOpStateCallback struct{}

func (n *noOpStateCallback) OnStateChange(state string) {}
func (n *noOpStateCallback) OnReconnecting(attempt int) {}
