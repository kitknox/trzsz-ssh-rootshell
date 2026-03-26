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
// Implement this interface in Swift to receive data from the transport session.
//
// All methods may be called from background goroutines, so implementations
// must be thread-safe and dispatch to the main thread if needed.
type TSSHOutputCallback interface {
	// OnOutput is called when stdout data is received from the remote host.
	// The data parameter contains raw terminal output bytes.
	OnOutput(data []byte)

	// OnError is called when an error message needs to be displayed.
	// This includes connection errors and transport issues.
	OnError(message string)

	// OnExit is called when the remote shell/command has exited.
	// exitCode is the exit status: 0 for success, non-zero for error.
	// This is called for graceful exits (e.g., user types "exit").
	OnExit(exitCode int)

	// OnClose is called when the session has been closed.
	// After this callback, no more OnOutput, OnError, or OnExit calls will be made.
	// This may be called after OnExit, or alone if the connection was lost.
	OnClose()
}

// noOpOutputCallback is a no-op implementation of TSSHOutputCallback.
type noOpOutputCallback struct{}

func (n *noOpOutputCallback) OnOutput(data []byte)   {}
func (n *noOpOutputCallback) OnError(message string) {}
func (n *noOpOutputCallback) OnExit(exitCode int)    {}
func (n *noOpOutputCallback) OnClose()               {}
