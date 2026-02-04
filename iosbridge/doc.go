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

// Package iosbridge provides gomobile-compatible bindings for trzsz-ssh.
//
// This package wraps the internal tssh package to provide a simple API
// that can be used from iOS/Swift via gomobile bindings. It handles:
//
//   - Connection management (TCP, UDP/KCP, QUIC)
//   - Authentication (password, public key)
//   - PTY allocation and terminal resize
//   - I/O via callbacks (since io.Reader/Writer aren't gomobile-compatible)
//
// Example usage from Swift:
//
//	let args = TrzszSSHNewTSSHArgs()!
//	args.destination = "user@host.example.com"
//	args.port = 22
//	args.kcp = true  // Use KCP transport
//
//	let client = try TrzszSSHConnectWithPassword(args, "password")
//	let session = try client.newSession()
//
//	try session.requestPty("xterm-256color", 24, 80)
//	session.setOutputCallback(myOutputHandler)
//	try session.shell()
package iosbridge
