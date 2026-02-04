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

// Package iosbridge provides gomobile-compatible KCP/QUIC transport bindings.
//
// This package provides TRANSPORT-ONLY functionality for connecting to tsshd
// servers. It does NOT handle SSH authentication - that is handled by the
// Swift side using Citadel or NIOSSH.
//
// Architecture:
//   1. Swift side: SSH connection via Citadel, spawn tsshd, parse JSON output
//   2. Go side: KCP/QUIC transport to tsshd using parsed server info
//
// This separation ensures SSH keys never touch the Go layer.
//
// Example usage from Swift:
//
//	// After SSH spawns tsshd and returns JSON like:
//	// {"Port":61001,"Mode":"KCP","Pass":"<hex>","Salt":"<hex>",...}
//
//	// Parse the server info
//	let config = try IosbridgeParseTransportConfig(jsonString)
//	config.host = serverIP
//
//	// Connect transport (no SSH involved)
//	let transport = try IosbridgeConnectTransport(config)
//	let session = try transport.newSession()
//
//	try session.requestPty("xterm-256color", 24, 80)
//	session.setOutputCallback(myOutputHandler)
//	try session.shell()
//
// The transport provides:
//   - KCP and QUIC protocol support
//   - Automatic reconnection on network changes
//   - PTY allocation and terminal resize
//   - I/O via callbacks (since io.Reader/Writer aren't gomobile-compatible)
package iosbridge
