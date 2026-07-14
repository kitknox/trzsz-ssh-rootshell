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

// Client-initiated TCP dial through the TSSHD UDP transport.
//
// This is the single-connection counterpart to PortForwarder's -L path:
// instead of binding a local listener and dialing the remote target per
// accepted connection, the app asks for exactly one connection to
// host:port, dialed by the tsshd server over the same "dial" event that
// port forwarding uses. The primary consumer is the in-app VNC client,
// which tunnels one RFB connection per screen-share session without
// needing a loopback listener.
//
// The returned int64 is a channel reference in the SAME handle table the
// stream-local forwarding APIs use, so byte transport reuses
// StreamLocalRead / StreamLocalWrite / StreamLocalClose unchanged — those
// methods are net.Conn-generic despite the name. The channel is torn down
// with everything else in closeAllStreamLocal when the transport closes.

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

// DialTCP opens a TCP connection to host:port from the remote tsshd
// server, tunneled through the established transport. Blocks until the
// connection is established or fails (30 second timeout, matching the
// per-connection dials in PortForwarder).
//
// On success, returns a channel reference for the Transport's
// StreamLocalRead / StreamLocalWrite / StreamLocalClose methods. The
// caller owns the channel and should StreamLocalClose it when done;
// Transport.Close also closes any still-open dialed channels.
//
// host may be a hostname (resolved on the server side), an IPv4, or an
// IPv6 literal.
func (t *Transport) DialTCP(host string, port int) (int64, error) {
	if t.closed.Load() {
		return 0, fmt.Errorf("transport is closed")
	}
	if host == "" {
		return 0, fmt.Errorf("host is empty")
	}
	if port <= 0 || port > 65535 {
		return 0, fmt.Errorf("invalid port: %d", port)
	}

	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := t.client.DialTimeout("tcp", targetAddr, 30*time.Second)
	if err != nil {
		return 0, fmt.Errorf("remote dial %s failed: %w", targetAddr, err)
	}

	ref := t.registerStreamLocalChannel(conn)

	// Close raced with the dial: closeAllStreamLocal may have already
	// drained the handle table before we registered, which would leak
	// the connection. StreamLocalClose is idempotent, so unwind here.
	if t.closed.Load() {
		_ = t.StreamLocalClose(ref)
		return 0, fmt.Errorf("transport is closed")
	}

	if dl := getDebugLogger(); dl != nil {
		dl.OnDebug(fmt.Sprintf("[dial] tcp %s connected, channel %d", targetAddr, ref))
	}
	return ref, nil
}
