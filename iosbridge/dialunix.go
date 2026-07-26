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

// Client-initiated Unix-socket dial through the TSSHD UDP transport.
//
// The Unix-domain counterpart to DialTCP in dial.go: the app asks for
// exactly one connection to a socket path on the remote host, dialed by
// the tsshd server over the same "dial" event port forwarding uses
// (tsshd handles Net == "unix" in its dial handler). Useful for talking
// to remote daemons that only listen on Unix sockets — e.g. a control
// socket exposed by a remote CLI.
//
// The returned int64 is a channel reference in the SAME handle table the
// stream-local forwarding APIs use, so byte transport reuses
// StreamLocalRead / StreamLocalWrite / StreamLocalClose unchanged — those
// methods are net.Conn-generic despite the name. The channel is torn down
// with everything else in closeAllStreamLocal when the transport closes.

import (
	"fmt"
	"time"
)

// DialUnix opens a connection to the Unix-domain socket at remotePath
// from the remote tsshd server, tunneled through the established
// transport. Blocks until the connection is established or fails
// (30 second timeout, matching DialTCP).
//
// On success, returns a channel reference for the Transport's
// StreamLocalRead / StreamLocalWrite / StreamLocalClose methods. The
// caller owns the channel and should StreamLocalClose it when done;
// Transport.Close also closes any still-open dialed channels.
//
// remotePath is interpreted by the server, so it must be an absolute
// path that exists on the remote host — no ~ or $VAR expansion happens
// on either side.
func (t *Transport) DialUnix(remotePath string) (int64, error) {
	if t.closed.Load() {
		return 0, fmt.Errorf("transport is closed")
	}
	if remotePath == "" {
		return 0, fmt.Errorf("remote path is empty")
	}

	conn, err := t.client.DialTimeout("unix", remotePath, 30*time.Second)
	if err != nil {
		return 0, fmt.Errorf("remote dial unix %s failed: %w", remotePath, err)
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
		dl.OnDebug(fmt.Sprintf("[dial] unix %s connected, channel %d", remotePath, ref))
	}
	return ref, nil
}
