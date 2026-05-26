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

// Unix-domain socket forwarding over the TSSHD UDP transport.
//
// This is the GPG-agent-forwarding (and general `RemoteForward
// /remote.sock /local.sock`) primitive. TSSHD's *SshUdpClient.Listen
// method is a generic remote-listener API — pass network "unix" and a
// remote path, and the TSSHD server binds that path with net.Listen
// and ships every accepted connection back to us as a regular
// net.Conn. There is no need for OpenSSH's
// `streamlocal-forward@openssh.com` channel-type machinery; TSSHD
// invented its own (simpler) wire format for the same job.
//
// Upstream `tssh` CLI uses exactly this code path when a user passes
// `RemoteForward /remote.sock /local.sock` in UDP mode — see
// trzsz-ssh/tssh/forward_tcp.go:172-174.
//
// The Swift side hands a callback object that's called per accepted
// connection with an opaque int64 channel reference. Further byte
// transport then goes through StreamLocalRead / StreamLocalWrite /
// StreamLocalClose on the Transport, which look the connection up in
// a handle table keyed by that reference.

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// StreamLocalCallback is the interface for handling forwarded Unix
// socket connections. Implement this in Swift to receive each accepted
// connection. The Swift bridge then drives byte I/O on the channel via
// the StreamLocalRead / StreamLocalWrite / StreamLocalClose methods on
// the parent Transport.
//
// OnAccept is invoked from a per-connection goroutine, never the main
// thread. The Swift implementation should hop to MainActor before
// touching shared state. Crucially the callback must return promptly
// — it runs on the forwarder's accept loop indirectly (via a goroutine
// it spawns to deliver) and any blocking here would back-pressure the
// listener.
type StreamLocalCallback interface {
	// OnAccept is called once per accepted connection. channelRef is
	// an opaque int64 the Swift side passes back to subsequent
	// StreamLocal* methods to identify this channel.
	OnAccept(channelRef int64)

	// OnError is called when the listener itself fails (e.g. the
	// server tore down the socket, the connection was lost). After
	// OnError, no further OnAccept calls happen for this forward.
	OnError(message string)
}

// streamLocalForwarder owns one remote-listener registration and its
// accept loop. Lifetime is bounded by EnableStreamLocalForwarding /
// DisableStreamLocalForwarding (or Transport.Close).
type streamLocalForwarder struct {
	transport *Transport
	listener  net.Listener
	path      string
	callback  StreamLocalCallback
	stopChan  chan struct{}
	stopped   atomic.Bool
}

func (f *streamLocalForwarder) acceptLoop() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			// Distinguish intentional shutdown from an unexpected
			// listener failure. Either way the accept loop ends.
			if f.stopped.Load() {
				return
			}
			if f.callback != nil {
				f.callback.OnError(err.Error())
			}
			return
		}

		ref := f.transport.registerStreamLocalChannel(conn)
		// Dispatch OnAccept on a fresh goroutine so a slow Swift
		// handler can't back-pressure the listener's accept loop.
		// (Each accepted connection is independent anyway, so there's
		// no ordering constraint to preserve here.)
		go f.callback.OnAccept(ref)
	}
}

func (f *streamLocalForwarder) close() error {
	if !f.stopped.CompareAndSwap(false, true) {
		return nil
	}
	close(f.stopChan)
	return f.listener.Close()
}

// EnableStreamLocalForwarding asks the remote tsshd server to bind a
// Unix socket at remotePath and forward every accepted connection back
// over the UDP transport. callback.OnAccept is called once per
// connection.
//
// Returns an error if the path is already forwarded on this transport
// or if the remote rejected the listen request (e.g.
// `AllowStreamLocalForwarding no` in sshd config on the server, or
// permission denied at the bind path).
//
// The forward stays active until DisableStreamLocalForwarding is
// called with the same path or Transport.Close happens.
func (t *Transport) EnableStreamLocalForwarding(remotePath string, callback StreamLocalCallback) error {
	if t.closed.Load() {
		return fmt.Errorf("transport is closed")
	}

	t.mu.Lock()
	if t.streamLocalForwarders == nil {
		t.streamLocalForwarders = make(map[string]*streamLocalForwarder)
	}
	if _, exists := t.streamLocalForwarders[remotePath]; exists {
		t.mu.Unlock()
		return fmt.Errorf("streamlocal forwarding already active for %s", remotePath)
	}
	t.mu.Unlock()

	listener, err := t.client.Listen("unix", remotePath)
	if err != nil && isAddrInUseError(err) {
		// Reattach-after-restart case: the previous client process is
		// gone, but tsshd's handleListenEvent is still blocking on
		// listener.Accept() over a dead bus stream. The unix socket
		// file stays bound, so this Listen fails with EADDRINUSE.
		//
		// tsshd only breaks out of the accept loop when sendMessage
		// on the bus stream fails — which only happens once an
		// incoming connection wakes Accept. So we wake it ourselves
		// by dialing the path and immediately closing. The stale
		// handler's sendMessage on the (now-closed) stream errors,
		// the accept loop exits, and the defer (newFileUnlinker)
		// unlinks the socket file. Then the retry succeeds.
		//
		// This is the workaround for servers running unmodified
		// tsshd; once tsshd ships a stream-watchdog the workaround
		// becomes a no-op (the listen retry succeeds because the
		// path is already free).
		if pokeConn, pokeErr := t.client.DialTimeout("unix", remotePath, 2*time.Second); pokeErr == nil {
			_ = pokeConn.Close()
			// 250ms is enough for the stale handler's cleanup on
			// every server we've tested; the operation is rare
			// (once per reattach with GPG forwarding on) so the
			// sleep cost is acceptable.
			time.Sleep(250 * time.Millisecond)
			listener, err = t.client.Listen("unix", remotePath)
		}
	}
	if err != nil {
		return fmt.Errorf("listen unix %s failed: %w", remotePath, err)
	}

	fwd := &streamLocalForwarder{
		transport: t,
		listener:  listener,
		path:      remotePath,
		callback:  callback,
		stopChan:  make(chan struct{}),
	}

	t.mu.Lock()
	t.streamLocalForwarders[remotePath] = fwd
	t.mu.Unlock()

	go fwd.acceptLoop()

	if dl := getDebugLogger(); dl != nil {
		dl.OnDebug(fmt.Sprintf("[streamlocal] forwarding %s active", remotePath))
	}
	return nil
}

// DisableStreamLocalForwarding tears down a previously enabled forward.
// Idempotent — calling with an unknown path is a no-op.
func (t *Transport) DisableStreamLocalForwarding(remotePath string) error {
	t.mu.Lock()
	fwd, ok := t.streamLocalForwarders[remotePath]
	if ok {
		delete(t.streamLocalForwarders, remotePath)
	}
	t.mu.Unlock()

	if !ok {
		return nil
	}
	return fwd.close()
}

// StreamLocalRead reads up to maxBytes from the channel identified by
// channelRef. Returns nil data with nil error on clean EOF — Swift
// callers should treat that as "peer closed, stop reading."
//
// All channel methods take the channel reference int64 that the Swift
// side received in OnAccept. Lookups go through a Transport-scoped
// handle table; the underlying net.Conn is never exposed to Swift.
func (t *Transport) StreamLocalRead(channelRef int64, maxBytes int32) ([]byte, error) {
	conn := t.lookupStreamLocalChannel(channelRef)
	if conn == nil {
		return nil, fmt.Errorf("unknown stream-local channel %d", channelRef)
	}
	if maxBytes <= 0 {
		return nil, nil
	}
	buf := make([]byte, int(maxBytes))
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	if err == io.EOF {
		// Signal clean close via nil data + nil error so the Swift
		// AsyncBytePipe adapter can return nil from its read() to mark
		// end-of-stream without throwing.
		return nil, nil
	}
	return nil, err
}

// StreamLocalWrite writes data to the channel identified by channelRef.
// Returns the number of bytes written (typically all of them for a
// healthy connection).
func (t *Transport) StreamLocalWrite(channelRef int64, data []byte) (int32, error) {
	conn := t.lookupStreamLocalChannel(channelRef)
	if conn == nil {
		return 0, fmt.Errorf("unknown stream-local channel %d", channelRef)
	}
	n, err := conn.Write(data)
	return int32(n), err
}

// StreamLocalClose closes the channel and removes it from the handle
// table. Idempotent — calling for an unknown ref is silent success.
func (t *Transport) StreamLocalClose(channelRef int64) error {
	t.mu.Lock()
	conn, ok := t.streamLocalChannels[channelRef]
	if ok {
		delete(t.streamLocalChannels, channelRef)
	}
	t.mu.Unlock()
	if !ok {
		return nil
	}
	return conn.Close()
}

// registerStreamLocalChannel files an accepted net.Conn into the
// handle table and returns its int64 reference. Called from
// acceptLoop; safe to call concurrently.
func (t *Transport) registerStreamLocalChannel(conn net.Conn) int64 {
	ref := atomic.AddInt64(&t.nextStreamLocalRef, 1)
	t.mu.Lock()
	if t.streamLocalChannels == nil {
		t.streamLocalChannels = make(map[int64]net.Conn)
	}
	t.streamLocalChannels[ref] = conn
	t.mu.Unlock()
	return ref
}

// lookupStreamLocalChannel returns the net.Conn for a channelRef, or
// nil if it's been closed / never existed. Held under the transport's
// mutex briefly so concurrent Close calls don't race.
func (t *Transport) lookupStreamLocalChannel(channelRef int64) net.Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.streamLocalChannels == nil {
		return nil
	}
	return t.streamLocalChannels[channelRef]
}

// isAddrInUseError matches the substring tsshd echoes back from the
// server's net.Listen call when the unix socket path is still bound.
// Substring match because the error crosses a wire boundary (tsshd's
// sendError serializes err.Error()), so error-type assertions don't
// survive. The text "address already in use" is the textual rendering
// of syscall.EADDRINUSE on every Unix platform Go targets.
func isAddrInUseError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "address already in use")
}

// closeAllStreamLocal is called from Transport.Close to tear down every
// active forwarder and channel. Holds the transport mutex for the
// listener-shutdown phase but releases it before draining the channel
// table, since Conn.Close can block on slow Network.framework state.
func (t *Transport) closeAllStreamLocal() {
	// Snapshot forwarders to close outside the lock.
	t.mu.Lock()
	forwarders := make([]*streamLocalForwarder, 0, len(t.streamLocalForwarders))
	for _, fwd := range t.streamLocalForwarders {
		forwarders = append(forwarders, fwd)
	}
	t.streamLocalForwarders = nil

	channels := make([]net.Conn, 0, len(t.streamLocalChannels))
	for _, conn := range t.streamLocalChannels {
		channels = append(channels, conn)
	}
	t.streamLocalChannels = nil
	t.mu.Unlock()

	for _, fwd := range forwarders {
		_ = fwd.close()
	}
	for _, conn := range channels {
		_ = conn.Close()
	}
}

