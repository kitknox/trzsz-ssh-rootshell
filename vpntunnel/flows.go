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

package vpntunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// flowRegistry tracks active TCP flows so CaptureResetFlows can RST them and
// make apps reconnect through the interceptor.
type flowRegistry struct {
	mu    sync.Mutex
	seq   uint64
	flows map[uint64]flowEntry
}

type flowEntry struct {
	ep     tcpip.Endpoint
	cancel context.CancelFunc
}

func newFlowRegistry() *flowRegistry {
	return &flowRegistry{flows: make(map[uint64]flowEntry)}
}

func (r *flowRegistry) add(ep tcpip.Endpoint, cancel context.CancelFunc) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	r.flows[r.seq] = flowEntry{ep: ep, cancel: cancel}
	return r.seq
}

func (r *flowRegistry) remove(id uint64) {
	r.mu.Lock()
	delete(r.flows, id)
	r.mu.Unlock()
}

func (r *flowRegistry) abortAll() int {
	r.mu.Lock()
	flows := r.flows
	r.flows = make(map[uint64]flowEntry)
	r.mu.Unlock()
	for _, f := range flows {
		f.ep.Abort()
		f.cancel()
	}
	return len(flows)
}

// peekConn buffers bytes read ahead of the real consumer. While recording, all
// bytes handed out are kept so a failed TLS interception can replay them to
// a passthrough relay; discardWrites hides any alert the TLS server emits.
type peekConn struct {
	net.Conn
	buf           []byte
	recording     bool
	recorded      []byte
	discardWrites atomic.Bool
}

const maxPeekRecord = 64 << 10

var errPeekOverflow = errors.New("peek buffer overflow")

func newPeekConn(c net.Conn) *peekConn { return &peekConn{Conn: c} }

// peek ensures at least n bytes are buffered, waiting until deadline.
func (p *peekConn) peek(n int, deadline time.Time) ([]byte, error) {
	if len(p.buf) >= n {
		return p.buf[:n], nil
	}
	_ = p.Conn.SetReadDeadline(deadline)
	defer p.Conn.SetReadDeadline(time.Time{})
	tmp := make([]byte, 4096)
	for len(p.buf) < n {
		k, err := p.Conn.Read(tmp)
		p.buf = append(p.buf, tmp[:k]...)
		if err != nil {
			return p.buf, err
		}
	}
	return p.buf[:n], nil
}

func (p *peekConn) Read(b []byte) (int, error) {
	var n int
	var err error
	if len(p.buf) > 0 {
		n = copy(b, p.buf)
		p.buf = p.buf[n:]
	} else {
		n, err = p.Conn.Read(b)
	}
	if p.recording && n > 0 {
		if len(p.recorded)+n > maxPeekRecord {
			return n, errPeekOverflow
		}
		p.recorded = append(p.recorded, b[:n]...)
	}
	return n, err
}

func (p *peekConn) Write(b []byte) (int, error) {
	if p.discardWrites.Load() {
		return len(b), nil
	}
	return p.Conn.Write(b)
}

func (p *peekConn) startRecording() {
	p.recording = true
	p.recorded = nil
}

// replay returns a conn that yields every byte consumed since startRecording
// again, then whatever is still buffered, then the rest of the stream.
func (p *peekConn) replay() *peekConn {
	buf := make([]byte, 0, len(p.recorded)+len(p.buf))
	buf = append(buf, p.recorded...)
	buf = append(buf, p.buf...)
	return &peekConn{Conn: p.Conn, buf: buf}
}

// idleConn refreshes deadlines on every read and write, closing quiet flows
// the same way the raw relay does.
type idleConn struct {
	net.Conn
	idle atomic.Int64 // nanoseconds
}

func newIdleConn(c net.Conn, idle time.Duration) *idleConn {
	ic := &idleConn{Conn: c}
	ic.idle.Store(int64(idle))
	return ic
}

func (c *idleConn) setIdle(d time.Duration) { c.idle.Store(int64(d)) }

func (c *idleConn) Read(b []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(time.Duration(c.idle.Load())))
	return c.Conn.Read(b)
}

func (c *idleConn) Write(b []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(time.Duration(c.idle.Load())))
	return c.Conn.Write(b)
}

// relayConns copies both directions until either side finishes, returning the
// byte counts (client→upstream, upstream→client).
// A client half-close keeps the response direction open (bounded by the idle
// timeout); an upstream close ends the flow.
func relayConns(ctx context.Context, client io.ReadWriter, clientCloser io.Closer, upstream net.Conn) (int64, int64) {
	var up, down int64
	upDone := make(chan struct{})
	downDone := make(chan struct{})
	go func() {
		defer close(upDone)
		up, _ = io.Copy(upstream, client)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer close(downDone)
		down, _ = io.Copy(client, upstream)
	}()
	select {
	case <-downDone:
	case <-upDone:
		select {
		case <-downDone:
		case <-ctx.Done():
		case <-time.After(tcpIdleTimeout):
		}
	case <-ctx.Done():
	}
	_ = upstream.Close()
	_ = clientCloser.Close()
	<-upDone
	<-downDone
	return up, down
}
