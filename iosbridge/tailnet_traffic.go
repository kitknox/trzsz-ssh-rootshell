//go:build rootshell_tailscale

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
	"encoding/json"
	"net"
	"sync/atomic"
)

// tailnetTraffic counts rootshell's own tailnet connections, the in-app
// counterpart of the VPN tunnel's byte counters.
type tailnetTraffic struct {
	bytesIn, bytesOut    atomic.Int64
	activeTCP, activeUDP atomic.Int64
	total                atomic.Int64
}

func (t *tailnetTraffic) json() string {
	b, _ := json.Marshal(struct {
		BytesIn   int64 `json:"bytesIn"`
		BytesOut  int64 `json:"bytesOut"`
		ActiveTCP int64 `json:"activeTCPConnections"`
		ActiveUDP int64 `json:"activeUDPConnections"`
		Total     int64 `json:"totalConnections"`
	}{t.bytesIn.Load(), t.bytesOut.Load(), t.activeTCP.Load(), t.activeUDP.Load(), t.total.Load()})
	return string(b)
}

// track counts c until it closes. Stream conns keep CloseWrite, which the
// descriptor bridge uses to pass half-closes through.
func (t *tailnetTraffic) track(c net.Conn, udp bool) net.Conn {
	active := &t.activeTCP
	if udp {
		active = &t.activeUDP
	}
	t.total.Add(1)
	active.Add(1)
	cc := &countedConn{Conn: c, t: t, active: active}
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return &countedStreamConn{countedConn: cc, cw: cw}
	}
	return cc
}

type countedConn struct {
	net.Conn
	t      *tailnetTraffic
	active *atomic.Int64
	closed atomic.Bool
}

func (c *countedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.t.bytesIn.Add(int64(n))
	return n, err
}

func (c *countedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.t.bytesOut.Add(int64(n))
	return n, err
}

func (c *countedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.active.Add(-1)
	}
	return c.Conn.Close()
}

type countedStreamConn struct {
	*countedConn
	cw interface{ CloseWrite() error }
}

func (c *countedStreamConn) CloseWrite() error { return c.cw.CloseWrite() }
