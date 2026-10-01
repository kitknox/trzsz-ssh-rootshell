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
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

// Darwin socket options that pin a socket to one interface.
const (
	ipBoundIF   = 25  // IP_BOUND_IF
	ipv6BoundIF = 125 // IPV6_BOUND_IF
)

// directInterface is the physical interface (Wi-Fi, cellular) Direct sockets
// are pinned to. The provider's own sockets otherwise follow its default route
// back into the tunnel and loop.
var directInterface atomic.Int64

// SetDirectInterface sets the interface index Direct-mode sockets bind to
// (0 = unbound). The provider updates it as the network path changes.
func SetDirectInterface(index int) {
	directInterface.Store(int64(index))
}

// directDialer dials upstream from the provider process itself, pinned to the
// physical interface (boundIf, else the live directInterface).
type directDialer struct {
	boundIf int
}

func (d *directDialer) dialer() *net.Dialer {
	dl := &net.Dialer{Timeout: dialTimeout}
	idx := d.boundIf
	if idx == 0 {
		idx = int(directInterface.Load())
	}
	if idx > 0 {
		dl.Control = func(network, _ string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				if network == "tcp6" || network == "udp6" {
					sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6BoundIF, idx)
				} else {
					sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIF, idx)
				}
			})
			if err != nil {
				return err
			}
			return sockErr
		}
	}
	return dl
}

func (d *directDialer) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	conn, err := d.dialer().DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("direct dial tcp %s: %w", addr, err)
	}
	return conn, nil
}

func (d *directDialer) DialUDP(ctx context.Context, addr string) (udpConn, error) {
	conn, err := d.dialer().DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("direct dial udp %s: %w", addr, err)
	}
	return &netUDPConn{conn: conn}, nil
}

// netUDPConn adapts a connected net.Conn to udpConn.
type netUDPConn struct {
	conn net.Conn
}

func (c *netUDPConn) Read(buf []byte) (int, error) { return c.conn.Read(buf) }

func (c *netUDPConn) Write(data []byte) error {
	_, err := c.conn.Write(data)
	return err
}

func (c *netUDPConn) Close() error { return c.conn.Close() }

func (c *netUDPConn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

func (c *netUDPConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
