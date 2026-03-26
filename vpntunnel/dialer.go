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
	"time"

	"github.com/trzsz/tsshd/tsshd"
)

const dialTimeout = 10 * time.Second

// tcpDialer is the interface for dialing TCP connections through the tunnel.
type tcpDialer interface {
	DialTCP(ctx context.Context, addr string) (net.Conn, error)
}

// udpDialer is the interface for forwarding UDP through the tunnel.
// Returns an io adapter around tsshd.PacketConn (Read/Write/Close).
type udpDialer interface {
	DialUDP(ctx context.Context, addr string) (udpConn, error)
}

// udpConn wraps the tsshd PacketConn to a simpler Read/Write/Close interface.
type udpConn interface {
	Read(buf []byte) (int, error)
	Write(data []byte) error
	Close() error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// tsshDialer dials through the tsshd transport (KCP/QUIC).
type tsshDialer struct {
	client *tsshd.SshUdpClient
}

func (d *tsshDialer) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	// tsshd.Stream embeds net.Conn
	conn, err := d.client.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("tssh dial tcp %s: %w", addr, err)
	}
	return conn, nil
}

func (d *tsshDialer) DialUDP(ctx context.Context, addr string) (udpConn, error) {
	pconn, err := d.client.DialUDP("udp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("tssh dial udp %s: %w", addr, err)
	}
	return &packetConnAdapter{pconn: pconn}, nil
}

// packetConnAdapter wraps tsshd.PacketConn to implement udpConn.
type packetConnAdapter struct {
	pconn tsshd.PacketConn
}

func (a *packetConnAdapter) Read(buf []byte) (int, error) {
	return a.pconn.Read(buf)
}

func (a *packetConnAdapter) Write(data []byte) error {
	return a.pconn.Write(data)
}

func (a *packetConnAdapter) Close() error {
	return a.pconn.Close()
}

func (a *packetConnAdapter) SetReadDeadline(_ time.Time) error {
	return nil // tsshd PacketConn doesn't support deadlines
}

func (a *packetConnAdapter) SetWriteDeadline(_ time.Time) error {
	return nil
}

// socks5Dialer dials through a localhost SOCKS5 proxy (backed by Swift Citadel).
type socks5Dialer struct {
	proxyAddr string
}

func (d *socks5Dialer) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: dialTimeout}
	proxyConn, err := dialer.DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5 connect to proxy %s: %w", d.proxyAddr, err)
	}

	// Bound handshake time to avoid hanging dial goroutines under proxy pressure.
	_ = proxyConn.SetDeadline(time.Now().Add(dialTimeout))
	if err := socks5Handshake(proxyConn, addr); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("socks5 handshake for %s: %w", addr, err)
	}
	_ = proxyConn.SetDeadline(time.Time{})

	return proxyConn, nil
}

// socks5Handshake performs the SOCKS5 protocol handshake.
func socks5Handshake(conn net.Conn, targetAddr string) error {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", targetAddr, err)
	}

	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return fmt.Errorf("invalid port %q: %w", portStr, err)
	}

	// Method negotiation: no auth
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("write method: %w", err)
	}

	methodResp := make([]byte, 2)
	if _, err := readFull(conn, methodResp); err != nil {
		return fmt.Errorf("read method response: %w", err)
	}
	if methodResp[0] != 0x05 || methodResp[1] != 0x00 {
		return fmt.Errorf("unsupported auth method: %x", methodResp[1])
	}

	// CONNECT request with address type chosen by host kind.
	req := []byte{
		0x05, // SOCKS5
		0x01, // CONNECT
		0x00, // reserved
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01) // IPv4
			req = append(req, v4...)
		} else {
			req = append(req, 0x04) // IPv6
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03, byte(len(host))) // domain
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port&0xff))

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("write connect: %w", err)
	}

	// Read reply header
	reply := make([]byte, 4)
	if _, err := readFull(conn, reply); err != nil {
		return fmt.Errorf("read connect reply: %w", err)
	}
	if reply[0] != 0x05 {
		return fmt.Errorf("invalid SOCKS version in reply: %d", reply[0])
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("SOCKS5 connect failed: status %d", reply[1])
	}

	// Skip bound address
	switch reply[3] {
	case 0x01: // IPv4
		skip := make([]byte, 4+2)
		if _, err := readFull(conn, skip); err != nil {
			return fmt.Errorf("skip ipv4 bound addr: %w", err)
		}
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := readFull(conn, lenBuf); err != nil {
			return fmt.Errorf("read domain len: %w", err)
		}
		skip := make([]byte, int(lenBuf[0])+2)
		if _, err := readFull(conn, skip); err != nil {
			return fmt.Errorf("skip domain bound addr: %w", err)
		}
	case 0x04: // IPv6
		skip := make([]byte, 16+2)
		if _, err := readFull(conn, skip); err != nil {
			return fmt.Errorf("skip ipv6 bound addr: %w", err)
		}
	default:
		return fmt.Errorf("unknown address type: %d", reply[3])
	}

	return nil
}

// readFull reads exactly len(buf) bytes from conn.
func readFull(conn net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		nn, err := conn.Read(buf[n:])
		n += nn
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
