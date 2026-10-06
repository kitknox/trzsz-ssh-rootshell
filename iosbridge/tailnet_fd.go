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
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
)

// Swift gets one end of a socketpair per tailnet connection; Go pumps the
// other end to the netstack connection.

const (
	datagramSocketBuffer = 2 << 20
	datagramIdleTimeout  = 10 * time.Minute
	maxDatagramSize      = 64 << 10
)

func socketpair(typ int) (swiftFD int, local net.Conn, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, typ, 0)
	if err != nil {
		return -1, nil, err
	}
	syscall.CloseOnExec(fds[0])
	syscall.CloseOnExec(fds[1])
	if typ == syscall.SOCK_DGRAM {
		// AF_UNIX datagram defaults hold only a couple of packets.
		for _, fd := range fds {
			_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, datagramSocketBuffer)
			_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, datagramSocketBuffer)
		}
	}
	f := os.NewFile(uintptr(fds[1]), "tailnet")
	local, err = net.FileConn(f) // dups the descriptor
	_ = f.Close()
	if err != nil {
		_ = syscall.Close(fds[0])
		return -1, nil, err
	}
	return fds[0], local, nil
}

// streamFD bridges a stream connection, passing half-closes through.
func streamFD(remote net.Conn) (int, error) {
	fd, local, err := socketpair(syscall.SOCK_STREAM)
	if err != nil {
		_ = remote.Close()
		return -1, err
	}
	go func() {
		var wg sync.WaitGroup
		pipe := func(dst, src net.Conn) {
			defer wg.Done()
			_, err := io.Copy(dst, src)
			if cw, ok := dst.(interface{ CloseWrite() error }); ok && err == nil {
				_ = cw.CloseWrite()
				return
			}
			// An error on either side ends both directions.
			_ = dst.Close()
			_ = src.Close()
		}
		wg.Add(2)
		go pipe(local, remote)
		go pipe(remote, local)
		wg.Wait()
		_ = local.Close()
		_ = remote.Close()
	}()
	return fd, nil
}

// datagramFD bridges a datagram connection. A full Swift socket drops the
// packet instead of blocking, like a congested UDP path. A datagram socket
// sees no EOF when Swift closes its end, so a write failure or idleness ends
// the bridge.
func datagramFD(remote net.Conn) (int, error) {
	fd, local, err := socketpair(syscall.SOCK_DGRAM)
	if err != nil {
		_ = remote.Close()
		return -1, err
	}
	raw, err := local.(syscall.Conn).SyscallConn()
	if err != nil {
		_ = local.Close()
		_ = remote.Close()
		_ = syscall.Close(fd)
		return -1, err
	}
	var once sync.Once
	done := make(chan struct{})
	stop := func() {
		once.Do(func() {
			close(done)
			_ = local.Close()
			_ = remote.Close()
		})
	}
	var lastActive syncTime
	lastActive.touch()

	go func() { // tailnet -> Swift
		defer stop()
		buf := make([]byte, maxDatagramSize)
		for {
			n, err := remote.Read(buf)
			if err != nil {
				return
			}
			lastActive.touch()
			var werr error
			if cerr := raw.Write(func(s uintptr) bool {
				_, werr = syscall.Write(int(s), buf[:n])
				return true // never wait for space
			}); cerr != nil {
				return
			}
			if werr != nil && !isTransientSendError(werr) {
				return
			}
		}
	}()
	go func() { // Swift -> tailnet
		defer stop()
		buf := make([]byte, maxDatagramSize)
		for {
			n, err := local.Read(buf)
			if err != nil {
				return
			}
			lastActive.touch()
			if _, err := remote.Write(buf[:n]); err != nil && !isTransientSendError(err) {
				return
			}
		}
	}()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if lastActive.since() > datagramIdleTimeout {
					stop()
				}
			}
		}
	}()
	return fd, nil
}

func isTransientSendError(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.ENOBUFS)
}

type syncTime struct {
	mu sync.Mutex
	t  time.Time
}

func (s *syncTime) touch() {
	s.mu.Lock()
	s.t = time.Now()
	s.mu.Unlock()
}

func (s *syncTime) since() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.t)
}

// fixedPeerConn is a bound UDP socket used as a connection to one peer.
type fixedPeerConn struct {
	net.PacketConn
	peer *net.UDPAddr
}

func (c *fixedPeerConn) Read(b []byte) (int, error) {
	for {
		n, from, err := c.ReadFrom(b)
		if err != nil {
			return n, err
		}
		if u, ok := from.(*net.UDPAddr); ok && unmapped(u.AddrPort()) == unmapped(c.peer.AddrPort()) {
			return n, nil
		}
	}
}

func (c *fixedPeerConn) Write(b []byte) (int, error) { return c.WriteTo(b, c.peer) }
func (c *fixedPeerConn) RemoteAddr() net.Addr        { return c.peer }

func unmapped(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}
