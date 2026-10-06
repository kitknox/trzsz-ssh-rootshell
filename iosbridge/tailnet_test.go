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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

func fdConn(t *testing.T, fd int) net.Conn {
	t.Helper()
	f := os.NewFile(uintptr(fd), "test")
	c, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		t.Fatalf("file conn: %v", err)
	}
	return c
}

func TestSOCKS5PasswordAuth(t *testing.T) {
	creds := &socks5Credentials{user: "u", pass: "secret"}
	for _, tc := range []struct {
		name string
		pass string
		ok   bool
	}{{"good", "secret", true}, {"bad", "nope", false}} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			type result struct {
				host string
				port int
				err  error
			}
			done := make(chan result, 1)
			go func() {
				h, p, err := socks5HandshakeAuth(server, creds)
				done <- result{h, p, err}
				_ = server.Close()
			}()
			mustWrite := func(b []byte) {
				if _, err := client.Write(b); err != nil {
					t.Fatalf("write: %v", err)
				}
			}
			mustRead := func(n int) []byte {
				b := make([]byte, n)
				if _, err := io.ReadFull(client, b); err != nil {
					t.Fatalf("read: %v", err)
				}
				return b
			}
			mustWrite([]byte{0x05, 0x02, 0x00, 0x02})
			if got := mustRead(2); !bytes.Equal(got, []byte{0x05, 0x02}) {
				t.Fatalf("method reply = %v", got)
			}
			auth := []byte{0x01, 1, 'u', byte(len(tc.pass))}
			mustWrite(append(auth, tc.pass...))
			status := mustRead(2)
			if !tc.ok {
				if status[1] == 0x00 {
					t.Fatal("bad password accepted")
				}
				if (<-done).err == nil {
					t.Fatal("handshake succeeded with bad password")
				}
				return
			}
			if status[1] != 0x00 {
				t.Fatalf("auth status = %v", status)
			}
			req := []byte{0x05, 0x01, 0x00, 0x03, byte(len("peer"))}
			req = append(req, "peer"...)
			req = binary.BigEndian.AppendUint16(req, 22)
			mustWrite(req)
			r := <-done
			if r.err != nil || r.host != "peer" || r.port != 22 {
				t.Fatalf("handshake = %q %d %v", r.host, r.port, r.err)
			}
		})
	}
}

func TestSOCKS5RejectsNoAuthWhenRequired(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		_, _, _ = socks5HandshakeAuth(server, &socks5Credentials{user: "u", pass: "p"})
		_ = server.Close()
	}()
	_, _ = client.Write([]byte{0x05, 0x01, 0x00})
	b := make([]byte, 2)
	if _, err := io.ReadFull(client, b); err != nil || b[1] != 0xFF {
		t.Fatalf("reply = %v %v, want no acceptable methods", b, err)
	}
}

func TestStreamFDBridge(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	remote, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer := <-accepted
	defer peer.Close()

	fd, err := streamFD(remote)
	if err != nil {
		t.Fatal(err)
	}
	swift := fdConn(t, fd)
	defer swift.Close()

	if _, err := swift.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(peer, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("peer got %q %v", buf, err)
	}
	if _, err := peer.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(swift, buf); err != nil || string(buf) != "world" {
		t.Fatalf("swift got %q %v", buf, err)
	}
	// A half-close from Swift reaches the peer as EOF, and the reverse
	// direction keeps working.
	_ = swift.(*net.UnixConn).CloseWrite()
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := peer.Read(buf); err != io.EOF {
		t.Fatalf("peer read after half-close = %d %v, want EOF", n, err)
	}
	if _, err := peer.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(swift, buf); err != nil || string(buf) != "after" {
		t.Fatalf("swift got %q %v after half-close", buf, err)
	}
}

func TestDatagramFDBridgeKeepsBoundaries(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	remote, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	fd, err := datagramFD(remote)
	if err != nil {
		t.Fatal(err)
	}
	swift := fdConn(t, fd)
	defer swift.Close()
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	_ = swift.SetReadDeadline(time.Now().Add(2 * time.Second))

	for _, msg := range []string{"one", "two-two"} {
		if _, err := swift.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, 64)
	var from *net.UDPAddr
	for _, want := range []string{"one", "two-two"} {
		n, addr, err := server.ReadFromUDP(buf)
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("server got %q %v, want %q", buf[:n], err, want)
		}
		from = addr
	}
	big := bytes.Repeat([]byte{7}, 1200)
	if _, err := server.WriteToUDP(big, from); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 2000)
	n, err := swift.Read(got)
	if err != nil || n != len(big) {
		t.Fatalf("swift read %d %v, want %d", n, err, len(big))
	}
}

func TestFixedPeerConnFiltersOtherSenders(t *testing.T) {
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	peer, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer peer.Close()
	stranger, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer stranger.Close()

	c := &fixedPeerConn{PacketConn: local, peer: peer.LocalAddr().(*net.UDPAddr)}
	_, _ = stranger.WriteTo([]byte("ignored"), local.LocalAddr())
	_, _ = peer.WriteTo([]byte("kept"), local.LocalAddr())
	_ = local.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "kept" {
		t.Fatalf("read %q %v, want kept", buf[:n], err)
	}
}

func TestTailnetProxyDialsDirectWithoutEngine(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err == nil {
			_, _ = io.Copy(c, c)
			_ = c.Close()
		}
	}()

	js, err := TailnetProxyStart()
	if err != nil {
		t.Fatal(err)
	}
	defer TailnetProxyStop()
	var info tailnetProxyInfo
	if err := json.Unmarshal([]byte(js), &info); err != nil {
		t.Fatal(err)
	}
	again, _ := TailnetProxyStart()
	if again != js {
		t.Fatalf("second start returned new proxy %s", again)
	}

	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte{0x05, 0x01, 0x02})
	b := make([]byte, 2)
	_, _ = io.ReadFull(c, b)
	auth := []byte{0x01, byte(len(info.User))}
	auth = append(auth, info.User...)
	auth = append(auth, byte(len(info.Pass)))
	auth = append(auth, info.Pass...)
	_, _ = c.Write(auth)
	_, _ = io.ReadFull(c, b)
	if b[1] != 0x00 {
		t.Fatalf("auth failed: %v", b)
	}
	addr := echo.Addr().(*net.TCPAddr)
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, addr.IP.To4()...)
	req = binary.BigEndian.AppendUint16(req, uint16(addr.Port))
	_, _ = c.Write(req)
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0x00 {
		t.Fatalf("connect reply %v %v", reply, err)
	}
	_, _ = c.Write([]byte("ping"))
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "ping" {
		t.Fatalf("echo %q %v", got, err)
	}
}

func TestTailnetCallsWithoutEngine(t *testing.T) {
	if got := TailnetResolve("100.64.0.1"); got != "" {
		t.Fatalf("resolve without engine = %q", got)
	}
	if _, err := TailnetDialTCP("100.64.0.1", 22, 100); err == nil {
		t.Fatal("dial without engine succeeded")
	}
	if TailnetRunning() {
		t.Fatal("running without engine")
	}
	var st struct{ State string }
	if err := json.Unmarshal([]byte(TailnetStatus()), &st); err != nil || st.State != "Stopped" {
		t.Fatalf("status = %+v %v", st, err)
	}
}
