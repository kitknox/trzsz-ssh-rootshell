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
	"io"
	"net"
	"testing"
)

func TestTailnetTrafficCounts(t *testing.T) {
	var tr tailnetTraffic
	a, b := net.Pipe()
	defer b.Close()
	c := tr.track(a, true)
	if _, ok := c.(interface{ CloseWrite() error }); ok {
		t.Fatal("datagram conn gained CloseWrite")
	}
	go func() {
		buf := make([]byte, 5)
		_, _ = io.ReadFull(b, buf)
		_, _ = b.Write([]byte("abc"))
	}()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 3)); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	_ = c.Close()

	var got map[string]int64
	if err := json.Unmarshal([]byte(tr.json()), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"bytesIn": 3, "bytesOut": 5, "activeTCPConnections": 0, "activeUDPConnections": 0, "totalConnections": 1}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d", k, got[k], v)
		}
	}
}

func TestTailnetTrafficKeepsCloseWrite(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if s, err := ln.Accept(); err == nil {
			defer s.Close()
			_, _ = io.Copy(io.Discard, s)
		}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var tr tailnetTraffic
	c := tr.track(raw, false)
	defer c.Close()
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("stream conn lost CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if n := tr.activeTCP.Load(); n != 1 {
		t.Fatalf("active TCP = %d, want 1", n)
	}
}
