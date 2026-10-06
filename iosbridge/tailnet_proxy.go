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
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"sync"
	"time"
)

// The loopback proxy lets local-shell tools (curl via ALL_PROXY) reach the
// tailnet. Other apps on the device can connect to loopback too, so it
// requires per-launch credentials.

type tailnetProxy struct {
	ln    net.Listener
	creds socks5Credentials
	wg    sync.WaitGroup
}

var (
	tailnetProxyMu  sync.Mutex
	tailnetProxyCur *tailnetProxy
)

type tailnetProxyInfo struct {
	Port int    `json:"port"`
	User string `json:"user"`
	Pass string `json:"pass"`
}

func randomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// TailnetProxyStart starts (or returns the running) SOCKS5 proxy on
// 127.0.0.1 and returns {port,user,pass} JSON. Tailnet hosts go over
// Tailscale (an exit node, when set, takes everything else); other hosts
// are dialed directly.
func TailnetProxyStart() (string, error) {
	tailnetProxyMu.Lock()
	defer tailnetProxyMu.Unlock()
	p := tailnetProxyCur
	if p == nil {
		user, err := randomToken()
		if err != nil {
			return "", err
		}
		pass, err := randomToken()
		if err != nil {
			return "", err
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return "", err
		}
		p = &tailnetProxy{ln: ln, creds: socks5Credentials{user: user, pass: pass}}
		p.wg.Add(1)
		go p.serve()
		tailnetProxyCur = p
	}
	js, _ := json.Marshal(tailnetProxyInfo{
		Port: p.ln.Addr().(*net.TCPAddr).Port,
		User: p.creds.user,
		Pass: p.creds.pass,
	})
	return string(js), nil
}

// TailnetProxyStop closes the proxy listener; open connections finish.
func TailnetProxyStop() {
	tailnetProxyMu.Lock()
	p := tailnetProxyCur
	tailnetProxyCur = nil
	tailnetProxyMu.Unlock()
	if p != nil {
		_ = p.ln.Close()
		p.wg.Wait()
	}
}

func (p *tailnetProxy) serve() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *tailnetProxy) handle(local net.Conn) {
	_ = local.SetDeadline(time.Now().Add(10 * time.Second))
	host, port, err := socks5HandshakeAuth(local, &p.creds)
	if err != nil {
		if se, ok := err.(*socks5Error); ok {
			socks5SendReply(local, se.rep)
		}
		_ = local.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	remote, err := tailnetOrDirectDial(ctx, host, port)
	cancel()
	if err != nil {
		socks5SendReply(local, 0x05) // connection refused
		_ = local.Close()
		return
	}
	_ = local.SetDeadline(time.Time{})
	socks5SendReply(local, 0x00)
	bridgeConnections(local, remote)
}
