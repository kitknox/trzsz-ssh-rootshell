package vpntunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestHostMatch(t *testing.T) {
	m := compileHostRules([]string{"-*.apple.com", "*.example.com", "api.test:8443", "any.test:0", "10.1.2.3", "-skip.test", "*"})
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"www.apple.com", 443, false},
		{"a.example.com", 443, true},
		{"A.Example.COM.", 443, true},
		{"api.test", 8443, true},
		{"api.test", 443, true}, // caught by the trailing "*"
		{"any.test", 9999, true},
		{"skip.test", 443, false},
		{"other.test", 80, false},
		{"10.1.2.3", 443, true},
	}
	for _, c := range cases {
		if got := m.match(c.host, c.port); got != c.want {
			t.Errorf("match(%q, %d) = %v, want %v", c.host, c.port, got, c.want)
		}
	}
	if !m.hasExplicitPort(8443) || !m.hasExplicitPort(9999) {
		t.Errorf("explicit ports wrong: %v any=%v", m.ports, m.anyPort)
	}
	if specific := compileHostRules([]string{"api.test:8443"}); !specific.hasExplicitPort(8443) || specific.hasExplicitPort(9999) {
		t.Errorf("specific port rule peeks wrong ports: %v", specific.ports)
	}
	if compileHostRules(nil).match("x.com", 443) {
		t.Error("empty rules must not match")
	}
}

func TestGlobAndURLGlob(t *testing.T) {
	if !globMatch("*.example.com", "a.b.example.com") || globMatch("*.example.com", "example.com") {
		t.Error("glob subdomain semantics")
	}
	if !globMatch("a?c", "abc") || globMatch("a?c", "ac") {
		t.Error("glob ?")
	}
	if g := normalizeURLGlob("api.example.com"); g != "*://api.example.com/*" {
		t.Errorf("normalize = %q", g)
	}
	if g := normalizeURLGlob("https://x.com/v1/*"); g != "https://x.com/v1/*" {
		t.Errorf("normalize = %q", g)
	}
}

func newTestCA(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test capture CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})), pool
}

func TestCertMint(t *testing.T) {
	certPEM, keyPEM, pool := newTestCA(t)
	m, err := newCertMinter(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"www.example.com", "192.0.2.7"} {
		c, err := m.certFor(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("verify %s: %v", name, err)
		}
		if d := c.Leaf.NotAfter.Sub(c.Leaf.NotBefore); d > 825*24*time.Hour {
			t.Errorf("leaf validity %v exceeds 825 days", d)
		}
		again, _ := m.certFor(name)
		if again != c {
			t.Error("leaf not cached")
		}
	}
}

func TestDNSCacheAndHTTPSNoData(t *testing.T) {
	name := dnsmessage.MustNewName("www.example.com.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, Response: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	_ = b.AResource(dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 9}})
	msg, _ := b.Finish()
	c := newDNSCache()
	c.observe(msg)
	if got := c.lookup("192.0.2.9"); got != "www.example.com" {
		t.Errorf("lookup = %q", got)
	}

	q := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 9, RecursionDesired: true})
	_ = q.StartQuestions()
	_ = q.Question(dnsmessage.Question{Name: name, Type: dnsTypeHTTPS, Class: dnsmessage.ClassINET})
	query, _ := q.Finish()
	resp := synthesizeHTTPSNoData(query)
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil || !h.Response || h.ID != 9 || h.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("bad synthesized header %+v %v", h, err)
	}
	_ = p.SkipAllQuestions()
	if _, err := p.AnswerHeader(); err != dnsmessage.ErrSectionDone {
		t.Error("expected no answers")
	}
	if synthesizeHTTPSNoData(msg) != nil {
		t.Error("must ignore responses / A queries")
	}
}

func wsFrame(op byte, payload []byte, mask bool) []byte {
	b := []byte{0x80 | op}
	l := len(payload)
	m := byte(0)
	if mask {
		m = 0x80
	}
	switch {
	case l < 126:
		b = append(b, m|byte(l))
	case l < 65536:
		b = append(b, m|126, byte(l>>8), byte(l))
	default:
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(l))
		b = append(append(b, m|127), ext[:]...)
	}
	if mask {
		key := []byte{1, 2, 3, 4}
		b = append(b, key...)
		for i, c := range payload {
			b = append(b, c^key[i%4])
		}
		return b
	}
	return append(b, payload...)
}

// testCapture wires up a capture state backed by a temp spool.
func testCapture(t *testing.T, mutate func(*captureConfig)) (string, *x509.CertPool) {
	t.Helper()
	certPEM, keyPEM, pool := newTestCA(t)
	dir := t.TempDir()
	resetCaptureTunnelState("direct", nil)
	cfg := captureConfig{
		Enabled: true, SessionID: "s1", SegmentNonce: "n1", SpoolDir: dir,
		MITMHosts: []string{"-pinned.example.com", "*"}, CACertPEM: certPEM, CAKeyPEM: keyPEM,
		EnableH2: true, SkipUpstreamVerify: true, AutoBypassPinned: true, Pcap: true,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	raw, _ := json.Marshal(cfg)
	if err := applyCaptureConfig(raw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeCapture("test", false)
	})
	return dir, pool
}

// startFlow hands one TCP flow to the capture layer and returns the app side.
func startFlow(t *testing.T, dstPort int, upstream string) (net.Conn, chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	app, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveCapturedFlow(&flowCtx{
			ctx: context.Background(), cs: captureCur.Load(), env: currentCaptureEnv(),
			client: server, dstIP: "192.0.2.10", dstPort: dstPort, dstAddr: "192.0.2.10:" + itoa(dstPort),
			srcAddr: "10.0.0.2:5555", start: time.Now(),
			dial: func(ctx context.Context) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", upstream)
			},
		})
	}()
	return app, done
}

func itoa(n int) string { return strconv.Itoa(n) }

func readEvents(t *testing.T, dir string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, indexFileName))
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func eventsOf(evs []map[string]any, kind string) []map[string]any {
	var out []map[string]any
	for _, e := range evs {
		if e["t"] == kind {
			out = append(out, e)
		}
	}
	return out
}

func waitDone(t *testing.T, done chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("flow did not finish")
	}
}

func oneShotClient(app net.Conn, pool *x509.CertPool, h2 bool) *http.Client {
	used := false
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "api.example.com"},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if used {
				return nil, io.EOF
			}
			used = true
			cfg := &tls.Config{RootCAs: pool, ServerName: "api.example.com", NextProtos: []string{"http/1.1"}}
			if h2 {
				cfg.NextProtos = []string{"h2", "http/1.1"}
			}
			c := tls.Client(app, cfg)
			if err := c.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			return c, nil
		},
		ForceAttemptHTTP2:  h2,
		DisableCompression: true,
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func TestMITMHTTP1AndHTTP2(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "h1"
		if h2 {
			name = "h2"
		}
		t.Run(name, func(t *testing.T) {
			dir, pool := testCapture(t, func(c *captureConfig) {
				c.RewriteRules = []rewriteRule{
					{ID: "r1", Enabled: true, Match: "*://api.example.com/*", Phase: "response", Action: "setHeader", Header: "X-Rewritten", Value: "yes"},
					{ID: "r2", Enabled: true, Match: "api.example.com/json*", Phase: "response", Action: "replaceBody", Find: "world", Replace: "capture"},
					{ID: "r3", Enabled: true, Match: "*", Phase: "request", Action: "addHeader", Header: "X-Added", Value: "1"},
				}
			})
			up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Saw-Added", r.Header.Get("X-Added"))
				body, _ := io.ReadAll(r.Body)
				_, _ = w.Write([]byte(`{"hello":"world","echo":"` + string(body) + `"}`))
			}))
			up.EnableHTTP2 = h2
			up.StartTLS()
			defer up.Close()

			app, done := startFlow(t, 443, up.Listener.Addr().String())
			client := oneShotClient(app, pool, h2)
			resp, err := client.Post("https://api.example.com/json?x=1", "text/plain", strings.NewReader("ping"))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != `{"hello":"capture","echo":"ping"}` {
				t.Errorf("body = %s", body)
			}
			if resp.Header.Get("X-Rewritten") != "yes" || resp.Header.Get("X-Saw-Added") != "1" {
				t.Errorf("headers = %v", resp.Header)
			}
			if h2 != (resp.ProtoMajor == 2) {
				t.Errorf("proto = %s", resp.Proto)
			}
			client.CloseIdleConnections()
			app.Close()
			waitDone(t, done)
			CaptureStop()

			evs := readEvents(t, dir)
			starts := eventsOf(evs, "txStart")
			if len(starts) != 1 || starts[0]["url"] != "https://api.example.com/json?x=1" || starts[0]["method"] != "POST" {
				t.Fatalf("txStart = %v", starts)
			}
			if !h2 && !strings.Contains(starts[0]["reqHead"].(string), "X-Added: 1") {
				t.Errorf("reqHead missing rewrite: %q", starts[0]["reqHead"])
			}
			res := eventsOf(evs, "txResponse")
			if len(res) != 1 || res[0]["status"].(float64) != 200 {
				t.Fatalf("txResponse = %v", res)
			}
			ends := eventsOf(evs, "txEnd")
			if len(ends) != 1 {
				t.Fatalf("txEnd = %v", ends)
			}
			resFile, _ := ends[0]["resBodyFile"].(string)
			stored, _ := os.ReadFile(filepath.Join(dir, resFile))
			if string(stored) != `{"hello":"capture","echo":"ping"}` {
				t.Errorf("stored body = %q", stored)
			}
			reqFile, _ := ends[0]["reqBodyFile"].(string)
			if b, _ := os.ReadFile(filepath.Join(dir, reqFile)); string(b) != "ping" {
				t.Errorf("stored request body = %q", b)
			}
			if kl, _ := os.ReadFile(filepath.Join(dir, keylogFileName)); !bytes.Contains(kl, []byte("CLIENT_")) {
				t.Errorf("keylog missing: %q", kl)
			}
		})
	}
}

func TestPinnedClientIsBypassed(t *testing.T) {
	dir, _ := testCapture(t, nil)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()

	app, done := startFlow(t, 443, up.Listener.Addr().String())
	c := tls.Client(app, &tls.Config{ServerName: "api.example.com", RootCAs: x509.NewCertPool()})
	if err := c.Handshake(); err == nil {
		t.Fatal("handshake should fail against an untrusted CA")
	}
	c.Close()
	waitDone(t, done)
	if !currentCaptureEnv().isBypassed("api.example.com") {
		t.Error("host not bypassed")
	}

	// Next connection passes through to the real server.
	app2, done2 := startFlow(t, 443, up.Listener.Addr().String())
	c2 := tls.Client(app2, &tls.Config{ServerName: "api.example.com", InsecureSkipVerify: true})
	if err := c2.Handshake(); err != nil {
		t.Fatal(err)
	}
	if got := c2.ConnectionState().PeerCertificates[0].Subject.Organization; len(got) == 0 || got[0] != "Acme Co" {
		t.Errorf("expected the upstream's own cert, got %v", got)
	}
	c2.Close()
	waitDone(t, done2)
	CaptureStop()

	evs := readEvents(t, dir)
	if rej := eventsOf(evs, "tlsRejected"); len(rej) != 1 || rej[0]["bypassed"] != true {
		t.Errorf("tlsRejected = %v", rej)
	}
	tun := eventsOf(evs, "tunnel")
	if len(tun) != 1 || tun[0]["reason"] != "bypassed" {
		t.Errorf("tunnel = %v", tun)
	}
}

func TestExcludedHostPassesThrough(t *testing.T) {
	dir, _ := testCapture(t, nil)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("direct")) }))
	defer up.Close()
	app, done := startFlow(t, 443, up.Listener.Addr().String())
	c := tls.Client(app, &tls.Config{ServerName: "pinned.example.com", InsecureSkipVerify: true})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	c.Close()
	waitDone(t, done)
	CaptureStop()
	tun := eventsOf(readEvents(t, dir), "tunnel")
	if len(tun) != 1 || tun[0]["reason"] != "notMatched" || tun[0]["sni"] != "pinned.example.com" {
		t.Errorf("tunnel = %v", tun)
	}
}

func TestPlainHTTPWebSocketAndContinue(t *testing.T) {
	dir, _ := testCapture(t, nil)
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		// Request 1: Expect: 100-continue POST.
		head, _ := readHead(br)
		if !strings.Contains(string(head), "Expect: 100-continue") {
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 100 Continue\r\n\r\n"))
		body := make([]byte, 5)
		_, _ = io.ReadFull(br, body)
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n3\r\ngot\r\n0\r\n\r\n"))
		// Request 2: WebSocket upgrade, then echo one frame back unmasked.
		head, _ = readHead(br)
		if strings.Contains(string(head), "Sec-WebSocket-Extensions") {
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		hdr := make([]byte, 6)
		_, _ = io.ReadFull(br, hdr)
		n := int(hdr[1] & 0x7f)
		payload := make([]byte, n)
		_, _ = io.ReadFull(br, payload)
		for i := range payload {
			payload[i] ^= hdr[2+i%4]
		}
		_, _ = c.Write(wsFrame(1, append([]byte("echo:"), payload...), false))
	}()

	app, done := startFlow(t, 80, up.Addr().String())
	br := bufio.NewReader(app)
	_, _ = app.Write([]byte("POST /upload HTTP/1.1\r\nHost: plain.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n"))
	cont, _ := readHead(br)
	if !strings.HasPrefix(string(cont), "HTTP/1.1 100") {
		t.Fatalf("expected 100 Continue, got %q", cont)
	}
	_, _ = app.Write([]byte("hello"))
	resHead, _ := readHead(br)
	if !strings.HasPrefix(string(resHead), "HTTP/1.1 200") {
		t.Fatalf("response head %q", resHead)
	}
	var sink bytes.Buffer
	if err := copyChunked(io.Discard, br, &sink); err != nil || sink.String() != "got" {
		t.Fatalf("chunked body %q %v", sink.String(), err)
	}

	_, _ = app.Write([]byte("GET /ws HTTP/1.1\r\nHost: plain.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"))
	wsHead, _ := readHead(br)
	if !strings.HasPrefix(string(wsHead), "HTTP/1.1 101") {
		t.Fatalf("ws head %q", wsHead)
	}
	_, _ = app.Write(wsFrame(1, []byte("hi"), true))
	echo := make([]byte, 2+len("echo:hi"))
	if _, err := io.ReadFull(br, echo); err != nil || string(echo[2:]) != "echo:hi" {
		t.Fatalf("echo %q %v", echo, err)
	}
	app.Close()
	waitDone(t, done)
	CaptureStop()

	evs := readEvents(t, dir)
	starts := eventsOf(evs, "txStart")
	if len(starts) != 2 || starts[0]["url"] != "http://plain.test/upload" {
		t.Fatalf("txStart = %v", starts)
	}
	ends := eventsOf(evs, "txEnd")
	if len(ends) != 2 || ends[1]["ws"] != true {
		t.Fatalf("txEnd = %v", ends)
	}
	frames, _ := os.ReadFile(filepath.Join(dir, "ws", starts[1]["id"].(string)+".jsonl"))
	if !bytes.Contains(frames, []byte(`"text":"hi"`)) || !bytes.Contains(frames, []byte(`"text":"echo:hi"`)) {
		t.Errorf("ws frames = %s", frames)
	}
}

func TestServerSpeaksFirstIsRelayed(t *testing.T) {
	// Only an any-port rule makes a non-web port peekable; those wait briefly.
	dir, _ := testCapture(t, func(c *captureConfig) { c.MITMHosts = []string{"*:0"} })
	up, _ := net.Listen("tcp", "127.0.0.1:0")
	defer up.Close()
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("220 smtp ready\r\n"))
		c.Close()
	}()
	app, done := startFlow(t, 2525, up.Addr().String())
	_ = app.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(app).ReadString('\n')
	if err != nil || line != "220 smtp ready\r\n" {
		t.Fatalf("banner %q %v", line, err)
	}
	app.Close()
	waitDone(t, done)
	CaptureStop()
	if tun := eventsOf(readEvents(t, dir), "tunnel"); len(tun) != 1 || tun[0]["reason"] != "notHTTP" {
		t.Errorf("tunnel = %v", tun)
	}
}

func TestCAEndpoint(t *testing.T) {
	testCapture(t, func(c *captureConfig) { c.CAProfileB64 = "cHJvZmlsZQ==" })
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	app, _ := net.Dial("tcp", ln.Addr().String())
	server, _ := ln.Accept()
	go serveCapturedFlow(&flowCtx{ctx: context.Background(), cs: captureCur.Load(), env: currentCaptureEnv(),
		client: server, dstIP: caEndpointIP, dstPort: 80})
	_, _ = app.Write([]byte("GET /ca.mobileconfig HTTP/1.1\r\nHost: 10.0.0.1\r\nConnection: close\r\n\r\n"))
	b, _ := io.ReadAll(app)
	if !bytes.Contains(b, []byte("application/x-apple-aspen-config")) || !bytes.HasSuffix(b, []byte("profile")) {
		t.Errorf("response %q", b)
	}
}

func TestConnectTunnelRelays(t *testing.T) {
	testCapture(t, nil)
	up, _ := net.Listen("tcp", "127.0.0.1:0")
	defer up.Close()
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		_, _ = readHead(br)
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		line, _ := br.ReadString('\n') // bytes after the tunnel opened
		_, _ = c.Write([]byte("echo " + line))
	}()
	app, done := startFlow(t, 80, up.Addr().String())
	_, _ = app.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	br := bufio.NewReader(app)
	head, _ := readHead(br)
	if !strings.HasPrefix(string(head), "HTTP/1.1 200") {
		t.Fatalf("head %q", head)
	}
	_, _ = app.Write([]byte("ping\n"))
	_ = app.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got, err := br.ReadString('\n'); err != nil || got != "echo ping\n" {
		t.Fatalf("tunnel echo %q %v", got, err)
	}
	app.Close()
	waitDone(t, done)
}

func TestAnyPortRuleEnablesPeek(t *testing.T) {
	m := compileHostRules([]string{"api.test:0"})
	if !m.hasExplicitPort(9443) || !m.match("api.test", 9443) {
		t.Error(":0 rule must peek and match any port")
	}
	if compileHostRules([]string{"-api.test:0"}).hasExplicitPort(9443) {
		t.Error("exclusions must not widen peeking")
	}
}

func TestRecorderStopDrainsQueuedWrites(t *testing.T) {
	dir := t.TempDir()
	r, err := newRecorder(dir, "s", "n", 1<<20, 0, "direct")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("b"), 64<<10)
	for i := 0; i < 8; i++ {
		r.appendFile("bodies/x.res", payload, true)
	}
	r.close("stop", "user")
	b, _ := os.ReadFile(filepath.Join(dir, "bodies/x.res"))
	if len(b) != 8*len(payload) {
		t.Errorf("drained %d bytes, want %d", len(b), 8*len(payload))
	}
	r2, _ := newRecorder(dir, "s", "n2", 1<<20, 0, "direct")
	defer r2.close("stop", "user")
	if r2.written.Load() < int64(len(b)) {
		t.Errorf("resumed usage %d ignores existing bodies (%d)", r2.written.Load(), len(b))
	}
}

func TestStopFinishesPendingTransactions(t *testing.T) {
	dir := t.TempDir()
	r, err := newRecorder(dir, "s", "n", 1<<20, 0, "direct")
	if err != nil {
		t.Fatal(err)
	}
	sink := r.newBodySink("n-1", "res")
	_, _ = sink.Write([]byte("partial body"))
	r.markWebSocket("n-2")
	done := r.newBodySink("n-3", "res")
	_, _ = done.Write([]byte("x"))
	endTx(r, "n-3", nil, done, "", false, "")
	r.close("stop", "user")

	ends := eventsOf(readEvents(t, dir), "txEnd")
	byID := map[string]map[string]any{}
	for _, e := range ends {
		byID[e["id"].(string)] = e
	}
	if len(ends) != 3 {
		t.Fatalf("txEnd events = %v", ends)
	}
	if e := byID["n-1"]; e["resBodyFile"] != "bodies/n-1.res" || e["resTruncated"] != true {
		t.Errorf("pending body not finalized: %v", e)
	}
	if byID["n-2"]["ws"] != true {
		t.Errorf("pending WebSocket flag lost: %v", byID["n-2"])
	}
}

func TestCompletionAndShutdownWriteOneTxEnd(t *testing.T) {
	for i := 0; i < 200; i++ {
		dir := t.TempDir()
		r, err := newRecorder(dir, "s", "n", 1<<20, 0, "direct")
		if err != nil {
			t.Fatal(err)
		}
		sink := r.newBodySink("n-1", "res")
		_, _ = sink.Write([]byte("body"))
		done := make(chan struct{})
		go func() { endTx(r, "n-1", nil, sink, "", false, ""); close(done) }()
		r.close("stop", "user")
		<-done
		if ends := eventsOf(readEvents(t, dir), "txEnd"); len(ends) != 1 {
			t.Fatalf("iteration %d: %d txEnd events", i, len(ends))
		}
	}
}

func TestRewriteRulesFollowLiveConfig(t *testing.T) {
	testCapture(t, func(c *captureConfig) {
		c.RewriteRules = []rewriteRule{{ID: "r", Enabled: true, Match: "*", Phase: "request", Action: "addHeader", Header: "X-A", Value: "1"}}
	})
	if len(liveRewrites().matching("request", "https://x.test/")) != 1 {
		t.Fatal("rule not live")
	}
	b, _ := json.Marshal(captureConfig{})
	if err := CaptureConfigure(string(b)); err != nil {
		t.Fatal(err)
	}
	if liveRewrites() != nil {
		t.Error("rewrites must stop with capture")
	}
}

func TestRecorderAutoStopsAtSizeLimit(t *testing.T) {
	dir := t.TempDir()
	r, err := newRecorder(dir, "s", "n", 1<<20, 1000, "direct")
	if err != nil {
		t.Fatal(err)
	}
	r.appendFile("bodies/x.res", bytes.Repeat([]byte("a"), 2000), true)
	deadline := time.Now().Add(2 * time.Second)
	for r.isActive() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.isActive() || r.stopReasonString() != "sizeLimit" {
		t.Fatalf("active=%v reason=%q", r.isActive(), r.stopReasonString())
	}
	r.close("stop", "user")
	evs := readEvents(t, dir)
	if stops := eventsOf(evs, "stop"); len(stops) != 1 || stops[0]["reason"] != "sizeLimit" {
		t.Errorf("stops = %v", stops)
	}
}
