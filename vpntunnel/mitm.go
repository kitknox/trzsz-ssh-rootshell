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
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	peekTimeout      = 300 * time.Millisecond
	handshakeTimeout = 15 * time.Second
	caEndpointIP     = "10.0.0.1" // tunnel gateway; serves the capture CA over plain HTTP
)

var errPassthrough = errors.New("capture: passthrough")

// flowCtx describes one TCP flow handed to the capture layer.
type flowCtx struct {
	ctx     context.Context
	cs      *captureState
	env     *captureEnv
	client  net.Conn // netstack side
	dstIP   string
	dstPort int
	dstAddr string
	srcAddr string
	start   time.Time
	dial    func(ctx context.Context) (net.Conn, error)
}

func (fc *flowCtx) rec() *recorder {
	if fc.cs.recording() {
		return fc.cs.rec
	}
	return nil
}

// connMeta is per-connection context shared by every transaction on it.
type connMeta struct {
	connID      string
	scheme      string
	client      string
	server      string
	sni         string
	tlsVersion  string
	alpn        string
	connectMs   float64
	tlsMs       float64
	defaultHost string
	served      int
}

// shouldPeek reports whether a flow's first bytes are worth inspecting.
// Server-speaks-first protocols on other ports are never delayed.
func shouldPeek(cs *captureState, dstIP string, port int) bool {
	if dstIP == caEndpointIP && port == 80 {
		return cs.caProfile != nil || cs.minter != nil
	}
	if !cs.cfg.Enabled || !cs.rec.isActive() {
		return false
	}
	switch port {
	case 80, 443, 8080, 8443:
		return true
	}
	return cs.hosts.hasExplicitPort(port)
}

// serveCapturedFlow classifies and serves one peekable flow. It owns client.
func serveCapturedFlow(fc *flowCtx) {
	defer fc.client.Close()
	if fc.dstIP == caEndpointIP && fc.dstPort == 80 {
		serveCAEndpoint(fc)
		return
	}
	pc := newPeekConn(fc.client)
	first, err := pc.peek(1, time.Now().Add(peekTimeout))
	if len(first) == 0 {
		if err != nil && isTimeout(err) {
			relayPeeked(fc, pc, "notHTTP", "", "", nil)
		}
		return
	}
	switch {
	case first[0] == 0x16:
		serveTLS(fc, pc)
	case looksLikeHTTP(pc):
		meta := &connMeta{
			scheme:      "http",
			client:      fc.srcAddr,
			server:      fc.dstAddr,
			defaultHost: hostForURL(fc.env.dns.lookup(fc.dstIP), fc.dstIP, fc.dstPort, 80),
		}
		meta.connID = fc.rec().nextConnID()
		serveHTTP1(fc, pc, nil, meta)
	default:
		relayPeeked(fc, pc, "notHTTP", "", "", nil)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

var httpMethodPrefixes = []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "}

func looksLikeHTTP(pc *peekConn) bool {
	b, _ := pc.peek(8, time.Now().Add(peekTimeout))
	s := string(b)
	for _, m := range httpMethodPrefixes {
		if strings.HasPrefix(m, s) || strings.HasPrefix(s, m) {
			return len(s) >= 3
		}
	}
	return false
}

// hostForURL builds the authority shown in URLs, omitting default ports.
func hostForURL(name, ip string, port, defaultPort int) string {
	h := name
	if h == "" {
		h = ip
		if strings.Contains(h, ":") {
			h = "[" + h + "]"
		}
	}
	if port != defaultPort {
		h += ":" + strconv.Itoa(port)
	}
	return h
}

// relayPeeked forwards a flow untouched (after replaying peeked bytes) and
// records it as a tunnel row.
func relayPeeked(fc *flowCtx, pc *peekConn, reason, sni, alpn string, upstream net.Conn) {
	rec := fc.rec()
	start := nowMs()
	var err error
	if upstream == nil {
		upstream, err = fc.dial(fc.ctx)
	}
	var up, down int64
	if err == nil {
		client := newIdleConn(pc, tcpIdleTimeout)
		up, down = relayConns(fc.ctx, client, pc, newIdleConn(upstream, tcpIdleTimeout))
	}
	if rec != nil {
		ev := evTunnel{
			T: "tunnel", ID: rec.nextTxID(), TS: nowMs(), Start: start,
			Client: fc.srcAddr, Server: fc.dstAddr, Host: fc.env.dns.lookup(fc.dstIP),
			SNI: sni, ALPN: alpn, Reason: reason, BytesUp: up, BytesDown: down,
		}
		if err != nil {
			ev.Error = err.Error()
		}
		rec.tunnelCount.Add(1)
		rec.event(ev)
	}
}

// recordRawTunnel logs a flow that bypassed inspection entirely (port not peeked).
func recordRawTunnel(cs *captureState, env *captureEnv, srcIP string, srcPort uint16, dstIP, dstAddr string, start float64, up, down int64, err error) {
	if !cs.recording() || env == nil {
		return
	}
	rec := cs.rec
	ev := evTunnel{
		T: "tunnel", ID: rec.nextTxID(), TS: nowMs(), Start: start,
		Client: net.JoinHostPort(srcIP, strconv.Itoa(int(srcPort))), Server: dstAddr,
		Host: env.dns.lookup(dstIP), Reason: "notInspected", BytesUp: up, BytesDown: down,
	}
	if err != nil {
		ev.Error = err.Error()
	}
	rec.tunnelCount.Add(1)
	rec.event(ev)
}

// tlsDecision is filled in by GetConfigForClient.
type tlsDecision struct {
	mu       sync.Mutex
	pass     string // passthrough reason; "" = intercept
	sni      string
	host     string
	upstream *tls.Conn
	raw      net.Conn // pre-dialed upstream kept for passthrough after an upstream TLS failure
	meta     *connMeta
	held     bool // holds a MITM slot
}

func serveTLS(fc *flowCtx, pc *peekConn) {
	cs, env := fc.cs, fc.env
	rec := fc.rec()
	d := &tlsDecision{}
	pc.startRecording()

	srvCfg := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			cfg, pass := decideTLS(fc, hello, d)
			if pass != "" {
				d.pass = pass
				pc.discardWrites.Store(true)
				return nil, errPassthrough
			}
			return cfg, nil
		},
	}
	tconn := tls.Server(pc, srvCfg)
	hsCtx, cancel := context.WithTimeout(fc.ctx, handshakeTimeout)
	err := tconn.HandshakeContext(hsCtx)
	cancel()
	pc.recording = false
	defer func() {
		if d.held {
			<-cs.mitmSem
			env.mitmLive.Add(-1)
		}
	}()

	if d.pass != "" {
		relayPeeked(fc, pc.replay(), d.pass, d.sni, "", d.raw)
		return
	}
	if err != nil {
		if d.upstream != nil {
			_ = d.upstream.Close()
		}
		if d.meta == nil {
			// Never reached the decision (garbage, timeout): nothing to report.
			return
		}
		detail := err.Error()
		if isCertRejection(detail) {
			bypassed := false
			if cs.cfg.AutoBypassPinned {
				env.bypass.Store(d.host, struct{}{})
				bypassed = true
			}
			if rec != nil {
				rec.rejected.Add(1)
				rec.event(evTLSRejected{T: "tlsRejected", ID: rec.nextTxID(), TS: nowMs(),
					Host: d.host, Server: fc.dstAddr, Detail: detail, Bypassed: bypassed})
			}
		}
		return
	}

	st := tconn.ConnectionState()
	meta := d.meta
	meta.tlsVersion = tls.VersionName(st.Version)
	meta.alpn = st.NegotiatedProtocol
	if st.NegotiatedProtocol == "h2" {
		serveHTTP2(fc, tconn, d.upstream, meta)
	} else {
		serveHTTP1(fc, tconn, d.upstream, meta)
	}
	if meta.served == 0 {
		if env.noteEmptyMITM(d.host) {
			bypassed := false
			if cs.cfg.AutoBypassPinned {
				env.bypass.Store(d.host, struct{}{})
				bypassed = true
			}
			if rec != nil {
				rec.rejected.Add(1)
				rec.event(evTLSRejected{T: "tlsRejected", ID: rec.nextTxID(), TS: nowMs(),
					Host: d.host, Server: fc.dstAddr, Detail: "closed after handshake without a request", Bypassed: bypassed})
			}
		}
	} else {
		env.noteServedMITM(d.host)
	}
}

// isCertRejection matches the alerts a client sends when it distrusts our leaf.
func isCertRejection(msg string) bool {
	if !strings.Contains(msg, "remote error") {
		return false
	}
	for _, s := range []string{"bad certificate", "unknown certificate authority", "certificate unknown", "unknown certificate", "certificate required"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// decideTLS chooses interception or passthrough and, when intercepting, dials
// and handshakes upstream first so the client is offered the same ALPN.
func decideTLS(fc *flowCtx, hello *tls.ClientHelloInfo, d *tlsDecision) (*tls.Config, string) {
	cs, env := fc.cs, fc.env
	sni := strings.ToLower(hello.ServerName)
	d.sni = sni
	name := sni
	if name == "" {
		name = fc.dstIP
	}
	d.host = name

	if sni == "" && !cs.hosts.match(fc.dstIP, fc.dstPort) {
		return nil, "noSNI"
	}
	if !cs.hosts.match(name, fc.dstPort) {
		return nil, "notMatched"
	}
	if env.isBypassed(name) {
		return nil, "bypassed"
	}
	if cs.minter == nil {
		return nil, "noCA"
	}
	protos := filterALPN(hello.SupportedProtos, cs.cfg.EnableH2)
	if len(hello.SupportedProtos) > 0 && len(protos) == 0 {
		return nil, "alpn"
	}
	select {
	case cs.mitmSem <- struct{}{}:
		d.held = true
		env.mitmLive.Add(1)
	default:
		env.overflow.Add(1)
		return nil, "capacity"
	}

	rec := fc.rec()
	t0 := time.Now()
	raw, err := fc.dial(fc.ctx)
	if err != nil {
		if rec != nil {
			rec.failures.Add(1)
			rec.event(evFailure{T: "failure", ID: rec.nextTxID(), TS: nowMs(), Host: name, Server: fc.dstAddr, Stage: "upstreamDial", Error: err.Error()})
		}
		return nil, "upstreamDial"
	}
	connectMs := msSince(t0)
	var askedForClientCert bool
	upCfg := &tls.Config{
		ServerName:         sni,
		NextProtos:         protos,
		InsecureSkipVerify: cs.cfg.SkipUpstreamVerify,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			askedForClientCert = true
			return &tls.Certificate{}, nil
		},
	}
	if sni == "" {
		upCfg.ServerName = fc.dstIP
	}
	t1 := time.Now()
	up := tls.Client(raw, upCfg)
	hsCtx, cancel := context.WithTimeout(fc.ctx, handshakeTimeout)
	err = up.HandshakeContext(hsCtx)
	cancel()
	if err != nil {
		_ = raw.Close()
		stage := "upstreamTLS"
		if askedForClientCert {
			stage = "clientCertRequired"
		}
		if rec != nil {
			rec.failures.Add(1)
			rec.event(evFailure{T: "failure", ID: rec.nextTxID(), TS: nowMs(), Host: name, Server: fc.dstAddr, Stage: stage, Error: err.Error()})
		}
		// Let the client talk to the server itself; it makes its own trust call.
		return nil, stage
	}
	tlsMs := msSince(t1)

	cert, err := cs.minter.certFor(name)
	if err != nil {
		_ = up.Close()
		return nil, "mintFailed"
	}
	d.upstream = up
	d.meta = &connMeta{
		connID:      rec.nextConnID(),
		scheme:      "https",
		client:      fc.srcAddr,
		server:      fc.dstAddr,
		sni:         sni,
		connectMs:   connectMs,
		tlsMs:       tlsMs,
		defaultHost: hostForURL(name, fc.dstIP, fc.dstPort, 443),
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{*cert}}
	if alpn := up.ConnectionState().NegotiatedProtocol; alpn != "" {
		cfg.NextProtos = []string{alpn}
	}
	if rec != nil && cs.cfg.Pcap {
		cfg.KeyLogWriter = keylogWriter{r: rec}
	}
	return cfg, ""
}

func filterALPN(offered []string, h2 bool) []string {
	var out []string
	for _, p := range offered {
		if p == "http/1.1" || (p == "h2" && h2) {
			out = append(out, p)
		}
	}
	return out
}

func msSince(t time.Time) float64 { return float64(time.Since(t).Microseconds()) / 1000 }
