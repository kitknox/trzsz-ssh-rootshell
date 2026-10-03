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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Tailscale mode sends each packet from the TUN to one of two places:
//
//   - the WireGuard engine (tailnetBackend), raw, for tailnet addresses;
//   - our gVisor netstack, created on first use, for flows that leave through
//     the SSH host or (in full-tunnel mode) a direct rule.
//
// DNS to 100.100.100.100 is looked at first: names with an SSH rule get a fake
// address so the SSH host resolves them, and the rest go to Tailscale's
// resolver or an upstream server.

var (
	quad100   = netip.MustParseAddr("100.100.100.100")
	quad100v6 = netip.MustParseAddr("fd7a:115c:a1e0::53")
)

const (
	tailnetMTU         = 1280
	tailnetOutQueue    = 256
	tailnetDNSInFlight = 64
	dnsUpstreamTimeout = 4 * time.Second
	fakeIPTTL          = 1
	directIPMemory     = 4096
)

var errTailnetClosed = errors.New("vpntunnel: tailnet path closed")

// tailnetBackend is the WireGuard side of Tailscale mode.
type tailnetBackend interface {
	// deliver hands a device-originated packet to Tailscale. The slice is
	// owned by the callee.
	deliver(pkt []byte)
}

// tailnetNetState is what Tailscale asked the OS for: its router and DNS
// configuration.
type tailnetNetState struct {
	addrs      []netip.Prefix
	routes     []netip.Prefix
	dnsServers []netip.Addr
	match      []string // lower case, no trailing dot
	search     []string
	allDomains bool // tailnet DNS takes every query ("override local DNS")
}

func (s *tailnetNetState) routesContain(ip netip.Addr) bool {
	if s == nil {
		return false
	}
	ip = ip.Unmap()
	for _, p := range s.routes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *tailnetNetState) isTailnetName(name string) bool {
	if s == nil {
		return false
	}
	for _, d := range s.match {
		if d == "" || name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

type tailnetPath struct {
	cfg       *VPNTunnelConfig
	stats     *tunnelStats
	table     *routeTable
	fake      *fakeIPPool
	directIPs *recentIPs
	socks     *socks5Dialer // nil without an SSH egress host
	direct    *directDialer
	upstream  []string // host:53 servers for names Tailscale doesn't own

	out     chan packetEntry
	backend atomic.Pointer[backendBox]
	state   atomic.Pointer[tailnetNetState]
	dnsSem  chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc

	// Our own queries to Tailscale's resolver, keyed by source port.
	probeMu   sync.Mutex
	probes    map[uint16]dnsProbe
	probeNext uint16

	// HTTP capture. Both flags stay false while it's off, so the packet
	// path pays one atomic load; capturing routes everything through the
	// netstack, the way the SSH VPN always runs.
	capturing atomic.Bool
	servesCA  atomic.Bool
	// Set by the engine before packets flow.
	onCaptureChange func(capturing bool)
	tailnetDial     func(ctx context.Context, dst netip.AddrPort) (net.Conn, error)

	stackMu   sync.Mutex
	stack     *tunnelStack
	stackErr  error
	unrouted  atomic.Int64
	dnsFake   atomic.Int64
	dnsFwd    atomic.Int64
	dnsFailed atomic.Int64
}

func newTailnetPath(cfg *VPNTunnelConfig, routing routingConfigJSON, stats *tunnelStats) *tailnetPath {
	ctx, cancel := context.WithCancel(context.Background())
	p := &tailnetPath{
		cfg:       cfg,
		stats:     stats,
		fake:      newFakeIPPool(),
		directIPs: newRecentIPs(directIPMemory),
		direct:    &directDialer{boundIf: cfg.DirectBoundInterface},
		out:       make(chan packetEntry, tailnetOutQueue),
		dnsSem:    make(chan struct{}, tailnetDNSInFlight),
		probes:    make(map[uint16]dnsProbe),
		ctx:       ctx,
		cancel:    cancel,
	}
	if cfg.SOCKS5Address != "" {
		p.socks = &socks5Dialer{proxyAddr: cfg.SOCKS5Address}
	}
	p.table = compileRouteTable(routing, p.socks != nil)
	for _, s := range cfg.DNSServers {
		if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
			p.upstream = append(p.upstream, netip.AddrPortFrom(a, 53).String())
		}
	}
	if len(p.upstream) == 0 {
		p.upstream = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	return p
}

type backendBox struct{ b tailnetBackend }

func (p *tailnetPath) setState(s *tailnetNetState) { p.state.Store(s) }

func (p *tailnetPath) setBackend(b tailnetBackend) {
	if b == nil {
		p.backend.Store(nil)
		return
	}
	p.backend.Store(&backendBox{b: b})
}

// toTailscale hands a copy of pkt to WireGuard, if it is running.
func (p *tailnetPath) toTailscale(pkt []byte) {
	if box := p.backend.Load(); box != nil {
		box.b.deliver(append([]byte(nil), pkt...))
	}
}

// emit queues an outbound packet for the provider; drops it once closed.
func (p *tailnetPath) emit(pkt []byte) {
	if p.claimProbeReply(pkt) {
		return
	}
	if p.capturing.Load() {
		observeQuad100Reply(pkt)
	}
	family := 2
	if len(pkt) > 0 && pkt[0]>>4 == 6 {
		family = 30
	}
	p.stats.addBytesIn(len(pkt))
	select {
	case p.out <- packetEntry{data: pkt, family: family}:
	case <-p.ctx.Done():
	}
}

func (p *tailnetPath) injectPacket(data []byte, family int) {
	info, ok := parseIPPacket(data)
	if !ok {
		return
	}
	st := p.state.Load()
	if info.proto == ipProtoUDP && info.dstPort == 53 && (info.dst == quad100 || info.dst == quad100v6) {
		p.stats.addBytesOut(len(data))
		p.handleDNS(info, data, st)
		return
	}
	// TCP DNS gets the same rules: our stack terminates it (routedDialer).
	// Without SSH egress no rule changes an answer, so Tailscale keeps it.
	if p.socks != nil && info.proto == ipProtoTCP && info.dstPort == 53 && info.dst == quad100 {
		if ts := p.ensureStack(); ts != nil {
			ts.injectPacket(data, family)
		}
		return
	}
	if p.toStack(info.dst, st) || p.captureToStack(info, st) {
		if ts := p.ensureStack(); ts != nil {
			ts.injectPacket(data, family) // counts its own bytes
		}
		return
	}
	if st.routesContain(info.dst) {
		p.stats.addBytesOut(len(data))
		p.toTailscale(data)
		return
	}
	p.unrouted.Add(1)
}

// toStack reports whether dst is terminated locally and re-dialed over SSH
// or a direct socket. Fake addresses and SSH CIDR rules win over tailnet
// routes; everything else on a tailnet route stays raw.
func (p *tailnetPath) toStack(dst netip.Addr, st *tailnetNetState) bool {
	dst = dst.Unmap()
	if p.socks != nil && fakeIPPrefix.Contains(dst) {
		return true
	}
	switch p.table.matchIP(dst) {
	case routeSSH:
		return true
	case routeDirect:
		return !st.routesContain(dst)
	}
	if st.routesContain(dst) {
		return false
	}
	return p.table.sendAllViaSSH && dst.Is4()
}

var caEndpointAddr = netip.MustParseAddr(caEndpointIP)

// captureToStack picks what HTTP capture terminates: the CA endpoint, and
// while recording, tailnet TCP (re-dialed through Tailscale) and everything
// off the tailnet.
func (p *tailnetPath) captureToStack(info ipPacketInfo, st *tailnetNetState) bool {
	if info.dst == caEndpointAddr && info.proto == ipProtoTCP && info.dstPort == 80 && p.servesCA.Load() {
		return true
	}
	if !p.capturing.Load() {
		return false
	}
	if st.routesContain(info.dst) {
		return info.proto == ipProtoTCP
	}
	return true
}

// refreshCapture follows capture state changes (captureRoutingHook).
func (p *tailnetPath) refreshCapture() {
	capturing := captureBlocking()
	p.servesCA.Store(captureServesCA())
	if was := p.capturing.Swap(capturing); was && !capturing && p.socks == nil {
		// Tailscale only: nothing else uses the netstack.
		p.retireStack()
	}
	if p.onCaptureChange != nil {
		p.onCaptureChange(capturing)
	}
}

// retireStack frees the netstack. The close waits briefly so a packet being
// injected on another goroutine finishes first.
func (p *tailnetPath) retireStack() {
	p.stackMu.Lock()
	ts := p.stack
	p.stack = nil
	p.stackMu.Unlock()
	if ts == nil {
		return
	}
	if env := currentCaptureEnv(); env != nil {
		env.udp.CompareAndSwap(ts.udpFwd, nil)
	}
	go func() {
		time.Sleep(2 * time.Second)
		ts.close()
		log.Printf("vpntunnel: tailnet netstack retired")
	}()
}

// observeQuad100Reply feeds DNS answers to capture's hostname labels.
func observeQuad100Reply(pkt []byte) {
	if len(pkt) < 30 || pkt[0]>>4 != 4 || pkt[9] != ipProtoUDP || [4]byte(pkt[12:16]) != quad100.As4() {
		return
	}
	if info, ok := parseIPPacket(pkt); ok && info.srcPort == 53 {
		observeDNSResponse(info.udpPayload())
	}
}

func (p *tailnetPath) ensureStack() *tunnelStack {
	p.stackMu.Lock()
	defer p.stackMu.Unlock()
	if p.stack != nil || p.stackErr != nil {
		return p.stack
	}
	if p.ctx.Err() != nil {
		return nil
	}
	stackCfg := *p.cfg
	stackCfg.MTU = tailnetMTU
	// SSH carries TCP only; refuse QUIC so browsers fall back at once.
	stackCfg.BlockQUIC = p.socks != nil
	d := &routedDialer{p: p}
	ts, err := newTunnelStackWithOutput(&stackCfg, d, d, p.stats, 0, p.out)
	if err != nil {
		p.stackErr = err
		log.Printf("vpntunnel: tailnet netstack: %v", err)
		return nil
	}
	ts.udpFwd.dnsViaTCP = p.table.sendAllViaSSH
	if env := currentCaptureEnv(); env != nil {
		env.udp.Store(ts.udpFwd) // so capture can reset QUIC flows
	}
	p.stack = ts
	log.Printf("vpntunnel: tailnet netstack started")
	return ts
}

func (p *tailnetPath) readPacket() ([]byte, int) {
	select {
	case e := <-p.out:
		return e.data, e.family
	case <-p.ctx.Done():
		return nil, 0
	}
}

func (p *tailnetPath) readPacketNonBlocking() ([]byte, int) {
	select {
	case e := <-p.out:
		return e.data, e.family
	default:
		return nil, 0
	}
}

func (p *tailnetPath) close() {
	p.cancel()
	p.stackMu.Lock()
	ts := p.stack
	p.stack = nil
	p.stackMu.Unlock()
	if ts != nil {
		ts.close()
	}
}

// handleDNS answers or forwards one query sent to 100.100.100.100.
func (p *tailnetPath) handleDNS(info ipPacketInfo, pkt []byte, st *tailnetNetState) {
	reply := func(msg []byte) {
		if msg == nil {
			return
		}
		src := netip.AddrPortFrom(info.dst, info.dstPort)
		dst := netip.AddrPortFrom(info.src, info.srcPort)
		p.emit(buildUDPPacket(src, dst, msg))
	}
	if p.capturing.Load() {
		// No ECH keys while recording, as in the other capture paths.
		if answer := interceptDNSQuery(info.udpPayload()); answer != nil {
			reply(answer)
			return
		}
	}
	q, ok := parseDNSQuery(info.udpPayload())
	route, remember := p.dnsRoute(q, ok, st)
	switch route {
	case dnsToTailscale:
		p.toTailscale(pkt)
	case dnsFakeAnswer:
		reply(p.fakeAnswer(q))
	case dnsViaSSH:
		p.forwardDNS(q, info, reply, true, false)
	default:
		p.forwardDNS(q, info, reply, false, remember)
	}
}

// dnsDestination is where a query to 100.100.100.100 is answered.
type dnsDestination int

const (
	dnsToTailscale dnsDestination = iota
	dnsFakeAnswer                 // SSH rule: resolved on the SSH host later
	dnsViaSSH
	dnsDirect
)

// dnsRoute applies the routing rules to one query, for UDP and TCP alike.
// remember reports whether answers become direct destinations.
func (p *tailnetPath) dnsRoute(q dnsQuestion, ok bool, st *tailnetNetState) (dnsDestination, bool) {
	if !ok || st.isTailnetName(q.name) {
		return dnsToTailscale, false
	}
	switch p.table.matchHost(q.name) {
	case routeSSH:
		return dnsFakeAnswer, false
	case routeDirect:
		return dnsDirect, p.table.sendAllViaSSH
	}
	switch {
	case st != nil && st.allDomains:
		// The tailnet set global resolvers; they also own split-DNS routes
		// Tailscale doesn't expose, so they win over the SSH fallback.
		return dnsToTailscale, false
	case p.table.sendAllViaSSH:
		return dnsViaSSH, false
	default:
		return dnsDirect, false
	}
}

func (p *tailnetPath) fakeAnswer(q dnsQuestion) []byte {
	p.dnsFake.Add(1)
	if q.q.Type != dnsmessage.TypeA {
		// No AAAA: SSH egress is IPv4-only, and an empty answer keeps
		// clients on the fake A record.
		return dnsAnswer(q, dnsmessage.RCodeSuccess, nil, fakeIPTTL)
	}
	a := p.fake.assign(q.name)
	return dnsAnswer(q, dnsmessage.RCodeSuccess, &a, fakeIPTTL)
}

// resolveDNS answers one query synchronously (the TCP path).
func (p *tailnetPath) resolveDNS(ctx context.Context, query []byte) []byte {
	if p.capturing.Load() {
		if answer := interceptDNSQuery(query); answer != nil {
			return answer
		}
	}
	q, ok := parseDNSQuery(query)
	route, remember := p.dnsRoute(q, ok, p.state.Load())
	var resp []byte
	var err error
	switch route {
	case dnsFakeAnswer:
		return p.fakeAnswer(q)
	case dnsToTailscale:
		resp, err = p.exchangeTailscale(ctx, query)
	default:
		p.dnsFwd.Add(1)
		resp, err = p.exchangeDNS(ctx, query, route == dnsViaSSH)
		if err == nil && remember {
			for _, a := range dnsAnswerAddrs(resp) {
				p.directIPs.add(a)
			}
		}
	}
	if err != nil {
		p.dnsFailed.Add(1)
		if !ok {
			return nil
		}
		return dnsAnswer(q, dnsmessage.RCodeServerFailure, nil, 0)
	}
	return resp
}

// Our own queries to 100.100.100.100 leave from these ports, below iOS's
// ephemeral range so client queries never collide with them.
const (
	probePortBase  = 40000
	probePortCount = 1000
)

type dnsProbe struct {
	id    uint16
	reply chan []byte
}

// exchangeTailscale asks Tailscale's resolver over UDP from the node's
// address; claimProbeReply hands the answer back.
func (p *tailnetPath) exchangeTailscale(ctx context.Context, query []byte) ([]byte, error) {
	var src netip.Addr
	if st := p.state.Load(); st != nil {
		for _, a := range st.addrs {
			if a.Addr().Is4() {
				src = a.Addr()
				break
			}
		}
	}
	if !src.IsValid() || len(query) < 2 {
		return nil, errors.New("vpntunnel: no tailnet address for DNS")
	}
	probe := dnsProbe{id: binary.BigEndian.Uint16(query), reply: make(chan []byte, 1)}
	p.probeMu.Lock()
	var port uint16
	for range probePortCount {
		candidate := probePortBase + p.probeNext%probePortCount
		p.probeNext++
		if _, busy := p.probes[candidate]; !busy {
			port = candidate
			break
		}
	}
	if port != 0 {
		p.probes[port] = probe
	}
	p.probeMu.Unlock()
	if port == 0 {
		return nil, errors.New("vpntunnel: too many DNS queries in flight")
	}
	defer func() {
		p.probeMu.Lock()
		delete(p.probes, port)
		p.probeMu.Unlock()
	}()

	p.toTailscale(buildUDPPacket(netip.AddrPortFrom(src, port), netip.AddrPortFrom(quad100, 53), query))
	select {
	case resp := <-probe.reply:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// claimProbeReply takes Tailscale's answer to one of our own queries out of
// the outbound stream.
func (p *tailnetPath) claimProbeReply(pkt []byte) bool {
	if len(pkt) < 30 || pkt[0]>>4 != 4 || pkt[9] != ipProtoUDP || [4]byte(pkt[12:16]) != quad100.As4() {
		return false
	}
	info, ok := parseIPPacket(pkt)
	payload := info.udpPayload()
	if !ok || info.srcPort != 53 || len(payload) < 2 {
		return false
	}
	p.probeMu.Lock()
	probe, found := p.probes[info.dstPort]
	if found && probe.id == binary.BigEndian.Uint16(payload) {
		delete(p.probes, info.dstPort)
	} else {
		found = false
	}
	p.probeMu.Unlock()
	if !found {
		return false
	}
	probe.reply <- append([]byte(nil), payload...)
	return true
}

// serveDNSOverTCP is the far end of a client's TCP connection to
// 100.100.100.100:53, answering each framed query through resolveDNS.
func (p *tailnetPath) serveDNSOverTCP() net.Conn {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		for {
			_ = server.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
			var hdr [2]byte
			if _, err := io.ReadFull(server, hdr[:]); err != nil {
				return
			}
			query := make([]byte, binary.BigEndian.Uint16(hdr[:]))
			if _, err := io.ReadFull(server, query); err != nil {
				return
			}
			ctx, cancel := context.WithTimeout(p.ctx, dnsUpstreamTimeout)
			resp := p.resolveDNS(ctx, query)
			cancel()
			if resp == nil {
				return
			}
			out := make([]byte, 2+len(resp))
			binary.BigEndian.PutUint16(out, uint16(len(resp)))
			copy(out[2:], resp)
			_ = server.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := server.Write(out); err != nil {
				return
			}
		}
	}()
	return client
}

// forwardDNS resolves q upstream, over SSH or a direct socket, off the
// packet path. remember records the answers as direct destinations.
func (p *tailnetPath) forwardDNS(q dnsQuestion, info ipPacketInfo, reply func([]byte), viaSSH, remember bool) {
	select {
	case p.dnsSem <- struct{}{}:
	default:
		p.dnsFailed.Add(1)
		return // the client retries
	}
	query := append([]byte(nil), info.udpPayload()...)
	p.dnsFwd.Add(1)
	go func() {
		defer func() { <-p.dnsSem }()
		ctx, cancel := context.WithTimeout(p.ctx, dnsUpstreamTimeout)
		defer cancel()
		resp, err := p.exchangeDNS(ctx, query, viaSSH)
		if err != nil {
			p.dnsFailed.Add(1)
			reply(dnsAnswer(q, dnsmessage.RCodeServerFailure, nil, 0))
			return
		}
		if remember {
			for _, a := range dnsAnswerAddrs(resp) {
				p.directIPs.add(a)
			}
		}
		reply(resp)
	}()
}

func (p *tailnetPath) exchangeDNS(ctx context.Context, query []byte, viaSSH bool) ([]byte, error) {
	var lastErr error
	for _, server := range p.upstream {
		var resp []byte
		var err error
		if viaSSH {
			resp, err = dnsExchangeTCP(ctx, p.socks, server, query)
		} else {
			resp, err = dnsExchangeUDP(ctx, p.direct, server, query)
		}
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func dnsExchangeUDP(ctx context.Context, d udpDialer, server string, query []byte) ([]byte, error) {
	c, err := d.DialUDP(ctx, server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	_ = c.SetReadDeadline(deadline)
	_ = c.SetWriteDeadline(deadline)
	if err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, udpBufferSize)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		// Ignore stray datagrams with a different transaction ID.
		if n >= 2 && len(query) >= 2 && buf[0] == query[0] && buf[1] == query[1] {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

// routedDialer picks the egress for each flow our netstack terminates.
type routedDialer struct {
	p *tailnetPath
}

func (d *routedDialer) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, err
	}
	p := d.p
	if ip == quad100 && port == "53" {
		return p.serveDNSOverTCP(), nil
	}
	if name, ok := p.fake.host(ip); ok {
		if p.socks == nil {
			return nil, fmt.Errorf("no SSH egress for %s", name)
		}
		return p.socks.DialTCP(ctx, net.JoinHostPort(name, port))
	}
	switch p.egressFor(ip) {
	case egressSSH:
		return p.socks.DialTCP(ctx, addr)
	case egressTailnet:
		portNum, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, err
		}
		return p.tailnetDial(ctx, netip.AddrPortFrom(ip, uint16(portNum)))
	}
	return p.direct.DialTCP(ctx, addr)
}

func (d *routedDialer) DialUDP(ctx context.Context, addr string) (udpConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, err
	}
	// Tailnet UDP never reaches the netstack; SSH carries only TCP.
	if _, ok := d.p.fake.host(ip); ok || d.p.egressFor(ip) != egressDirect {
		return nil, fmt.Errorf("no UDP over SSH to %s", addr)
	}
	return d.p.direct.DialUDP(ctx, addr)
}

// dialsIPv6 lets IPv6 flows through unless they'd need SSH.
func (d *routedDialer) dialsIPv6(host string) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	if _, fake := d.p.fake.host(ip); fake {
		return false
	}
	return d.p.egressFor(ip) != egressSSH
}

type egressKind int

const (
	egressDirect egressKind = iota
	egressSSH
	egressTailnet // capture re-dials tailnet flows through Tailscale
)

// egressFor picks where a flow our netstack terminated goes: an SSH rule
// first, then the tailnet, then the default.
func (p *tailnetPath) egressFor(ip netip.Addr) egressKind {
	if p.socks != nil && p.table.matchIP(ip) == routeSSH {
		return egressSSH
	}
	if p.tailnetDial != nil && p.state.Load().routesContain(ip) {
		return egressTailnet
	}
	if p.viaSSH(ip) {
		return egressSSH
	}
	return egressDirect
}

func (p *tailnetPath) viaSSH(ip netip.Addr) bool {
	if p.socks == nil {
		return false
	}
	switch p.table.matchIP(ip) {
	case routeSSH:
		return true
	case routeDirect:
		return false
	}
	return p.table.sendAllViaSSH && !p.directIPs.contains(ip)
}

// tunnelNetworkSettings is the NEPacketTunnelNetworkSettings shape Swift
// applies. Swift adds the SSH server exclusion itself.
type tunnelNetworkSettings struct {
	IPv4Addresses []string `json:"ipv4Addresses"`
	IPv4Routes    []string `json:"ipv4Routes"`
	IPv4Excluded  []string `json:"ipv4Excluded,omitempty"`
	IPv6Addresses []string `json:"ipv6Addresses,omitempty"`
	IPv6Routes    []string `json:"ipv6Routes,omitempty"`
	DNSServers    []string `json:"dnsServers,omitempty"`
	MatchDomains  []string `json:"matchDomains,omitempty"` // [""] = every query
	SearchDomains []string `json:"searchDomains,omitempty"`
	FullTunnel    bool     `json:"fullTunnel"`
	MTU           int      `json:"mtu"`
}

// placeholderTunnelAddr keeps the interface configured before login, when
// Tailscale has no address yet.
const placeholderTunnelAddr = "10.0.0.2"

func (p *tailnetPath) networkSettings() tunnelNetworkSettings {
	st := p.state.Load()
	s := tunnelNetworkSettings{MTU: tailnetMTU, FullTunnel: p.table.sendAllViaSSH}
	add := func(dst *[]string, v string) {
		if !slices.Contains(*dst, v) {
			*dst = append(*dst, v)
		}
	}
	addRoute := func(pfx netip.Prefix) {
		if pfx.Addr().Is4() {
			add(&s.IPv4Routes, pfx.String())
		} else {
			add(&s.IPv6Routes, pfx.String())
		}
	}
	if st != nil {
		for _, a := range st.addrs {
			if a.Addr().Is4() {
				add(&s.IPv4Addresses, a.Addr().String())
			} else {
				add(&s.IPv6Addresses, a.Addr().String())
			}
		}
		for _, r := range st.routes {
			addRoute(r)
		}
	}
	if len(s.IPv4Addresses) == 0 {
		s.IPv4Addresses = []string{placeholderTunnelAddr}
	}
	if st == nil || len(st.addrs) == 0 {
		// Not logged in: nothing to route or resolve yet.
		s.IPv4Routes, s.IPv6Routes, s.FullTunnel = nil, nil, false
		return s
	}

	sshHosts := p.table.dnsDomains(routeSSH)
	if p.socks != nil {
		for _, pfx := range p.table.prefixes(routeSSH) {
			addRoute(pfx)
		}
		if len(sshHosts) > 0 {
			addRoute(fakeIPPrefix)
		}
	}
	if s.FullTunnel {
		s.IPv4Routes = []string{"0.0.0.0/0"}
		for _, pfx := range p.table.directExclusions() {
			// Tailnet routes win over direct rules (see toStack), so never
			// exclude a prefix that overlaps one; Go sorts those packets.
			if pfx.Addr().Is4() && !slices.ContainsFunc(st.routes, pfx.Overlaps) {
				add(&s.IPv4Excluded, pfx.String())
			}
		}
	}
	if p.servesCA.Load() {
		addRoute(netip.PrefixFrom(caEndpointAddr, 32))
	}
	capturing := p.capturing.Load()
	if capturing {
		// Recording: everything enters the tunnel so the engine sees it,
		// direct rules included (Go dials those out directly).
		s.IPv4Routes = []string{"0.0.0.0/0"}
		s.IPv4Excluded = nil
		if len(s.IPv6Addresses) > 0 {
			s.IPv6Routes = []string{"::/0"}
		}
	}

	// DNS: we must see tailnet names, SSH-rule names, and in full-tunnel
	// mode or while recording, everything.
	match := append([]string(nil), st.match...)
	for _, d := range sshHosts {
		if !slices.Contains(match, d) {
			match = append(match, d)
		}
	}
	if s.FullTunnel || capturing || st.allDomains || slices.Contains(match, "") {
		match = []string{""}
	}
	if len(match) > 0 {
		s.DNSServers = []string{quad100.String()}
		s.MatchDomains = match
		s.SearchDomains = append([]string(nil), st.search...)
	}
	return s
}

// tailnetStats is the Tailscale part of GetStatus.
type tailnetStats struct {
	Unrouted  int64 `json:"unrouted"`
	DNSFake   int64 `json:"dnsFake"`
	DNSFwd    int64 `json:"dnsForwarded"`
	DNSFailed int64 `json:"dnsFailed"`
	Netstack  bool  `json:"netstack"`
}

func (p *tailnetPath) statsSnapshot() tailnetStats {
	p.stackMu.Lock()
	hasStack := p.stack != nil
	p.stackMu.Unlock()
	return tailnetStats{
		Unrouted:  p.unrouted.Load(),
		DNSFake:   p.dnsFake.Load(),
		DNSFwd:    p.dnsFwd.Load(),
		DNSFailed: p.dnsFailed.Load(),
		Netstack:  hasStack,
	}
}
