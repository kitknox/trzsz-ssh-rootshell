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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/trzsz/trzsz-ssh/vpntunnel/tsengine"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/ipn"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
)

const tailnetBuilt = true

// noDefaultRouteIfName never names a real interface. netmon ignores "", so
// this is how a lost network clears the stale one.
const noDefaultRouteIfName = "rootshell-none"

func tailnetDefaultInterfaceChanged(name string) {
	if name == "" {
		name = noDefaultRouteIfName
	}
	netmon.UpdateLastKnownDefaultRouteInterface(name)
	if b, ok := currentTailnetBackend().(*inAppTailnet); ok {
		b.core.NetMon.InjectEvent()
	}
}

func tailnetResetSockets() error {
	b, ok := currentTailnetBackend().(*inAppTailnet)
	if !ok {
		return nil
	}
	if err := b.core.ResetSockets(); err != nil {
		if errors.Is(err, tsengine.ErrResetStuck) {
			return errors.New(TailnetResetStuck)
		}
		return err
	}
	return nil
}

type inAppTailnet struct {
	core *tsengine.Engine
	cb   TailnetCallback
	kick chan struct{}
	ctx  context.Context
	stop context.CancelFunc

	mu       sync.Mutex
	lastEmit string

	traffic tailnetTraffic
}

func toEnginePrefs(p tailnetPrefs) tsengine.Prefs {
	return tsengine.Prefs{
		Hostname:         p.Hostname,
		AcceptRoutes:     p.AcceptRoutes,
		ExitNodeID:       p.ExitNodeID,
		ExitNodeAllowLAN: p.ExitNodeAllowLAN,
	}
}

func startTailnetBackend(conf tailnetConfig, store TailnetStateStore, cb TailnetCallback) (tailnetBackend, error) {
	t := &inAppTailnet{cb: cb, kick: make(chan struct{}, 1)}
	t.ctx, t.stop = context.WithCancel(context.Background())
	core, err := tsengine.Start(tsengine.Config{
		Logf:     tailnetLogf,
		Prefs:    toEnginePrefs(conf.tailnetPrefs),
		StateDir: conf.StateDir,
		Store:    store,
		OnChange: t.wake,
	})
	if err != nil {
		t.stop()
		return nil, err
	}
	t.core = core
	go t.emitLoop()
	t.wake()
	return t, nil
}

func (t *inAppTailnet) wake() {
	select {
	case t.kick <- struct{}{}:
	default:
	}
}

// emitLoop coalesces changes and calls Swift off Tailscale's goroutines.
func (t *inAppTailnet) emitLoop() {
	for {
		select {
		case <-t.kick:
		case <-t.ctx.Done():
			return
		}
		msg := t.statusJSON()
		t.mu.Lock()
		same := msg == t.lastEmit
		t.lastEmit = msg
		t.mu.Unlock()
		if !same && t.cb != nil {
			t.cb.OnTailnetState(msg)
		}
	}
}

func (t *inAppTailnet) close() {
	t.stop()
	t.core.Close()
}

func (t *inAppTailnet) login() error  { return t.core.Login() }
func (t *inAppTailnet) logout() error { return t.core.Logout() }

func (t *inAppTailnet) statusJSON() string {
	b, _ := json.Marshal(t.core.Status())
	return string(b)
}

func (t *inAppTailnet) trafficJSON() string { return t.traffic.json() }

func (t *inAppTailnet) setPrefs(p tailnetPrefs) error {
	err := t.core.SetPrefs(toEnginePrefs(p))
	t.wake()
	return err
}

func (t *inAppTailnet) running() bool {
	state, _, _ := t.core.State()
	return state == ipn.Running
}

func (t *inAppTailnet) exitNode() (on, allowLAN bool) {
	p := t.core.LB.Prefs()
	if !p.Valid() {
		return false, false
	}
	return p.ExitNodeID() != "", p.ExitNodeAllowLANAccess()
}

// routes reports whether ip goes over the tailnet: a peer, an accepted subnet
// route or, with an exit node, the default route (minus the LAN when allowed).
func (t *inAppTailnet) routes(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	pr, ok := t.core.LB.PeerForIP(ip)
	if !ok || pr.IsSelf {
		return false
	}
	if pr.Route.Bits() == 0 {
		if _, allowLAN := t.exitNode(); allowLAN && ip.IsPrivate() && !tsaddr.IsTailscaleIP(ip) {
			return false
		}
	}
	return true
}

func (t *inAppTailnet) resolve(ctx context.Context, host string) (netip.Addr, bool) {
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		return ip, t.routes(ip)
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	if name == "" || name == "localhost" || strings.HasSuffix(name, ".local") {
		return netip.Addr{}, false
	}
	if t.splitDNSDomain(name) {
		if ip, ok := t.lookupDNS(ctx, name); ok && t.routes(ip) {
			return ip, true
		}
		return netip.Addr{}, false
	}
	// MagicDNS names (short or full) resolve from the netmap. Other names
	// are looked up too, through the exit node's DNS when one is set.
	ipp, via, err := t.core.Dialer.UserDialPlan(ctx, "tcp", net.JoinHostPort(name, "0"))
	if err != nil || !via || !t.routes(ipp.Addr()) {
		return netip.Addr{}, false
	}
	return ipp.Addr(), true
}

// splitDNSDomain reports whether name falls under a split-DNS route, whose
// resolvers are only reachable through the tailnet.
func (t *inAppTailnet) splitDNSDomain(name string) bool {
	nm := t.core.LB.NetMap()
	if nm == nil {
		return false
	}
	for suffix := range nm.DNS.Routes {
		s := strings.ToLower(strings.TrimSuffix(suffix, "."))
		if s != "" && (name == s || strings.HasSuffix(name, "."+s)) {
			return true
		}
	}
	return false
}

// lookupDNS asks Tailscale's resolver (quad-100) for A, then AAAA.
func (t *inAppTailnet) lookupDNS(ctx context.Context, name string) (netip.Addr, bool) {
	from := netip.AddrPortFrom(t.core.SelfAddr(true), 0)
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		q, err := dnsQuery(name, typ)
		if err != nil {
			return netip.Addr{}, false
		}
		resp, err := t.core.DNSManager.Query(ctx, q, "tcp", from)
		if err != nil {
			continue
		}
		if ip, ok := dnsFirstAddr(resp); ok {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

func dnsQuery(name string, typ dnsmessage.Type) ([]byte, error) {
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: uint16(time.Now().UnixNano()), RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

func dnsFirstAddr(resp []byte) (netip.Addr, bool) {
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		return netip.Addr{}, false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return netip.Addr{}, false
	}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return netip.Addr{}, false
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return netip.Addr{}, false
			}
			return netip.AddrFrom4(r.A), true
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return netip.Addr{}, false
			}
			return netip.AddrFrom16(r.AAAA), true
		default:
			if err := p.SkipAnswer(); err != nil {
				return netip.Addr{}, false
			}
		}
	}
}

func (t *inAppTailnet) dialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	c, err := t.core.Dialer.UserDial(ctx, "tcp", dst.String())
	if err != nil {
		return nil, err
	}
	return t.traffic.track(c, false), nil
}

func (t *inAppTailnet) dialUDP(ctx context.Context, dst netip.AddrPort, localPort uint16) (net.Conn, error) {
	c, err := t.openUDP(ctx, dst, localPort)
	if err != nil {
		return nil, err
	}
	return t.traffic.track(c, true), nil
}

func (t *inAppTailnet) openUDP(ctx context.Context, dst netip.AddrPort, localPort uint16) (net.Conn, error) {
	if localPort == 0 {
		return t.core.Dialer.UserDial(ctx, "udp", dst.String())
	}
	network := "udp4"
	if dst.Addr().Is6() {
		network = "udp6"
	}
	self := t.core.SelfAddr(dst.Addr().Is4())
	if !self.IsValid() {
		return nil, fmt.Errorf("no tailnet address for %s", network)
	}
	pc, err := t.core.Netstack.ListenPacket(network, netip.AddrPortFrom(self, localPort).String())
	if err != nil {
		return nil, err
	}
	return &fixedPeerConn{PacketConn: pc, peer: net.UDPAddrFromAddrPort(dst)}, nil
}

func (t *inAppTailnet) ping(ctx context.Context, ip netip.Addr) (tailnetPingResult, error) {
	res, err := t.core.Ping(ctx, ip)
	if err != nil {
		return tailnetPingResult{}, err
	}
	out := tailnetPingResult{
		IP:        res.IP,
		NodeName:  res.NodeName,
		LatencyMs: res.LatencySeconds * 1000,
		Endpoint:  res.Endpoint,
		Error:     res.Err,
	}
	if res.Endpoint == "" {
		out.DERP = res.DERPRegionCode
	}
	return out, nil
}
