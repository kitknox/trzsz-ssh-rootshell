package vpntunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/route"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func testRouting() routingConfigJSON {
	return routingConfigJSON{Rules: []routingRuleJSON{
		{Pattern: "direct.corp.example.com", Action: "direct"},
		{Pattern: "corp.example.com", Action: "ssh"},
		{Pattern: "*.intranet", Action: "ssh"},
		{Pattern: "10.20.0.0/16", Action: "ssh"},
		{Pattern: "192.168.50.7", Action: "direct"},
		{Pattern: "", Action: "ssh"},
		{Pattern: "bogus.example", Action: "maybe"},
	}}
}

func TestRouteTableMatching(t *testing.T) {
	tbl := compileRouteTable(testRouting(), true)
	for _, tc := range []struct {
		host string
		want routeAction
	}{
		{"corp.example.com", routeSSH},
		{"WIKI.Corp.Example.com.", routeSSH},
		{"direct.corp.example.com", routeDirect},
		{"a.direct.corp.example.com", routeDirect},
		{"notcorp.example.com", routeNone},
		{"git.intranet", routeSSH},
		{"intranet", routeNone},
		{"bogus.example", routeNone},
	} {
		if got := tbl.matchHost(tc.host); got != tc.want {
			t.Errorf("matchHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
	for _, tc := range []struct {
		ip   string
		want routeAction
	}{
		{"10.20.3.4", routeSSH},
		{"10.21.0.1", routeNone},
		{"192.168.50.7", routeDirect},
		{"::ffff:10.20.0.9", routeSSH},
	} {
		if got := tbl.matchIP(netip.MustParseAddr(tc.ip)); got != tc.want {
			t.Errorf("matchIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if got := tbl.dnsDomains(routeSSH); !slices.Equal(got, []string{"corp.example.com", "intranet"}) {
		t.Errorf("dnsDomains(ssh) = %q", got)
	}

	// Without an SSH host, SSH rules do nothing.
	noSSH := compileRouteTable(testRouting(), false)
	if got := noSSH.matchHost("corp.example.com"); got != routeNone {
		t.Errorf("no-ssh matchHost = %v", got)
	}
	if len(noSSH.prefixes(routeSSH)) != 0 || noSSH.sendAllViaSSH {
		t.Errorf("no-ssh table still routes to SSH")
	}
}

func TestGlobSuffix(t *testing.T) {
	for glob, want := range map[string]string{
		"*.corp.example.com": "corp.example.com",
		"api-?.example.com":  "example.com",
		"*":                  "",
		"foo*":               "",
	} {
		if got := globSuffix(glob); got != want {
			t.Errorf("globSuffix(%q) = %q, want %q", glob, got, want)
		}
	}
}

func TestFakeIPPoolWraps(t *testing.T) {
	p := newFakeIPPool()
	a := p.assign("one.example")
	if !fakeIPPrefix.Contains(a) || a == fakeIPPrefix.Addr() {
		t.Fatalf("bad fake address %s", a)
	}
	if again := p.assign("one.example"); again != a {
		t.Fatalf("reassigned %s -> %s", a, again)
	}
	if h, ok := p.host(a); !ok || h != "one.example" {
		t.Fatalf("host(%s) = %q, %v", a, h, ok)
	}
	for i := 1; i < fakeIPCapacity; i++ {
		p.assign("filler-" + itoa(i))
	}
	// One more evicts the first name and reuses its address.
	b := p.assign("next.example")
	if b != a {
		t.Fatalf("wrap gave %s, want %s", b, a)
	}
	if h, _ := p.host(a); h != "next.example" {
		t.Fatalf("after wrap host = %q", h)
	}
	if _, ok := p.host(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("real address resolved as fake")
	}
}

func TestRecentIPs(t *testing.T) {
	r := newRecentIPs(2)
	a, b, c := netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2"), netip.MustParseAddr("3.3.3.3")
	r.add(a)
	r.add(b)
	r.add(c)
	if r.contains(a) || !r.contains(b) || !r.contains(c) {
		t.Fatal("ring did not evict the oldest")
	}
}

func dnsQuery(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x4242, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestBuildUDPPacketChecksums(t *testing.T) {
	for _, pair := range [][2]string{
		{"100.100.100.100:53", "100.101.102.103:5353"},
		{"[fd7a:115c:a1e0::53]:53", "[fd7a:115c:a1e0::1]:5353"},
	} {
		src, dst := netip.MustParseAddrPort(pair[0]), netip.MustParseAddrPort(pair[1])
		payload := []byte("hello, odd length")
		pkt := buildUDPPacket(src, dst, payload)
		info, ok := parseIPPacket(pkt)
		if !ok || info.src != src.Addr() || info.dst != dst.Addr() || info.dstPort != dst.Port() {
			t.Fatalf("round trip failed: %+v", info)
		}
		if string(info.udpPayload()) != string(payload) {
			t.Fatalf("payload %q", info.udpPayload())
		}
		// Recomputing over the finished packet must give zero.
		var sum uint32
		l4 := info.l4
		if src.Addr().Is4() {
			if checksumFold(checksumAdd(0, pkt[:20])) != 0 {
				t.Fatal("bad IPv4 header checksum")
			}
			sum = checksumAdd(0, pkt[12:20])
		} else {
			sum = checksumAdd(0, pkt[8:40])
		}
		sum += uint32(ipProtoUDP) + uint32(binary.BigEndian.Uint16(l4[4:6]))
		if checksumFold(checksumAdd(sum, l4)) != 0 {
			t.Fatalf("bad UDP checksum for %v", src)
		}
	}
}

// fakeBackend records packets handed to WireGuard.
type fakeBackend struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (f *fakeBackend) deliver(pkt []byte) {
	f.mu.Lock()
	f.pkts = append(f.pkts, pkt)
	f.mu.Unlock()
}

func (f *fakeBackend) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pkts)
}

func testPath(t *testing.T, routing routingConfigJSON, socks bool) (*tailnetPath, *fakeBackend) {
	t.Helper()
	cfg := &VPNTunnelConfig{TransportType: "tailscale"}
	if socks {
		cfg.SOCKS5Address = "127.0.0.1:1"
	}
	return testPathWith(t, cfg, routing, false)
}

func testPathWith(t *testing.T, cfg *VPNTunnelConfig, routing routingConfigJSON, tsshEgress bool) (*tailnetPath, *fakeBackend) {
	t.Helper()
	p := newTailnetPath(cfg, routing, tsshEgress, &tunnelStats{})
	fb := &fakeBackend{}
	p.setBackend(fb)
	p.setState(&tailnetNetState{
		addrs:      []netip.Prefix{netip.MustParsePrefix("100.101.102.103/32"), netip.MustParsePrefix("fd7a:115c:a1e0::1/128")},
		routes:     []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48"), netip.MustParsePrefix("10.20.5.0/24")},
		dnsServers: []netip.Addr{quad100},
		match:      []string{"tail1234.ts.net"},
		search:     []string{"tail1234.ts.net"},
	})
	t.Cleanup(p.close)
	return p, fb
}

func dnsPacket(t *testing.T, name string, typ dnsmessage.Type) []byte {
	return buildUDPPacket(netip.MustParseAddrPort("100.101.102.103:6000"), netip.AddrPortFrom(quad100, 53), dnsQuery(t, name, typ))
}

func readReply(t *testing.T, p *tailnetPath) dnsmessage.Message {
	t.Helper()
	select {
	case e := <-p.out:
		info, ok := parseIPPacket(e.data)
		if !ok || info.src != quad100 || info.dstPort != 6000 {
			t.Fatalf("bad reply packet %+v", info)
		}
		var m dnsmessage.Message
		if err := m.Unpack(info.udpPayload()); err != nil {
			t.Fatal(err)
		}
		return m
	case <-time.After(2 * time.Second):
		t.Fatal("no DNS reply")
	}
	return dnsmessage.Message{}
}

func TestTailnetDNSRouting(t *testing.T) {
	p, fb := testPath(t, testRouting(), true)

	// Tailnet names go to Tailscale's resolver untouched.
	p.injectPacket(dnsPacket(t, "laptop.tail1234.ts.net.", dnsmessage.TypeA), 2)
	if fb.count() != 1 {
		t.Fatalf("tailnet query not delivered, count=%d", fb.count())
	}

	// SSH-rule names get a fake A record and an empty AAAA.
	p.injectPacket(dnsPacket(t, "wiki.corp.example.com.", dnsmessage.TypeA), 2)
	m := readReply(t, p)
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Fatalf("fake answer: %+v", m)
	}
	a := netip.AddrFrom4(m.Answers[0].Body.(*dnsmessage.AResource).A)
	if h, ok := p.fake.host(a); !ok || h != "wiki.corp.example.com" {
		t.Fatalf("fake %s maps to %q", a, h)
	}
	p.injectPacket(dnsPacket(t, "wiki.corp.example.com.", dnsmessage.TypeAAAA), 2)
	if m := readReply(t, p); len(m.Answers) != 0 || m.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("AAAA answer: %+v", m)
	}
	if fb.count() != 1 {
		t.Fatal("SSH-rule query leaked to Tailscale")
	}
}

func TestTailnetPacketClassification(t *testing.T) {
	p, _ := testPath(t, testRouting(), true)
	st := p.state.Load()
	for _, tc := range []struct {
		ip      string
		toStack bool
		tailnet bool
	}{
		{"100.90.1.2", false, true},        // tailnet peer
		{"10.20.5.9", true, true},          // SSH CIDR rule beats subnet route
		{"10.20.9.9", true, false},         // SSH CIDR rule
		{"198.18.0.5", true, false},        // fake address
		{"8.8.8.8", false, false},          // not ours in split mode
		{"fd7a:115c:a1e0::9", false, true}, // tailnet IPv6
	} {
		ip := netip.MustParseAddr(tc.ip)
		if got := p.toStack(ip, st); got != tc.toStack {
			t.Errorf("toStack(%s) = %v, want %v", tc.ip, got, tc.toStack)
		}
		if got := st.routesContain(ip); got != tc.tailnet {
			t.Errorf("routesContain(%s) = %v, want %v", tc.ip, got, tc.tailnet)
		}
	}

	full := routingConfigJSON{SendAllViaSSH: true, Rules: testRouting().Rules}
	pf, _ := testPath(t, full, true)
	stf := pf.state.Load()
	if !pf.toStack(netip.MustParseAddr("8.8.8.8"), stf) {
		t.Error("full tunnel: internet address should go to the stack")
	}
	if pf.toStack(netip.MustParseAddr("100.90.1.2"), stf) {
		t.Error("full tunnel: tailnet address should stay raw")
	}
	if !pf.viaSSH(netip.MustParseAddr("8.8.8.8")) || pf.viaSSH(netip.MustParseAddr("192.168.50.7")) {
		t.Error("full tunnel: viaSSH wrong")
	}
	pf.directIPs.add(netip.MustParseAddr("9.9.9.9"))
	if pf.viaSSH(netip.MustParseAddr("9.9.9.9")) {
		t.Error("remembered direct answer still goes via SSH")
	}
}

func TestDirectExclusionsKeepFirstMatch(t *testing.T) {
	tbl := compileRouteTable(routingConfigJSON{Rules: []routingRuleJSON{
		{Pattern: "10.0.0.0/8", Action: "ssh"},
		{Pattern: "10.1.0.0/16", Action: "direct"}, // shadowed by the SSH rule
		{Pattern: "192.168.0.0/16", Action: "direct"},
		{Pattern: "198.18.0.0/16", Action: "direct"}, // fake-IP range
	}}, true)
	got := tbl.directExclusions()
	if len(got) != 1 || got[0] != netip.MustParsePrefix("192.168.0.0/16") {
		t.Fatalf("directExclusions = %v", got)
	}
	if tbl.matchIP(netip.MustParseAddr("10.1.2.3")) != routeSSH {
		t.Fatal("first match should be SSH")
	}
}

func TestTailnetGlobalDNSInFullTunnel(t *testing.T) {
	full := routingConfigJSON{SendAllViaSSH: true, Rules: testRouting().Rules}
	p, fb := testPath(t, full, true)
	// Tailscale took every query: no match domains, suffix in search.
	p.setState(&tailnetNetState{
		addrs:      []netip.Prefix{netip.MustParsePrefix("100.101.102.103/32")},
		routes:     []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		dnsServers: []netip.Addr{quad100},
		match:      []string{"tail1234.ts.net"}, // as rebuildNetState fills it from search
		search:     []string{"tail1234.ts.net"},
		allDomains: true,
	})
	p.injectPacket(dnsPacket(t, "laptop.tail1234.ts.net.", dnsmessage.TypeA), 2)
	p.injectPacket(dnsPacket(t, "example.org.", dnsmessage.TypeA), 2)
	if fb.count() != 2 {
		t.Fatalf("queries for tailnet and global resolvers not sent to Tailscale, count=%d", fb.count())
	}
	// SSH rules still win over the global resolvers.
	p.injectPacket(dnsPacket(t, "wiki.corp.example.com.", dnsmessage.TypeA), 2)
	if m := readReply(t, p); len(m.Answers) != 1 {
		t.Fatalf("SSH-rule name not answered with a fake address: %+v", m)
	}
}

func tcpDNS(t *testing.T, conn net.Conn, query []byte) dnsmessage.Message {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	frame := append([]byte{byte(len(query) >> 8), byte(len(query))}, query...)
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestTailnetDNSOverTCPFollowsRules(t *testing.T) {
	p, fb := testPath(t, testRouting(), true)
	peer := netip.MustParseAddr("100.90.1.2")
	var asked []string
	p.tailscaleQuery = func(_ context.Context, query []byte) ([]byte, error) {
		q, _ := parseDNSQuery(query)
		asked = append(asked, q.name)
		return dnsAnswer(q, dnsmessage.RCodeSuccess, &peer, 60), nil
	}

	conn, err := (&routedDialer{p: p}).DialTCP(context.Background(), "100.100.100.100:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// SSH-rule name: fake address, as over UDP.
	m := tcpDNS(t, conn, dnsQuery(t, "wiki.corp.example.com.", dnsmessage.TypeA))
	a := netip.AddrFrom4(m.Answers[0].Body.(*dnsmessage.AResource).A)
	if h, ok := p.fake.host(a); !ok || h != "wiki.corp.example.com" {
		t.Fatalf("TCP SSH-rule answer %s -> %q", a, h)
	}

	// Tailnet name: Tailscale's resolver in-process, with no packets sent.
	m = tcpDNS(t, conn, dnsQuery(t, "laptop.tail1234.ts.net.", dnsmessage.TypeA))
	if got := netip.AddrFrom4(m.Answers[0].Body.(*dnsmessage.AResource).A); got != peer {
		t.Fatalf("TCP tailnet answer %s", got)
	}
	if !slices.Equal(asked, []string{"laptop.tail1234.ts.net"}) || fb.count() != 0 {
		t.Fatalf("Tailscale asked %v, packets %d", asked, fb.count())
	}
}

func TestDNSExchangeKeepsTCP(t *testing.T) {
	// A TCP-only DNS server: the TCP path must not fall back to UDP.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var hdr [2]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(c, query); err != nil {
			return
		}
		q, _ := parseDNSQuery(query)
		a := netip.MustParseAddr("192.0.2.7")
		resp := dnsAnswer(q, dnsmessage.RCodeSuccess, &a, 60)
		_, _ = c.Write(append([]byte{byte(len(resp) >> 8), byte(len(resp))}, resp...))
	}()

	p, _ := testPath(t, routingConfigJSON{}, false)
	p.upstream = []string{ln.Addr().String()}
	pinDirectTo(t, net.ParseIP("127.0.0.1"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := p.exchangeDNS(ctx, dnsQuery(t, "big.example.org.", dnsmessage.TypeA), false, true)
	if err != nil {
		t.Fatal(err)
	}
	if addrs := dnsAnswerAddrs(resp); len(addrs) != 1 || addrs[0] != netip.MustParseAddr("192.0.2.7") {
		t.Fatalf("answer %v", addrs)
	}
}

func TestTailnetTCPDNSUsesStackOnlyWithEgress(t *testing.T) {
	syn := func() []byte {
		// Minimal IPv4/TCP header to 100.100.100.100:53.
		pkt := make([]byte, 40)
		pkt[0], pkt[9] = 0x45, ipProtoTCP
		binary.BigEndian.PutUint16(pkt[2:4], 40)
		copy(pkt[12:16], netip.MustParseAddr("100.101.102.103").AsSlice())
		copy(pkt[16:20], quad100.AsSlice())
		binary.BigEndian.PutUint16(pkt[20:22], 5555)
		binary.BigEndian.PutUint16(pkt[22:24], 53)
		return pkt
	}
	only, fb := testPath(t, testRouting(), false)
	only.injectPacket(syn(), 2)
	if fb.count() != 1 || only.statsSnapshot().Netstack {
		t.Fatal("Tailscale-only TCP DNS should go to Tailscale")
	}
	egress, efb := testPath(t, testRouting(), true)
	egress.injectPacket(syn(), 2)
	if efb.count() != 0 || !egress.statsSnapshot().Netstack {
		t.Fatal("TCP DNS with SSH egress should be terminated locally")
	}
}

func TestTailnetCaptureRouting(t *testing.T) {
	p, _ := testPath(t, routingConfigJSON{}, false) // Tailscale only
	changes := 0
	p.onCaptureChange = func(bool) { changes++ }
	hook := p.refreshCapture
	captureRoutingHook.Store(&hook)
	t.Cleanup(func() { captureRoutingHook.Store(nil) })

	st := p.state.Load()
	tailnetTCP := ipPacketInfo{dst: netip.MustParseAddr("100.90.1.2"), proto: ipProtoTCP, dstPort: 443}
	tailnetUDP := ipPacketInfo{dst: netip.MustParseAddr("100.90.1.2"), proto: ipProtoUDP, dstPort: 41641}
	internet := ipPacketInfo{dst: netip.MustParseAddr("93.184.216.34"), proto: ipProtoTCP, dstPort: 443}
	ca := ipPacketInfo{dst: caEndpointAddr, proto: ipProtoTCP, dstPort: 80}

	// Off: nothing goes to the netstack and the routes stay split.
	idle := p.networkSettings()
	for _, info := range []ipPacketInfo{tailnetTCP, tailnetUDP, internet, ca} {
		if p.captureToStack(info, st) {
			t.Fatalf("idle capture terminates %v", info.dst)
		}
	}

	// Recording: tailnet TCP and everything off the tailnet; tailnet UDP stays raw.
	testCapture(t, nil)
	if !p.capturing.Load() || !p.servesCA.Load() || changes == 0 {
		t.Fatal("hook did not report recording")
	}
	if !p.captureToStack(tailnetTCP, st) || p.captureToStack(tailnetUDP, st) ||
		!p.captureToStack(internet, st) || !p.captureToStack(ca, st) {
		t.Fatal("recording routes wrong")
	}
	if p.egressFor(tailnetTCP.dst) != egressTailnet || p.egressFor(internet.dst) != egressDirect {
		t.Fatal("recording egress wrong")
	}
	s := p.networkSettings()
	if !slices.Equal(s.IPv4Routes, []string{"0.0.0.0/0"}) || !slices.Equal(s.IPv6Routes, []string{"::/0"}) ||
		!slices.Equal(s.MatchDomains, []string{""}) {
		t.Fatalf("recording settings: %+v", s)
	}
	p.ensureStack()

	// Stopped: back to the idle routes, and the netstack is freed.
	CaptureStop()
	if p.capturing.Load() {
		t.Fatal("still capturing after stop")
	}
	if p.statsSnapshot().Netstack {
		t.Fatal("netstack kept after capture stopped")
	}
	s = p.networkSettings()
	s.IPv4Routes = slices.DeleteFunc(s.IPv4Routes, func(r string) bool { return r == "10.0.0.1/32" }) // CA stays reachable
	if !slices.Equal(s.IPv4Routes, idle.IPv4Routes) || !slices.Equal(s.MatchDomains, idle.MatchDomains) {
		t.Fatalf("settings after stop %+v, idle %+v", s, idle)
	}
}

// peerBackend stands in for WireGuard and a tailnet host: a second gVisor
// stack whose packets come back through the path's outbound stream.
type peerBackend struct {
	ep *channel.Endpoint
}

func (b *peerBackend) deliver(pkt []byte) {
	buf := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
	b.ep.InjectInbound(ipv4.ProtocolNumber, buf)
	buf.DecRef()
}

func newTailnetPeer(t *testing.T, p *tailnetPath, addr netip.Addr) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	ep := channel.New(256, tailnetMTU, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			data := append([]byte(nil), pkt.ToView().AsSlice()...)
			pkt.DecRef()
			p.emit(data)
		}
	}()
	p.setBackend(&peerBackend{ep: ep})
	t.Cleanup(func() {
		cancel()
		s.Close()
	})
	return s
}

func TestDialTailnetOverLink(t *testing.T) {
	p, _ := testPath(t, routingConfigJSON{}, false)
	peerAddr := netip.MustParseAddr("100.90.1.2")
	peer := newTailnetPeer(t, p, peerAddr)
	ln, err := gonet.ListenTCP(peer, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(peerAddr.AsSlice()), Port: 80}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err == nil {
			_, _ = c.Write(append([]byte("echo:"), buf...))
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := p.dialTailnet(ctx, netip.AddrPortFrom(peerAddr, 80))
	if err != nil {
		t.Fatal(err)
	}
	if p.linkConns.Load() != 1 {
		t.Fatalf("link connections = %d", p.linkConns.Load())
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 9)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "echo:ping" {
		t.Fatalf("read %q, %v", got, err)
	}
	c.Close()
	if p.linkConns.Load() != 0 {
		t.Fatalf("link connections after close = %d", p.linkConns.Load())
	}
	// The peer's replies were claimed by the link, never sent to the apps.
	select {
	case e := <-p.out:
		t.Fatalf("link reply leaked to the provider: %x", e.data)
	default:
	}
}

func TestCapturedTailnetFlowEndToEnd(t *testing.T) {
	p, _ := testPath(t, routingConfigJSON{}, false)
	peerAddr := netip.MustParseAddr("100.90.1.2")
	peer := newTailnetPeer(t, p, peerAddr)
	ln, err := gonet.ListenTCP(peer, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(peerAddr.AsSlice()), Port: 80}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err == nil {
			_, _ = c.Write(append([]byte("echo:"), buf...))
		}
	}()

	// An app on the device: its packets enter the tunnel, and the tunnel's
	// output comes back to it.
	app := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	defer app.Close()
	appEP := channel.New(256, tailnetMTU, "")
	if err := app.CreateNIC(1, appEP); err != nil {
		t.Fatal(err)
	}
	node := netip.MustParseAddr("100.101.102.103")
	_ = app.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFromSlice(node.AsSlice()).WithPrefix(),
	}, stack.AddressProperties{})
	app.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		for {
			pkt := appEP.ReadContext(ctx)
			if pkt == nil {
				return
			}
			data := append([]byte(nil), pkt.ToView().AsSlice()...)
			pkt.DecRef()
			p.injectPacket(data, 2)
		}
	}()
	go func() {
		for {
			data, _ := p.readPacket()
			if data == nil {
				return
			}
			buf := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
			appEP.InjectInbound(ipv4.ProtocolNumber, buf)
			buf.DecRef()
		}
	}()

	p.capturing.Store(true) // routing as while recording
	c, err := gonet.DialContextTCP(ctx, app, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(peerAddr.AsSlice()), Port: 80}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 9)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "echo:ping" {
		t.Fatalf("app read %q, %v", got, err)
	}
	if !p.statsSnapshot().Netstack {
		t.Fatal("captured flow did not go through the netstack")
	}
}

// recordingEgress stands in for a tsshd connection.
type recordingEgress struct {
	mu   sync.Mutex
	tcp  []string
	udp  []string
	done bool
}

func (r *recordingEgress) DialTCP(_ context.Context, addr string) (net.Conn, error) {
	r.mu.Lock()
	r.tcp = append(r.tcp, addr)
	r.mu.Unlock()
	c, _ := net.Pipe()
	return c, nil
}

func (r *recordingEgress) DialUDP(_ context.Context, addr string) (udpConn, error) {
	r.mu.Lock()
	r.udp = append(r.udp, addr)
	r.mu.Unlock()
	return nil, errors.New("recorded")
}

func TestTailnetTSSHEgress(t *testing.T) {
	p, _ := testPathWith(t, &VPNTunnelConfig{TransportType: "tailscale"}, testRouting(), true)
	d := &routedDialer{p: p}

	// Before tsshd attaches: SSH rules already apply, dials fail fast.
	if p.table.matchHost("wiki.corp.example.com") != routeSSH {
		t.Fatal("SSH rules inert before the TSSH egress attaches")
	}
	if _, err := d.DialTCP(context.Background(), "10.20.9.9:22"); !errors.Is(err, errEgressNotReady) {
		t.Fatalf("pre-attach dial: %v", err)
	}
	ts := p.ensureStack()
	if !ts.udpFwd.blockQUIC.Load() {
		t.Fatal("QUIC allowed before the egress can carry it")
	}

	// Attached: TCP and UDP both go over it, and QUIC opens up.
	eg := &recordingEgress{}
	p.setEgress(&egressDialers{tcp: eg, udp: eg, close: func() { eg.done = true }}, true)
	if ts.udpFwd.blockQUIC.Load() {
		t.Fatal("QUIC still blocked with a QUIC-capable egress")
	}
	fake := p.fake.assign("wiki.corp.example.com")
	if c, err := d.DialTCP(context.Background(), netip.AddrPortFrom(fake, 443).String()); err != nil {
		t.Fatal(err)
	} else {
		c.Close()
	}
	_, _ = d.DialUDP(context.Background(), netip.AddrPortFrom(fake, 443).String())
	_, _ = d.DialUDP(context.Background(), "10.20.9.9:53")
	if !slices.Equal(eg.tcp, []string{"wiki.corp.example.com:443"}) ||
		!slices.Equal(eg.udp, []string{"wiki.corp.example.com:443", "10.20.9.9:53"}) {
		t.Fatalf("egress saw tcp=%v udp=%v", eg.tcp, eg.udp)
	}

	// Replacing it closes the old one; so does closing the path.
	p.setEgress(&egressDialers{tcp: egressDown{}}, false)
	if !eg.done || !ts.udpFwd.blockQUIC.Load() {
		t.Fatal("old egress not closed or QUIC not re-blocked")
	}
}

func TestDirectDialFailsClosedWithoutInterface(t *testing.T) {
	SetDirectInterface(0)
	if _, err := (&directDialer{}).DialTCP(context.Background(), "192.0.2.1:443"); !errors.Is(err, errNoDirectInterface) {
		t.Fatalf("unpinned direct dial: %v", err)
	}
	if _, err := (&directDialer{}).DialUDP(context.Background(), "192.0.2.1:53"); !errors.Is(err, errNoDirectInterface) {
		t.Fatalf("unpinned direct UDP dial: %v", err)
	}
}

func TestPickDirectInterface(t *testing.T) {
	ifaces, _ := net.Interfaces()
	var all []string
	loopback := 0
	for _, ifc := range ifaces {
		all = append(all, itoa(ifc.Index))
		if ifc.Flags&net.FlagLoopback != 0 {
			loopback = ifc.Index
		}
	}
	if got := PickDirectInterface(itoa(loopback)); got != 0 {
		t.Fatalf("loopback picked: %d", got)
	}
	if got := PickDirectInterface(""); got != 0 {
		t.Fatalf("empty candidates picked %d", got)
	}
	// On this machine: whatever is picked must reach a gateway and be usable.
	got := PickDirectInterface(strings.Join(all, ","))
	if got == 0 {
		t.Skip("no interface with a default route here")
	}
	ifc, err := net.InterfaceByIndex(got)
	if err != nil || !usableDirectInterface(ifc) || !defaultGatewayInterfaces()[got] {
		t.Fatalf("picked %d (%v) without a usable default route", got, ifc)
	}
}

func TestIsDefaultDestination(t *testing.T) {
	zero4 := &route.Inet4Addr{}
	host := &route.Inet4Addr{IP: [4]byte{10, 0, 0, 1}}
	mask24 := &route.Inet4Addr{IP: [4]byte{255, 255, 255, 0}}
	for _, tc := range []struct {
		addrs []route.Addr
		want  bool
	}{
		{[]route.Addr{zero4, host, zero4}, true},
		{[]route.Addr{zero4, host}, true}, // no netmask sent
		{[]route.Addr{zero4, host, mask24}, false},
		{[]route.Addr{host, host, zero4}, false},
		{[]route.Addr{&route.Inet6Addr{}, host, &route.Inet6Addr{}}, true},
	} {
		if got := isDefaultDestination(tc.addrs); got != tc.want {
			t.Errorf("isDefaultDestination(%v) = %v, want %v", tc.addrs, got, tc.want)
		}
	}
}

func TestTailnetCancelReleasesBlockedWriter(t *testing.T) {
	p, _ := testPath(t, routingConfigJSON{}, false)
	for range tailnetOutQueue {
		p.emit([]byte{0x45})
	}
	done := make(chan struct{})
	go func() {
		p.emit([]byte{0x45}) // queue full, nobody reading
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("emit returned with a full queue")
	case <-time.After(50 * time.Millisecond):
	}
	p.cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not release the blocked writer")
	}
}

func TestTailnetNetworkSettings(t *testing.T) {
	// Before login: placeholder address, no routes or DNS.
	cfg := &VPNTunnelConfig{TransportType: "tailscale", SOCKS5Address: "127.0.0.1:1"}
	pre := newTailnetPath(cfg, testRouting(), false, &tunnelStats{})
	defer pre.close()
	s := pre.networkSettings()
	if !slices.Equal(s.IPv4Addresses, []string{placeholderTunnelAddr}) || len(s.IPv4Routes) != 0 || len(s.DNSServers) != 0 {
		t.Fatalf("pre-login settings: %+v", s)
	}

	p, _ := testPath(t, testRouting(), true)
	s = p.networkSettings()
	if !slices.Equal(s.IPv4Addresses, []string{"100.101.102.103"}) || !slices.Equal(s.IPv6Addresses, []string{"fd7a:115c:a1e0::1"}) {
		t.Fatalf("addresses: %+v", s)
	}
	for _, want := range []string{"100.64.0.0/10", "10.20.5.0/24", "10.20.0.0/16", "198.18.0.0/15"} {
		if !slices.Contains(s.IPv4Routes, want) {
			t.Errorf("missing route %s in %v", want, s.IPv4Routes)
		}
	}
	if s.FullTunnel || !slices.Equal(s.DNSServers, []string{"100.100.100.100"}) {
		t.Fatalf("dns/full: %+v", s)
	}
	if !slices.Equal(s.MatchDomains, []string{"tail1234.ts.net", "corp.example.com", "intranet"}) {
		t.Fatalf("match domains %q", s.MatchDomains)
	}

	// Tailscale only: no fake pool, no SSH CIDRs.
	ts, _ := testPath(t, testRouting(), false)
	s = ts.networkSettings()
	if slices.Contains(s.IPv4Routes, "198.18.0.0/15") || slices.Contains(s.IPv4Routes, "10.20.0.0/16") {
		t.Fatalf("tailscale-only routes leak SSH rules: %v", s.IPv4Routes)
	}
	if !slices.Equal(s.MatchDomains, []string{"tail1234.ts.net"}) {
		t.Fatalf("tailscale-only match %q", s.MatchDomains)
	}

	// Full tunnel: default route, direct CIDRs excluded, every query.
	full := routingConfigJSON{SendAllViaSSH: true, Rules: testRouting().Rules}
	pf, _ := testPath(t, full, true)
	s = pf.networkSettings()
	if !s.FullTunnel || !slices.Equal(s.IPv4Routes, []string{"0.0.0.0/0"}) || !slices.Equal(s.IPv4Excluded, []string{"192.168.50.7/32"}) {
		t.Fatalf("full settings: %+v", s)
	}
	if !slices.Equal(s.MatchDomains, []string{""}) || !slices.Contains(s.IPv6Routes, "fd7a:115c:a1e0::/48") {
		t.Fatalf("full dns/v6: %+v", s)
	}

	// A direct rule over a tailnet route is not excluded at the OS level.
	overlap := routingConfigJSON{SendAllViaSSH: true, Rules: []routingRuleJSON{
		{Pattern: "100.64.0.0/10", Action: "direct"},
		{Pattern: "10.20.0.0/16", Action: "direct"}, // covers the 10.20.5.0/24 subnet route
	}}
	po, _ := testPath(t, overlap, true)
	if s := po.networkSettings(); len(s.IPv4Excluded) != 0 {
		t.Fatalf("tailnet-overlapping exclusions: %v", s.IPv4Excluded)
	}
}
