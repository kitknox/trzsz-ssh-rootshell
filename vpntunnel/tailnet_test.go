package vpntunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
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
	p := newTailnetPath(cfg, routing, &tunnelStats{})
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

// answeringBackend plays Tailscale's resolver: every query to 100.100.100.100
// gets one A record back through the path's outbound stream.
type answeringBackend struct {
	p      *tailnetPath
	answer netip.Addr
}

func (b *answeringBackend) deliver(pkt []byte) {
	info, ok := parseIPPacket(pkt)
	if !ok || info.dst != quad100 {
		return
	}
	q, ok := parseDNSQuery(info.udpPayload())
	if !ok {
		return
	}
	resp := dnsAnswer(q, dnsmessage.RCodeSuccess, &b.answer, 60)
	go b.p.emit(buildUDPPacket(netip.AddrPortFrom(quad100, 53), netip.AddrPortFrom(info.src, info.srcPort), resp))
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
	p, _ := testPath(t, testRouting(), true)
	peer := netip.MustParseAddr("100.90.1.2")
	p.setBackend(&answeringBackend{p: p, answer: peer})

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

	// Tailnet name: Tailscale's resolver, and its reply never reaches the provider.
	m = tcpDNS(t, conn, dnsQuery(t, "laptop.tail1234.ts.net.", dnsmessage.TypeA))
	if got := netip.AddrFrom4(m.Answers[0].Body.(*dnsmessage.AResource).A); got != peer {
		t.Fatalf("TCP tailnet answer %s", got)
	}
	select {
	case e := <-p.out:
		t.Fatalf("probe reply leaked to the provider: %x", e.data)
	default:
	}
	if len(p.probes) != 0 {
		t.Fatalf("probe not released: %v", p.probes)
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
	p.tailnetDial = func(context.Context, netip.AddrPort) (net.Conn, error) { return nil, errors.New("unused") }
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
	pre := newTailnetPath(cfg, testRouting(), &tunnelStats{})
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
