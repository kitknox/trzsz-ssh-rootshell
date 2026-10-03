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

package vpntunnel

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tsd"
	"tailscale.com/types/logid"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
)

// This file is a trimmed copy of tsnet's bootstrap. tsnet can't be used
// directly: it always starts a log uploader and keeps its own router and DNS
// configurators, while the provider needs both to build its network settings.

const tailscaleBuilt = true

const maxStatusPeers = 500

// activeNetMon lets SetDirectInterface nudge Tailscale after a path change.
var activeNetMon atomic.Pointer[netmon.Monitor]

func tailnetInterfaceChanged(index int) {
	if index > 0 {
		if ifc, err := net.InterfaceByIndex(index); err == nil {
			netmon.UpdateLastKnownDefaultRouteInterface(ifc.Name)
		}
	}
	if m := activeNetMon.Load(); m != nil {
		m.InjectEvent()
	}
}

type tsEngine struct {
	path *tailnetPath
	tun  *chanTUN
	cb   TailscaleCallback
	lb   *ipnlocal.LocalBackend
	ctx  context.Context
	stop context.CancelFunc

	mu        sync.Mutex
	state     ipn.State
	authURL   string
	lastErr   string
	routerCfg *router.Config
	dnsCfg    *dns.OSConfig
	lastEmit  string
	loginOnce bool // StartLoginInteractive already asked for this NeedsLogin

	kick      chan struct{}
	closers   []func()
	closeOnce sync.Once
}

func startTailnetEngine(path *tailnetPath, conf tailscaleConfigJSON, store TailscaleStateStore, cb TailscaleCallback) (_ tailnetEngine, reterr error) {
	logf := func(format string, a ...any) {
		if getDebugLogger() != nil {
			log.Printf("tailscale: "+format, a...)
		}
	}
	e := &tsEngine{path: path, cb: cb, kick: make(chan struct{}, 1)}
	e.ctx, e.stop = context.WithCancel(context.Background())
	defer func() {
		if reterr != nil {
			e.close()
		}
	}()
	e.closers = append(e.closers, e.stop)

	// We never upload logs; say so to the control plane.
	envknob.SetNoLogsNoSupport()
	hostinfo.SetApp("rootshell")

	dir := conf.StateDir
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "tailscale")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	sys := tsd.NewSystem()
	netMon, err := netmon.New(sys.Bus.Get(), logf)
	if err != nil {
		return nil, fmt.Errorf("netmon: %w", err)
	}
	e.closers = append(e.closers, func() { netMon.Close() })
	sys.Set(netMon)

	dialer := &tsdial.Dialer{Logf: logf}
	dialer.SetBus(sys.Bus.Get())
	e.tun = newChanTUN(path)
	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Tun:           e.tun,
		Router:        &tsRouter{e: e},
		DNS:           &tsDNS{e: e},
		EventBus:      sys.Bus.Get(),
		NetMon:        netMon,
		Dialer:        dialer,
		SetSubsystem:  sys.Set,
		ControlKnobs:  sys.ControlKnobs(),
		HealthTracker: sys.HealthTracker.Get(),
		Metrics:       sys.UserMetricsRegistry(),
	})
	if err != nil {
		return nil, fmt.Errorf("wgengine: %w", err)
	}
	// LocalBackend.Shutdown closes the engine once it exists; until then
	// (a failed start) close it here. Not dialer.Close: it panics when
	// peerAPI is compiled out, and the engine owns its sockets.
	e.closers = append(e.closers, func() {
		if e.lb == nil {
			eng.Close()
		}
	})
	sys.Set(eng)

	// Netstack only answers 100.100.100.100 (MagicDNS); tailnet traffic
	// stays raw through the TUN.
	ns, err := netstack.Create(logf, sys.Tun.Get(), eng, sys.MagicSock.Get(), dialer, sys.DNSManager.Get(), sys.ProxyMapper())
	if err != nil {
		return nil, fmt.Errorf("netstack: %w", err)
	}
	// LocalBackend.Shutdown doesn't close it; this covers a failed start.
	nsClosed := false
	closeNetstack := func() {
		if !nsClosed {
			nsClosed = true
			ns.Close()
		}
	}
	e.closers = append(e.closers, closeNetstack)
	sys.Tun.Get().Start()
	sys.Set(ns)
	ns.ProcessLocalIPs = false
	ns.ProcessSubnets = false

	sys.Set(ipn.StateStore(&tsStateStore{s: store}))
	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, controlclient.LoginDefault|controlclient.LocalBackendStartKeyOSNeutral)
	if err != nil {
		return nil, fmt.Errorf("local backend: %w", err)
	}
	e.lb = lb
	// tsnet's order: netstack, then the backend.
	e.closers = append(e.closers, func() {
		closeNetstack()
		lb.Shutdown()
	})
	lb.SetVarRoot(dir)
	if err := ns.Start(lb); err != nil {
		return nil, fmt.Errorf("netstack start: %w", err)
	}

	prefs := ipn.NewPrefs()
	prefs.Hostname = conf.Hostname
	prefs.WantRunning = true
	prefs.RouteAll = conf.AcceptRoutes
	prefs.CorpDNS = true
	if err := lb.Start(ipn.Options{UpdatePrefs: prefs}); err != nil {
		return nil, fmt.Errorf("backend start: %w", err)
	}
	// Start keeps stored prefs; re-apply the ones the user controls.
	if _, err := lb.EditPrefs(&ipn.MaskedPrefs{
		Prefs:          ipn.Prefs{Hostname: conf.Hostname, RouteAll: conf.AcceptRoutes, CorpDNS: true, WantRunning: true},
		HostnameSet:    conf.Hostname != "",
		RouteAllSet:    true,
		CorpDNSSet:     true,
		WantRunningSet: true,
	}); err != nil {
		logf("edit prefs: %v", err)
	}

	activeNetMon.Store(netMon)
	e.closers = append(e.closers, func() { activeNetMon.CompareAndSwap(netMon, nil) })
	dnsManager := sys.DNSManager.Get()
	path.tailscaleQuery = func(ctx context.Context, query []byte) ([]byte, error) {
		return dnsManager.Query(ctx, query, "tcp", netip.AddrPortFrom(e.localAddr(true), 0))
	}
	path.onCaptureChange = func(bool) { e.wake() }
	path.setBackend(e.tun)

	go e.emitLoop()
	ready := make(chan struct{})
	go lb.WatchNotifications(e.ctx, ipn.NotifyInitialState|ipn.NotifyNoNetMap,
		func() { close(ready) }, e.onNotify)
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
	}
	return e, nil
}

func (e *tsEngine) onNotify(n *ipn.Notify) bool {
	e.mu.Lock()
	login := false
	if n.State != nil {
		e.state = *n.State
		if e.state == ipn.NeedsLogin {
			login = !e.loginOnce
			e.loginOnce = true
		} else {
			e.loginOnce = false
		}
		if e.state == ipn.Running || e.state == ipn.Starting {
			e.authURL = ""
		}
	}
	if n.BrowseToURL != nil {
		e.authURL = *n.BrowseToURL
	}
	if n.ErrMessage != nil {
		e.lastErr = *n.ErrMessage
	}
	if n.LoginFinished != nil {
		e.authURL = ""
		e.lastErr = ""
	}
	e.mu.Unlock()
	if login {
		go func() {
			if err := e.lb.StartLoginInteractive(e.ctx); err != nil {
				e.setError(err)
			}
		}()
	}
	e.wake()
	return e.ctx.Err() == nil
}

func (e *tsEngine) setError(err error) {
	e.mu.Lock()
	e.lastErr = err.Error()
	e.mu.Unlock()
	e.wake()
}

func (e *tsEngine) wake() {
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

// emitLoop coalesces changes and calls Swift off Tailscale's goroutines.
func (e *tsEngine) emitLoop() {
	for {
		select {
		case <-e.kick:
		case <-e.ctx.Done():
			return
		}
		msg := e.stateJSON()
		e.mu.Lock()
		same := msg == e.lastEmit
		e.lastEmit = msg
		e.mu.Unlock()
		if !same && e.cb != nil {
			e.cb.OnTailscaleState(msg)
		}
	}
}

func (e *tsEngine) stateJSON() string {
	e.mu.Lock()
	s := tailscaleStateJSON{State: e.state.String(), AuthURL: e.authURL, Error: e.lastErr}
	if rc := e.routerCfg; rc != nil {
		for _, a := range rc.LocalAddrs {
			s.Addresses = append(s.Addresses, a.Addr().String())
		}
	}
	e.mu.Unlock()
	if nm := e.lb.NetMap(); nm != nil && nm.SelfNode.Valid() {
		s.SelfName = strings.TrimSuffix(nm.SelfNode.Name(), ".")
	}
	s.Settings = e.path.networkSettings()
	b, _ := json.Marshal(s)
	return string(b)
}

// localAddr is this node's tailnet address of the given family.
func (e *tsEngine) localAddr(v4 bool) netip.Addr {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.routerCfg != nil {
		for _, a := range e.routerCfg.LocalAddrs {
			if a.Addr().Is4() == v4 {
				return a.Addr()
			}
		}
	}
	return netip.Addr{}
}

// rebuildNetState merges router and DNS config into the path's view.
func (e *tsEngine) rebuildNetState() {
	e.mu.Lock()
	st := &tailnetNetState{}
	if rc := e.routerCfg; rc != nil {
		st.addrs = append(st.addrs, rc.LocalAddrs...)
		st.routes = append(st.routes, rc.Routes...)
	}
	if dc := e.dnsCfg; dc != nil {
		st.dnsServers = append(st.dnsServers, dc.Nameservers...)
		for _, d := range dc.MatchDomains {
			st.match = append(st.match, strings.ToLower(d.WithoutTrailingDot()))
		}
		for _, d := range dc.SearchDomains {
			st.search = append(st.search, strings.ToLower(d.WithoutTrailingDot()))
		}
		st.allDomains = len(dc.Nameservers) > 0 && len(dc.MatchDomains) == 0
		if st.allDomains {
			// No match domains then; the search domains carry the MagicDNS
			// suffix, so tailnet names still bypass SSH rules.
			st.match = append(st.match, st.search...)
		}
	}
	e.mu.Unlock()
	e.path.setState(st)
	e.wake()
}

func (e *tsEngine) login() error {
	e.mu.Lock()
	e.lastErr = ""
	e.mu.Unlock()
	return e.lb.StartLoginInteractive(e.ctx)
}

func (e *tsEngine) logout() error {
	ctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
	defer cancel()
	return e.lb.Logout(ctx, ipnauth.Self)
}

type statusPeer struct {
	Name    string   `json:"name"`
	DNSName string   `json:"dnsName,omitempty"`
	OS      string   `json:"os,omitempty"`
	IPs     []string `json:"ips,omitempty"`
	Online  bool     `json:"online"`
}

type statusJSONOut struct {
	State          string       `json:"state"`
	AuthURL        string       `json:"authURL,omitempty"`
	Error          string       `json:"error,omitempty"`
	Tailnet        string       `json:"tailnet,omitempty"`
	MagicDNSSuffix string       `json:"magicDNSSuffix,omitempty"`
	Self           *statusPeer  `json:"self,omitempty"`
	Peers          []statusPeer `json:"peers,omitempty"`
	PeersTotal     int          `json:"peersTotal"`
	TUNDrops       int64        `json:"tunDrops"`
	Path           tailnetStats `json:"path"`
}

func toStatusPeer(name, dnsName, os string, ips []netip.Addr, online bool) statusPeer {
	p := statusPeer{Name: name, DNSName: strings.TrimSuffix(dnsName, "."), OS: os, Online: online}
	for _, ip := range ips {
		p.IPs = append(p.IPs, ip.String())
	}
	return p
}

func (e *tsEngine) statusJSON() string {
	st := e.lb.Status()
	e.mu.Lock()
	out := statusJSONOut{State: st.BackendState, AuthURL: e.authURL, Error: e.lastErr}
	e.mu.Unlock()
	if t := st.CurrentTailnet; t != nil {
		out.Tailnet = t.Name
		out.MagicDNSSuffix = t.MagicDNSSuffix
	}
	if s := st.Self; s != nil {
		p := toStatusPeer(s.HostName, s.DNSName, s.OS, s.TailscaleIPs, true)
		out.Self = &p
	}
	out.PeersTotal = len(st.Peer)
	for _, ps := range st.Peer {
		out.Peers = append(out.Peers, toStatusPeer(ps.HostName, ps.DNSName, ps.OS, ps.TailscaleIPs, ps.Online))
	}
	slices.SortFunc(out.Peers, func(a, b statusPeer) int {
		if a.Online != b.Online {
			if a.Online {
				return -1
			}
			return 1
		}
		return cmp.Compare(a.DNSName, b.DNSName)
	})
	if len(out.Peers) > maxStatusPeers {
		out.Peers = out.Peers[:maxStatusPeers]
	}
	out.TUNDrops = e.tun.drops.Load()
	out.Path = e.path.statsSnapshot()
	b, _ := json.Marshal(out)
	return string(b)
}

func (e *tsEngine) close() {
	e.closeOnce.Do(func() {
		if e.path != nil {
			e.path.setBackend(nil)
		}
		// Closed first so WireGuard's TUN reader and writer return at once.
		if e.tun != nil {
			e.tun.Close()
		}
		for i := len(e.closers) - 1; i >= 0; i-- {
			e.closers[i]()
		}
	})
}

// tsRouter receives the routes and addresses Tailscale wants on the OS.
type tsRouter struct{ e *tsEngine }

func (r *tsRouter) Up() error { return nil }

func (r *tsRouter) Set(cfg *router.Config) error {
	r.e.mu.Lock()
	if cfg == nil {
		r.e.routerCfg = nil
	} else {
		c := *cfg
		r.e.routerCfg = &c
	}
	r.e.mu.Unlock()
	r.e.rebuildNetState()
	return nil
}

func (r *tsRouter) Close() error { return nil }

// tsDNS receives the resolver configuration Tailscale wants on the OS.
type tsDNS struct{ e *tsEngine }

func (d *tsDNS) SetDNS(cfg dns.OSConfig) error {
	d.e.mu.Lock()
	c := cfg
	d.e.dnsCfg = &c
	d.e.mu.Unlock()
	d.e.rebuildNetState()
	return nil
}

func (d *tsDNS) SupportsSplitDNS() bool { return true }

func (d *tsDNS) GetBaseConfig() (dns.OSConfig, error) {
	return dns.OSConfig{}, dns.ErrGetBaseConfigNotSupported
}

func (d *tsDNS) Close() error { return nil }

// tsStateStore adapts the Swift keychain store to ipn.StateStore.
type tsStateStore struct{ s TailscaleStateStore }

func (t *tsStateStore) ReadState(id ipn.StateKey) ([]byte, error) {
	b, err := t.s.ReadState(string(id))
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, ipn.ErrStateNotExist
	}
	return b, nil
}

func (t *tsStateStore) WriteState(id ipn.StateKey, bs []byte) error {
	if bs == nil {
		bs = []byte{}
	}
	return t.s.WriteState(string(id), bs)
}
