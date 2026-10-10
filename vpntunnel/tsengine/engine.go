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

package tsengine

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
)

// This is a trimmed copy of tsnet's bootstrap. tsnet can't be used directly:
// it always starts a log uploader and keeps its own router and DNS
// configurators.

const maxStatusPeers = 500

// StateStore persists the node's state (keys, profile). Swift backs it with
// the keychain or root-only files. ReadState returns empty data for a
// missing key.
type StateStore interface {
	ReadState(key string) ([]byte, error)
	WriteState(key string, value []byte) error
}

// Prefs are the preferences the user controls.
type Prefs struct {
	Hostname         string `json:"hostname,omitempty"`
	AcceptRoutes     bool   `json:"acceptRoutes,omitempty"`
	ExitNodeID       string `json:"exitNodeID,omitempty"`
	ExitNodeAllowLAN bool   `json:"exitNodeAllowLAN,omitempty"`
}

// Config starts an Engine. A nil Tun runs userspace netstack mode: no OS
// routes or DNS, and Dialer reaches the tailnet through netstack.
type Config struct {
	Logf     logger.Logf
	Prefs    Prefs
	StateDir string // scratch directory, no secrets
	Store    StateStore
	Tun      tun.Device
	Router   router.Router
	DNS      dns.OSConfigurator
	// OnChange runs on Tailscale goroutines after login state changes; it
	// must not block.
	OnChange func()
	// Started runs after the backend starts, before notifications are watched.
	Started func(*Engine)
}

// Engine is a running Tailscale backend.
type Engine struct {
	LB         *ipnlocal.LocalBackend
	Dialer     *tsdial.Dialer
	Netstack   *netstack.Impl
	DNSManager *dns.Manager
	NetMon     *netmon.Monitor
	Userspace  bool

	ctx      context.Context
	stop     context.CancelFunc
	onChange func()
	logf     logger.Logf
	wg       wgengine.Engine
	magic    *magicsock.Conn
	resetMu  sync.Mutex

	mu        sync.Mutex
	state     ipn.State
	authURL   string
	lastErr   string
	loginOnce bool // StartLoginInteractive already asked for this NeedsLogin

	stateVersion atomic.Int64
	closers      []func()
	closeOnce    sync.Once
}

// Start boots the backend and waits briefly for its first notification.
func Start(conf Config) (_ *Engine, reterr error) {
	logf := conf.Logf
	if logf == nil {
		logf = logger.Discard
	}
	if conf.Store == nil {
		return nil, fmt.Errorf("tailscale needs a state store")
	}
	e := &Engine{onChange: conf.OnChange, Userspace: conf.Tun == nil, logf: logf}
	e.ctx, e.stop = context.WithCancel(context.Background())
	defer func() {
		if reterr != nil {
			e.Close()
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
	e.NetMon = netMon
	e.closers = append(e.closers, func() { netMon.Close() })
	sys.Set(netMon)

	dialer := &tsdial.Dialer{Logf: logf}
	dialer.SetBus(sys.Bus.Get())
	e.Dialer = dialer
	wgConf := wgengine.Config{
		EventBus:      sys.Bus.Get(),
		NetMon:        netMon,
		Dialer:        dialer,
		SetSubsystem:  sys.Set,
		ControlKnobs:  sys.ControlKnobs(),
		HealthTracker: sys.HealthTracker.Get(),
		Metrics:       sys.UserMetricsRegistry(),
	}
	if conf.Tun != nil {
		wgConf.Tun, wgConf.Router, wgConf.DNS = conf.Tun, conf.Router, conf.DNS
	}
	eng, err := wgengine.NewUserspaceEngine(logf, wgConf)
	if err != nil {
		return nil, fmt.Errorf("wgengine: %w", err)
	}
	// LocalBackend.Shutdown closes the engine once it exists; until then
	// (a failed start) close it here. Not dialer.Close: it panics when
	// peerAPI is compiled out, and the engine owns its sockets.
	e.closers = append(e.closers, func() {
		if e.LB == nil {
			eng.Close()
		}
	})
	sys.Set(eng)
	e.wg, e.magic = eng, sys.MagicSock.Get()

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
	e.Netstack = ns
	e.DNSManager = sys.DNSManager.Get()
	if e.Userspace {
		ns.ProcessLocalIPs = true
		ns.ProcessSubnets = true
		dialer.UseNetstackForIP = func(ip netip.Addr) bool {
			_, ok := e.LB.PeerForIP(ip)
			return ok
		}
		dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			c, err := ns.DialContextTCPWithBind(ctx, e.SelfAddr(dst.Addr().Is4()), dst)
			if err != nil {
				return nil, err // not a typed nil
			}
			return c, nil
		}
		dialer.NetstackDialUDP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			c, err := ns.DialContextUDPWithBind(ctx, e.SelfAddr(dst.Addr().Is4()), dst)
			if err != nil {
				return nil, err
			}
			return c, nil
		}
	} else {
		// Netstack only answers 100.100.100.100 (MagicDNS); tailnet traffic
		// stays raw through the TUN.
		ns.ProcessLocalIPs = false
		ns.ProcessSubnets = false
	}

	sys.Set(ipn.StateStore(&stateStore{s: conf.Store, version: &e.stateVersion}))
	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, controlclient.LoginDefault|controlclient.LocalBackendStartKeyOSNeutral)
	if err != nil {
		return nil, fmt.Errorf("local backend: %w", err)
	}
	e.LB = lb
	// Backend first, unlike tsnet: its TUN close frees netstack writes stuck
	// behind a wedged WireGuard, which netstack's close would wait on.
	e.closers = append(e.closers, func() {
		lb.Shutdown()
		closeNetstack()
	})
	lb.SetVarRoot(dir)
	if err := ns.Start(lb); err != nil {
		return nil, fmt.Errorf("netstack start: %w", err)
	}

	prefs := ipn.NewPrefs()
	prefs.Hostname = conf.Prefs.Hostname
	prefs.WantRunning = true
	prefs.RouteAll = conf.Prefs.AcceptRoutes
	prefs.CorpDNS = true
	if err := lb.Start(ipn.Options{UpdatePrefs: prefs}); err != nil {
		return nil, fmt.Errorf("backend start: %w", err)
	}
	// Start keeps stored prefs; re-apply the ones the user controls.
	if err := e.SetPrefs(conf.Prefs); err != nil {
		logf("edit prefs: %v", err)
	}
	if conf.Started != nil {
		conf.Started(e)
	}

	ready := make(chan struct{})
	go lb.WatchNotifications(e.ctx, ipn.NotifyInitialState|ipn.NotifyNoNetMap,
		func() { close(ready) }, e.onNotify)
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
	}
	return e, nil
}

// Context ends when the engine closes.
func (e *Engine) Context() context.Context { return e.ctx }

// SetPrefs applies the user's preferences. The exit node is only honoured in
// userspace mode; the packet tunnel has no default route to give it.
func (e *Engine) SetPrefs(p Prefs) error {
	mp := &ipn.MaskedPrefs{
		Prefs:          ipn.Prefs{Hostname: p.Hostname, RouteAll: p.AcceptRoutes, CorpDNS: true, WantRunning: true},
		HostnameSet:    p.Hostname != "",
		RouteAllSet:    true,
		CorpDNSSet:     true,
		WantRunningSet: true,
	}
	if e.Userspace {
		mp.ExitNodeID = tailcfg.StableNodeID(p.ExitNodeID)
		mp.ExitNodeAllowLANAccess = p.ExitNodeAllowLAN
		mp.ExitNodeIDSet, mp.ExitNodeIPSet, mp.ExitNodeAllowLANAccessSet = true, true, true
	}
	_, err := e.LB.EditPrefs(mp)
	return err
}

func (e *Engine) onNotify(n *ipn.Notify) bool {
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
			if err := e.LB.StartLoginInteractive(e.ctx); err != nil {
				e.SetError(err)
			}
		}()
	}
	e.changed()
	return e.ctx.Err() == nil
}

func (e *Engine) changed() {
	if e.onChange != nil {
		e.onChange()
	}
}

// SetError records an error for the next state report.
func (e *Engine) SetError(err error) {
	e.mu.Lock()
	e.lastErr = err.Error()
	e.mu.Unlock()
	e.changed()
}

// State returns the backend state, the pending auth URL and the last error.
func (e *Engine) State() (state ipn.State, authURL, lastErr string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state, e.authURL, e.lastErr
}

// Login starts an interactive login; the URL arrives through State.
func (e *Engine) Login() error {
	e.mu.Lock()
	e.lastErr = ""
	e.mu.Unlock()
	return e.LB.StartLoginInteractive(e.ctx)
}

// Logout logs the node out and forgets its keys.
func (e *Engine) Logout() error {
	ctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
	defer cancel()
	return e.LB.Logout(ctx, ipnauth.Self)
}

// SelfAddr is this node's tailnet address of the given family, from the
// netmap.
func (e *Engine) SelfAddr(v4 bool) netip.Addr {
	if e.LB == nil {
		return netip.Addr{}
	}
	nm := e.LB.NetMap()
	if nm == nil {
		return netip.Addr{}
	}
	for _, p := range nm.GetAddresses().All() {
		if p.Addr().Is4() == v4 {
			return p.Addr()
		}
	}
	return netip.Addr{}
}

// Peer is one node in Status.
type Peer struct {
	ID             string   `json:"id,omitempty"`
	Name           string   `json:"name"`
	DNSName        string   `json:"dnsName,omitempty"`
	OS             string   `json:"os,omitempty"`
	IPs            []string `json:"ips,omitempty"`
	Online         bool     `json:"online"`
	ExitNodeOption bool     `json:"exitNodeOption,omitempty"`
}

// Status is the JSON both Swift sides decode as TailnetStatus.
type Status struct {
	State          string `json:"state"`
	AuthURL        string `json:"authURL,omitempty"`
	Error          string `json:"error,omitempty"`
	Tailnet        string `json:"tailnet,omitempty"`
	MagicDNSSuffix string `json:"magicDNSSuffix,omitempty"`
	Self           *Peer  `json:"self,omitempty"`
	Peers          []Peer `json:"peers,omitempty"`
	PeersTotal     int    `json:"peersTotal"`
	ExitNodeID     string `json:"exitNodeID,omitempty"`
	ExitNodeOnline bool   `json:"exitNodeOnline,omitempty"`
	StateVersion   int64  `json:"stateVersion"`
}

func toPeer(ps *ipnstate.PeerStatus, online bool) Peer {
	p := Peer{
		ID:             string(ps.ID),
		Name:           ps.HostName,
		DNSName:        strings.TrimSuffix(ps.DNSName, "."),
		OS:             ps.OS,
		Online:         online,
		ExitNodeOption: ps.ExitNodeOption,
	}
	for _, ip := range ps.TailscaleIPs {
		p.IPs = append(p.IPs, ip.String())
	}
	return p
}

// Status reports the node, its peers (online first, capped) and the exit node.
func (e *Engine) Status() Status {
	st := e.LB.Status()
	e.mu.Lock()
	out := Status{State: st.BackendState, AuthURL: e.authURL, Error: e.lastErr}
	e.mu.Unlock()
	out.StateVersion = e.stateVersion.Load()
	if t := st.CurrentTailnet; t != nil {
		out.Tailnet = t.Name
		out.MagicDNSSuffix = t.MagicDNSSuffix
	}
	if s := st.Self; s != nil {
		p := toPeer(s, true)
		out.Self = &p
	}
	if x := st.ExitNodeStatus; x != nil {
		out.ExitNodeID = string(x.ID)
		out.ExitNodeOnline = x.Online
	}
	out.PeersTotal = len(st.Peer)
	for _, ps := range st.Peer {
		out.Peers = append(out.Peers, toPeer(ps, ps.Online))
	}
	slices.SortFunc(out.Peers, func(a, b Peer) int {
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
	return out
}

// Ping sends a disco ping, which says whether the path is direct or DERP.
func (e *Engine) Ping(ctx context.Context, ip netip.Addr) (*ipnstate.PingResult, error) {
	return e.LB.Ping(ctx, ip, tailcfg.PingDisco, 0)
}

// Close shuts the backend down; it is safe to call more than once. It gives
// up after stuckTimeout, leaving a wedged shutdown running, so a new engine
// can start.
func (e *Engine) Close() {
	e.closeOnce.Do(func() {
		e.await("close", true, func() {
			for i := len(e.closers) - 1; i >= 0; i-- {
				e.closers[i]()
			}
		})
	})
}

// stateStore adapts StateStore to ipn.StateStore and counts writes, so
// Swift can tell when the node's state changed.
type stateStore struct {
	s       StateStore
	version *atomic.Int64
}

func (t *stateStore) ReadState(id ipn.StateKey) ([]byte, error) {
	b, err := t.s.ReadState(string(id))
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, ipn.ErrStateNotExist
	}
	return b, nil
}

func (t *stateStore) WriteState(id ipn.StateKey, bs []byte) error {
	if bs == nil {
		bs = []byte{}
	}
	if err := t.s.WriteState(string(id), bs); err != nil {
		return err
	}
	t.version.Add(1)
	return nil
}
