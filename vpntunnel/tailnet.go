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
	"context"
	"encoding/json"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/trzsz/trzsz-ssh/vpntunnel/tsengine"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/wgengine/router"
)

const tailscaleBuilt = true

// activeNetMon lets SetDirectInterface nudge Tailscale after a path change.
var activeNetMon atomic.Pointer[netmon.Monitor]

// noDefaultRouteIfName never names a real interface. netmon ignores "", so
// storing this is how the stale interface is cleared: lookups of it fail and
// Tailscale falls back to reading the routing table.
const noDefaultRouteIfName = "rootshell-none"

func tailnetInterfaceChanged(index int) {
	name := noDefaultRouteIfName
	if index > 0 {
		if ifc, err := net.InterfaceByIndex(index); err == nil {
			name = ifc.Name
		}
	}
	netmon.UpdateLastKnownDefaultRouteInterface(name)
	if m := activeNetMon.Load(); m != nil {
		m.InjectEvent()
	}
}

// tsEngine drives the shared engine behind the packet tunnel: the router and
// DNS configurators feed the path's view, and state goes to Swift.
type tsEngine struct {
	core *tsengine.Engine
	path *tailnetPath
	tun  *chanTUN
	cb   TailscaleCallback
	ctx  context.Context
	stop context.CancelFunc

	mu        sync.Mutex
	routerCfg *router.Config
	dnsCfg    *dns.OSConfig
	lastEmit  string

	kick      chan struct{}
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
	e.tun = newChanTUN(path)
	defer func() {
		if reterr != nil {
			e.close()
		}
	}()

	_, err := tsengine.Start(tsengine.Config{
		Logf:     logf,
		Prefs:    tsengine.Prefs{Hostname: conf.Hostname, AcceptRoutes: conf.AcceptRoutes},
		StateDir: conf.StateDir,
		Store:    store,
		Tun:      e.tun,
		Router:   &tsRouter{e: e},
		DNS:      &tsDNS{e: e},
		OnChange: e.wake,
		Started: func(core *tsengine.Engine) {
			activeNetMon.Store(core.NetMon)
			dnsManager := core.DNSManager
			path.tailscaleQuery = func(ctx context.Context, query []byte) ([]byte, error) {
				return dnsManager.Query(ctx, query, "tcp", netip.AddrPortFrom(e.localAddr(true), 0))
			}
			path.onCaptureChange = func(bool) { e.wake() }
			path.setBackend(e.tun)
			e.core = core
			go e.emitLoop()
		},
	})
	if err != nil {
		return nil, err
	}
	return e, nil
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
	state, authURL, lastErr := e.core.State()
	s := tailscaleStateJSON{State: state.String(), AuthURL: authURL, Error: lastErr}
	e.mu.Lock()
	if rc := e.routerCfg; rc != nil {
		for _, a := range rc.LocalAddrs {
			s.Addresses = append(s.Addresses, a.Addr().String())
		}
	}
	e.mu.Unlock()
	if nm := e.core.LB.NetMap(); nm != nil && nm.SelfNode.Valid() {
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

func (e *tsEngine) login() error  { return e.core.Login() }
func (e *tsEngine) logout() error { return e.core.Logout() }

type statusJSONOut struct {
	tsengine.Status
	TUNDrops int64        `json:"tunDrops"`
	Path     tailnetStats `json:"path"`
}

func (e *tsEngine) statusJSON() string {
	out := statusJSONOut{Status: e.core.Status(), TUNDrops: e.tun.drops.Load(), Path: e.path.statsSnapshot()}
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
		if e.core != nil {
			activeNetMon.CompareAndSwap(e.core.NetMon, nil)
			e.core.Close()
		}
		e.stop()
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
