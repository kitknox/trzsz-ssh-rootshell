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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trzsz/tsshd/tsshd"
)

// In-app Tailscale: the engine runs on a userspace netstack in this process,
// with no VPN. Only builds tagged rootshell_tailscale contain it; the rest
// report TailnetSupported() == false.

var errTailnetNotBuilt = errors.New("iosbridge: Tailscale is not available in this build")
var errTailnetNotRunning = errors.New("iosbridge: Tailscale is not running")

// TailnetStateStore persists the node's state. Swift backs it with the
// keychain. ReadState returns empty data for a missing key.
type TailnetStateStore interface {
	ReadState(key string) ([]byte, error)
	WriteState(key string, value []byte) error
}

// TailnetCallback receives status JSON (the TailnetStatus shape) whenever the
// login state changes.
type TailnetCallback interface {
	OnTailnetState(statusJSON string)
}

// tailnetConfig is TailnetStart's JSON.
type tailnetConfig struct {
	tailnetPrefs
	StateDir string `json:"stateDir,omitempty"` // scratch directory, no secrets
}

type tailnetPrefs struct {
	Hostname         string `json:"hostname,omitempty"`
	AcceptRoutes     bool   `json:"acceptRoutes,omitempty"`
	ExitNodeID       string `json:"exitNodeID,omitempty"`
	ExitNodeAllowLAN bool   `json:"exitNodeAllowLAN,omitempty"`
}

// tailnetBackend is the running engine (tailnet.go) or nothing (stub).
type tailnetBackend interface {
	close()
	login() error
	logout() error
	statusJSON() string
	setPrefs(tailnetPrefs) error
	running() bool
	// resolve returns the tailnet address for host, or false when host
	// isn't reached through the tailnet.
	resolve(ctx context.Context, host string) (netip.Addr, bool)
	dialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	// dialUDP returns a connection that keeps datagram boundaries. A
	// localPort > 0 binds that port on this node.
	dialUDP(ctx context.Context, dst netip.AddrPort, localPort uint16) (net.Conn, error)
	ping(ctx context.Context, ip netip.Addr) (tailnetPingResult, error)
}

type tailnetPingResult struct {
	IP        string  `json:"ip,omitempty"`
	NodeName  string  `json:"nodeName,omitempty"`
	LatencyMs float64 `json:"latencyMs,omitempty"`
	Endpoint  string  `json:"endpoint,omitempty"` // set for a direct path
	DERP      string  `json:"derp,omitempty"`     // region code when relayed
	Error     string  `json:"error,omitempty"`
}

var (
	tailnetMu  sync.Mutex
	tailnetCur tailnetBackend
)

func currentTailnetBackend() tailnetBackend {
	tailnetMu.Lock()
	defer tailnetMu.Unlock()
	return tailnetCur
}

// TailnetSupported reports whether this slice contains the engine.
func TailnetSupported() bool { return tailnetBuilt }

// TailnetStart starts the in-app engine. configJSON holds hostname,
// acceptRoutes, exitNodeID, exitNodeAllowLAN and stateDir.
func TailnetStart(configJSON string, store TailnetStateStore, callback TailnetCallback) error {
	if !tailnetBuilt {
		return errTailnetNotBuilt
	}
	var conf tailnetConfig
	if err := json.Unmarshal([]byte(configJSON), &conf); err != nil {
		return fmt.Errorf("iosbridge: parse tailnet config: %w", err)
	}
	if store == nil {
		return fmt.Errorf("iosbridge: tailnet needs a state store")
	}
	tailnetMu.Lock()
	defer tailnetMu.Unlock()
	if tailnetCur != nil {
		return fmt.Errorf("iosbridge: Tailscale is already running")
	}
	b, err := startTailnetBackend(conf, store, callback)
	if err != nil {
		return fmt.Errorf("iosbridge: start tailscale: %w", err)
	}
	tailnetCur = b
	return nil
}

// TailnetStop shuts the engine down. Open tailnet connections end.
func TailnetStop() {
	tailnetMu.Lock()
	b := tailnetCur
	tailnetCur = nil
	tailnetMu.Unlock()
	if b != nil {
		b.close()
	}
}

// TailnetRunning reports whether the engine is up and signed in.
func TailnetRunning() bool {
	b := currentTailnetBackend()
	return b != nil && b.running()
}

// TailnetLogin starts an interactive login; the URL arrives in status.
func TailnetLogin() error {
	b := currentTailnetBackend()
	if b == nil {
		return errTailnetNotRunning
	}
	return b.login()
}

// TailnetLogout logs the node out and forgets its keys.
func TailnetLogout() error {
	b := currentTailnetBackend()
	if b == nil {
		return errTailnetNotRunning
	}
	return b.logout()
}

// TailnetStatus returns the TailnetStatus JSON.
func TailnetStatus() string {
	b := currentTailnetBackend()
	if b == nil {
		return `{"state":"Stopped","peersTotal":0,"stateVersion":0}`
	}
	return b.statusJSON()
}

// TailnetSetPrefs applies hostname, acceptRoutes and the exit node.
func TailnetSetPrefs(prefsJSON string) error {
	b := currentTailnetBackend()
	if b == nil {
		return errTailnetNotRunning
	}
	var p tailnetPrefs
	if err := json.Unmarshal([]byte(prefsJSON), &p); err != nil {
		return fmt.Errorf("iosbridge: parse tailnet prefs: %w", err)
	}
	return b.setPrefs(p)
}

const tailnetResolveTimeout = 5 * time.Second

// tailnetRoute resolves host when the running engine reaches it.
func tailnetRoute(host string) (tailnetBackend, netip.Addr, bool) {
	b := currentTailnetBackend()
	if b == nil || !b.running() {
		return nil, netip.Addr{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), tailnetResolveTimeout)
	defer cancel()
	addr, ok := b.resolve(ctx, strings.Trim(host, "[]"))
	return b, addr, ok
}

// TailnetResolve returns the address host is reached at over the tailnet, or
// "" when it isn't (Swift then uses the OS).
func TailnetResolve(host string) string {
	if _, addr, ok := tailnetRoute(host); ok {
		return addr.String()
	}
	return ""
}

func tailnetTarget(host string, port int) (tailnetBackend, netip.AddrPort, error) {
	if port <= 0 || port > 65535 {
		return nil, netip.AddrPort{}, fmt.Errorf("invalid port %d", port)
	}
	b, addr, ok := tailnetRoute(host)
	if !ok {
		if currentTailnetBackend() == nil {
			return nil, netip.AddrPort{}, errTailnetNotRunning
		}
		return nil, netip.AddrPort{}, fmt.Errorf("%s is not reachable through Tailscale", host)
	}
	return b, netip.AddrPortFrom(addr, uint16(port)), nil
}

func timeoutContext(ms int) (context.Context, context.CancelFunc) {
	if ms <= 0 {
		ms = 30_000
	}
	return context.WithTimeout(context.Background(), time.Duration(ms)*time.Millisecond)
}

// TailnetDialTCP connects to host:port over the tailnet and returns a
// stream socket carrying the connection. The caller owns and closes it.
func TailnetDialTCP(host string, port int, timeoutMs int) (int, error) {
	b, dst, err := tailnetTarget(host, port)
	if err != nil {
		return -1, err
	}
	ctx, cancel := timeoutContext(timeoutMs)
	defer cancel()
	conn, err := b.dialTCP(ctx, dst)
	if err != nil {
		return -1, fmt.Errorf("dial %s over Tailscale: %w", dst, err)
	}
	return streamFD(conn)
}

// TailnetDialUDP opens a UDP flow to host:remotePort over the tailnet and
// returns a connected datagram socket for it. localPort > 0 binds that port
// on this node (VNC media expects replies on the port it offered).
func TailnetDialUDP(host string, remotePort int, localPort int, timeoutMs int) (int, error) {
	b, dst, err := tailnetTarget(host, remotePort)
	if err != nil {
		return -1, err
	}
	if localPort < 0 || localPort > 65535 {
		return -1, fmt.Errorf("invalid local port %d", localPort)
	}
	ctx, cancel := timeoutContext(timeoutMs)
	defer cancel()
	conn, err := b.dialUDP(ctx, dst, uint16(localPort))
	if err != nil {
		return -1, fmt.Errorf("udp %s over Tailscale: %w", dst, err)
	}
	return datagramFD(conn)
}

// TailnetPing sends a Tailscale (disco) ping and returns tailnetPingResult
// JSON: latency plus a direct endpoint or the DERP region.
func TailnetPing(host string, timeoutMs int) string {
	b, dst, err := tailnetTarget(host, 1)
	out := tailnetPingResult{}
	if err == nil {
		ctx, cancel := timeoutContext(timeoutMs)
		out, err = b.ping(ctx, dst.Addr())
		cancel()
	}
	if err != nil {
		out.Error = err.Error()
	}
	js, _ := json.Marshal(out)
	return string(js)
}

// tailnetOrDirectDial dials over the tailnet when the engine reaches host,
// and directly otherwise. Used by the loopback proxy.
func tailnetOrDirectDial(ctx context.Context, host string, port int) (net.Conn, error) {
	if b, addr, ok := tailnetRoute(host); ok {
		return b.dialTCP(ctx, netip.AddrPortFrom(addr, uint16(port)))
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

// tailnetPacketSize keeps KCP/QUIC packets inside the tailnet's 1280 MTU.
const tailnetPacketSize = 1200

// useTailnetForTransport sends tsshd's UDP/TCP path over the tailnet whenever
// the engine reaches the host. Every (re)connect routes again, so a session
// created before the engine came up moves onto it at its next reconnect.
func useTailnetForTransport(opts *tsshd.UdpClientOptions, host string) {
	if !tailnetBuilt {
		return
	}
	if _, _, ok := tailnetRoute(host); ok {
		opts.MaxPacketSize = tailnetPacketSize
	}
	dial := func(udp bool) func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return func(_, addr string, timeout time.Duration) (net.Conn, error) {
			h, p, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, err := strconv.ParseUint(p, 10, 16)
			if err != nil {
				return nil, err
			}
			b, ip, ok := tailnetRoute(h)
			if !ok {
				return nil, nil // the OS dial
			}
			dst := netip.AddrPortFrom(ip, uint16(port))
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if udp {
				return b.dialUDP(ctx, dst, 0)
			}
			return b.dialTCP(ctx, dst)
		}
	}
	opts.DialTCP = dial(false)
	opts.DialUDP = dial(true)
}
