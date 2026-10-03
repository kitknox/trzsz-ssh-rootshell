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
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"runtime"

	"github.com/trzsz/tsshd/tsshd"
)

// The Tailscale API is exported from every slice. Only builds tagged
// rootshell_tailscale contain the engine; the rest return errTailscaleNotBuilt.

var errTailscaleNotBuilt = errors.New("vpntunnel: Tailscale is not available in this build")

const (
	// One Go heap holds WireGuard, the control client and (with SSH egress)
	// our netstack, beside Citadel's buffers in the same extension.
	tailnetHeapLimitBytes    = 30 * 1024 * 1024
	tailnetSSHHeapLimitBytes = 26 * 1024 * 1024
	tailnetGCPercent         = 75
)

// TailscaleStateStore persists the node's Tailscale state (keys, profile).
// Swift backs it with the keychain. ReadState returns empty data for a
// missing key.
type TailscaleStateStore interface {
	ReadState(key string) ([]byte, error)
	WriteState(key string, value []byte) error
}

// TailscaleCallback receives Tailscale state as JSON (tailscaleStateJSON)
// whenever the login state, address, routes or DNS change.
type TailscaleCallback interface {
	OnTailscaleState(stateJSON string)
}

// tailscaleConfigJSON is the optional "tailscale" object of the tunnel config.
type tailscaleConfigJSON struct {
	Hostname     string `json:"hostname,omitempty"`
	AcceptRoutes bool   `json:"acceptRoutes,omitempty"`
	StateDir     string `json:"stateDir,omitempty"` // scratch directory, no secrets
	// "tssh": SSH rules apply now; the tsshd egress attaches later
	// (TailscaleAttachTSSH). SSH egress uses socks5Address instead.
	Egress string `json:"egress,omitempty"`
}

// tailscaleStateJSON is what OnTailscaleState delivers.
type tailscaleStateJSON struct {
	State     string                `json:"state"`
	AuthURL   string                `json:"authURL,omitempty"`
	Error     string                `json:"error,omitempty"`
	SelfName  string                `json:"selfName,omitempty"`
	Addresses []string              `json:"addresses,omitempty"`
	Settings  tunnelNetworkSettings `json:"settings"`
}

// tailnetEngine is the running Tailscale backend.
type tailnetEngine interface {
	close()
	login() error
	logout() error
	statusJSON() string
}

var (
	globalTailnet     tailnetEngine
	globalTailnetPath *tailnetPath
)

// TailscaleSupported reports whether this slice contains the Tailscale engine.
func TailscaleSupported() bool { return tailscaleBuilt }

// StartTailscaleTunnel starts Tailscale mode. configJSON is a VPNTunnelConfig
// with transportType "tailscale" plus optional "tailscale" and "routing"
// objects; socks5Address enables SSH egress. Packets then flow through the
// usual InjectPacket / ReadPacket calls, and StopTunnel tears it down.
func StartTailscaleTunnel(configJSON string, store TailscaleStateStore, tsCallback TailscaleCallback, callback TunnelCallback) error {
	if !tailscaleBuilt {
		return errTailscaleNotBuilt
	}
	globalMu.Lock()
	defer globalMu.Unlock()
	if globalStack != nil {
		return fmt.Errorf("vpntunnel: tunnel already running")
	}
	cfg, err := ParseConfig(configJSON)
	if err != nil {
		return err
	}
	if cfg.TransportType != "tailscale" {
		return fmt.Errorf("vpntunnel: StartTailscaleTunnel needs transportType tailscale, got %q", cfg.TransportType)
	}
	var extra struct {
		Tailscale tailscaleConfigJSON `json:"tailscale"`
		Routing   routingConfigJSON   `json:"routing"`
	}
	if err := json.Unmarshal([]byte(configJSON), &extra); err != nil {
		return fmt.Errorf("vpntunnel: parse tailscale config: %w", err)
	}
	if store == nil {
		return fmt.Errorf("vpntunnel: tailscale needs a state store")
	}

	tsshEgress := extra.Tailscale.Egress == "tssh"
	// Capture restores these when it stops. Only iOS has the ~50 MB limit;
	// the macOS system extension runs uncapped.
	if runtime.GOOS == "ios" {
		limit := int64(tailnetHeapLimitBytes)
		if cfg.SOCKS5Address != "" || tsshEgress {
			limit = tailnetSSHHeapLimitBytes
		}
		setBaseMemoryLimits(limit, tailnetGCPercent)
	} else {
		setBaseMemoryLimits(sshHeapLimitBytes, sshGCPercent)
	}

	cfg.MTU = tailnetMTU
	stats := &tunnelStats{}
	p := newTailnetPath(cfg, extra.Routing, tsshEgress, stats)
	eng, err := startTailnetEngine(p, extra.Tailscale, store, tsCallback)
	if err != nil {
		p.close()
		return fmt.Errorf("vpntunnel: start tailscale: %w", err)
	}

	// HTTP capture: idle until configured; the hook reroutes on changes.
	resetCaptureTunnelState(cfg.TransportType, nil)
	hook := p.refreshCapture
	captureRoutingHook.Store(&hook)
	if capture := initialCaptureConfig(configJSON); len(capture) > 0 && string(capture) != "null" {
		if err := applyCaptureConfig(capture); err != nil {
			log.Printf("vpntunnel: initial capture config: %v", err)
		}
	}

	globalStack = p
	globalStats = stats
	globalConfig = cfg
	globalCB = callback
	globalTailnet = eng
	globalTailnetPath = p
	if callback != nil {
		callback.OnTunnelReady()
	}
	log.Printf("vpntunnel: tailscale tunnel started (sshEgress=%v)", cfg.SOCKS5Address != "")
	return nil
}

func currentTailnet() (tailnetEngine, *tailnetPath) {
	globalMu.Lock()
	defer globalMu.Unlock()
	return globalTailnet, globalTailnetPath
}

// TailscaleAttachTSSH connects the TSSH egress of a Tailscale tunnel started
// with tailscale.egress "tssh". configJSON is a tssh VPNTunnelConfig built
// from tsshd's spawn output; relay, if non-nil, is a prepared jump relay that
// Go owns on success. Attaching again replaces the previous egress.
func TailscaleAttachTSSH(configJSON string, relay *Relay) error {
	_, p := currentTailnet()
	if p == nil {
		return fmt.Errorf("vpntunnel: tailscale is not running")
	}
	if !p.egressOn {
		return fmt.Errorf("vpntunnel: tailscale tunnel has no SSH egress")
	}
	cfg, err := ParseConfig(configJSON)
	if err != nil {
		return err
	}
	if cfg.TransportType != "tssh" {
		return fmt.Errorf("vpntunnel: TailscaleAttachTSSH needs transportType tssh, got %q", cfg.TransportType)
	}
	var proxy *tsshd.SshUdpClient
	if relay != nil {
		if proxy, err = relay.connectedClient(); err != nil {
			return err
		}
		mtu, err := relay.EffectiveMTU(cfg.TSSHMTU, cfg.TSSHMode)
		if err != nil {
			return err
		}
		if mtu != cfg.TSSHMTU {
			return fmt.Errorf("target MTU must match relay budget: %d", mtu)
		}
	}
	if cfg.TSSHRelayRequired && proxy == nil {
		return fmt.Errorf("tssh relay is required")
	}
	client, err := connectTSSH(cfg, proxy)
	if err != nil {
		return fmt.Errorf("vpntunnel: tssh connect: %w", err)
	}
	d := &tsshDialer{client: client}
	p.setEgress(&egressDialers{tcp: d, udp: d, close: func() {
		_ = client.Close()
		relay.Close()
	}}, int(client.GetMaxDatagramSize()) >= minQUICPayload)
	log.Printf("vpntunnel: tailscale tssh egress attached (datagram budget %d)", client.GetMaxDatagramSize())
	return nil
}

// TailscaleLogin starts an interactive login; the URL arrives through
// OnTailscaleState.
func TailscaleLogin() error {
	e, _ := currentTailnet()
	if e == nil {
		return fmt.Errorf("vpntunnel: tailscale is not running")
	}
	return e.login()
}

// TailscaleLogout logs the node out and forgets its keys.
func TailscaleLogout() error {
	e, _ := currentTailnet()
	if e == nil {
		return fmt.Errorf("vpntunnel: tailscale is not running")
	}
	return e.logout()
}

// TailscaleStatus returns JSON with the node, its peers and path counters.
func TailscaleStatus() string {
	e, _ := currentTailnet()
	if e == nil {
		return `{"state":"Stopped"}`
	}
	return e.statusJSON()
}

// TailscaleNetworkSettings returns the current tunnelNetworkSettings JSON.
func TailscaleNetworkSettings() string {
	_, p := currentTailnet()
	if p == nil {
		return "{}"
	}
	b, _ := json.Marshal(p.networkSettings())
	return string(b)
}

// TailscaleRoutesContain reports whether ip is reached over the tailnet, so
// Swift never excludes a tailnet SSH host from the tunnel.
func TailscaleRoutesContain(ip string) bool {
	_, p := currentTailnet()
	if p == nil {
		return false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return p.state.Load().routesContain(a)
}

// stopTailnetLocked tears down the engine; StopTunnel holds globalMu.
// Cancelling the path first unblocks WireGuard writes into the full
// outbound queue, which engine shutdown would otherwise wait on forever.
func stopTailnetLocked() {
	captureRoutingHook.Store(nil)
	if globalTailnetPath != nil {
		globalTailnetPath.cancel()
	}
	if globalTailnet != nil {
		globalTailnet.close()
		globalTailnet = nil
	}
	globalTailnetPath = nil
}
