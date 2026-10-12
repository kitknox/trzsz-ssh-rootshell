package vpntunnel

import (
	"fmt"
	"github.com/trzsz/tsshd/tsshd"
	"sync/atomic"
)

// Relay is a prepared outer tssh transport. It is private to this Go binding;
// no TrzszSSH/iosbridge handle crosses the runtime boundary. A relay reached
// through another relay owns that parent and closes it after itself.
type Relay struct {
	client *tsshd.SshUdpClient
	parent *Relay
	closed atomic.Bool
}

// PrepareRelay connects an already-spawned jump tsshd. configJSON uses the
// existing VPN server-info fields. Swift keeps bootstrap SSH alive until this
// returns, then uses EffectiveMTU when spawning target tsshd.
func PrepareRelay(configJSON string) (*Relay, error) {
	return prepareRelay(configJSON, nil)
}

// PrepareRelayVia connects a later hop's tsshd through parent, which must
// stay open. Spawn that tsshd with --mtu parent.EffectiveMTU. On success the
// returned relay owns parent; on failure the caller still does.
func PrepareRelayVia(configJSON string, parent *Relay) (*Relay, error) {
	if parent == nil {
		return nil, fmt.Errorf("jump transport is not connected")
	}
	return prepareRelay(configJSON, parent)
}

func prepareRelay(configJSON string, parent *Relay) (*Relay, error) {
	cfg, err := ParseConfig(configJSON)
	if err != nil {
		return nil, err
	}
	if cfg.TransportType != "tssh" {
		return nil, fmt.Errorf("relay requires tssh")
	}
	cfg.TSSHClientID = 0 // fresh attachable client, no shell on the relay
	var proxy *tsshd.SshUdpClient
	if parent != nil {
		if proxy, err = parent.connectedClient(); err != nil {
			return nil, err
		}
		mtu, err := parent.EffectiveMTU(cfg.TSSHMTU, cfg.TSSHMode)
		if err != nil {
			return nil, err
		}
		if mtu != cfg.TSSHMTU {
			return nil, fmt.Errorf("relay MTU must match parent relay budget: %d", mtu)
		}
	}
	client, err := connectTSSH(cfg, proxy)
	if err != nil {
		return nil, fmt.Errorf("jump host UDP connection failed: %w", err)
	}
	return &Relay{client: client, parent: parent}, nil
}

func (r *Relay) connectedClient() (*tsshd.SshUdpClient, error) {
	if r == nil || r.closed.Load() || r.client == nil {
		return nil, fmt.Errorf("jump transport is closed")
	}
	return r.client, nil
}

func (r *Relay) EffectiveMTU(requested int, mode string) (int, error) {
	client, err := r.connectedClient()
	if err != nil {
		return 0, err
	}
	return resolveRelayMTU(requested, int(client.GetMaxDatagramSize()), mode)
}

// Close tears down this hop, then every parent toward the first relay.
func (r *Relay) Close() {
	if r == nil || !r.closed.CompareAndSwap(false, true) {
		return
	}
	if r.client != nil {
		_ = r.client.Close()
	}
	r.parent.Close()
}
