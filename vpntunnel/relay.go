package vpntunnel

import (
	"fmt"
	"github.com/trzsz/tsshd/tsshd"
	"sync/atomic"
)

// Relay is a prepared outer tssh transport. It is private to this Go binding;
// no TrzszSSH/iosbridge handle crosses the runtime boundary.
type Relay struct {
	client *tsshd.SshUdpClient
	closed atomic.Bool
}

// PrepareRelay connects an already-spawned jump tsshd. configJSON uses the
// existing VPN server-info fields. Swift keeps bootstrap SSH alive until this
// returns, then uses EffectiveMTU when spawning target tsshd.
func PrepareRelay(configJSON string) (*Relay, error) {
	cfg, err := ParseConfig(configJSON)
	if err != nil {
		return nil, err
	}
	if cfg.TransportType != "tssh" {
		return nil, fmt.Errorf("relay requires tssh")
	}
	cfg.TSSHClientID = 0 // fresh attachable client, no shell on the relay
	client, err := connectTSSH(cfg, nil)
	if err != nil {
		return nil, fmt.Errorf("jump host UDP connection failed: %w", err)
	}
	return &Relay{client: client}, nil
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

func (r *Relay) Close() {
	if r == nil || !r.closed.CompareAndSwap(false, true) {
		return
	}
	if r.client != nil {
		_ = r.client.Close()
	}
}
