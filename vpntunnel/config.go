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
	"fmt"
)

// VPNTunnelConfig is the JSON-serializable configuration for the VPN tunnel.
// Shared between the Swift main app and the Go netstack layer.
type VPNTunnelConfig struct {
	// TransportType selects the SSH transport: "ssh" or "tssh"
	TransportType string `json:"transportType"`

	// TSSH-specific fields (used when TransportType == "tssh")
	// These come from tsshd's JSON spawn output, parsed by the Swift extension.
	TSSHHost       string `json:"tsshHost,omitempty"`
	TSSHPort       int    `json:"tsshPort,omitempty"`
	TSSHMode       string `json:"tsshMode,omitempty"`       // "KCP" or "QUIC"
	TSSHServerVer  string `json:"tsshServerVer,omitempty"`  // tsshd version (e.g., "v1.0")
	TSSHPass       string `json:"tsshPass,omitempty"`       // KCP: hex-encoded password
	TSSHSalt       string `json:"tsshSalt,omitempty"`       // KCP: hex-encoded salt
	TSSHServerCert string `json:"tsshServerCert,omitempty"` // QUIC: hex-encoded server cert
	TSSHClientCert string `json:"tsshClientCert,omitempty"` // QUIC: hex-encoded client cert
	TSSHClientKey  string `json:"tsshClientKey,omitempty"`  // QUIC: hex-encoded client key
	TSSHProxyKey   string `json:"tsshProxyKey,omitempty"`   // hex-encoded proxy key
	TSSHClientID   uint64 `json:"tsshClientID,omitempty"`
	TSSHServerID   uint64 `json:"tsshServerID,omitempty"`

	// SSH-specific fields (used when TransportType == "ssh")
	// The SOCKS5 proxy runs on localhost in the extension process.
	SOCKS5Address string `json:"socks5Address,omitempty"` // e.g., "127.0.0.1:1080"

	// TSSH packet MTU (separate from TUN device MTU)
	// Zero means use default (1400). Both client and server must match.
	TSSHMTU int `json:"trzszMTU,omitempty"`

	// Shared fields
	DNSServers     []string `json:"dnsServers,omitempty"`
	ExcludedRoutes []string `json:"excludedRoutes,omitempty"` // CIDRs to exclude
	MTU            int      `json:"mtu,omitempty"`

	// BlockQUIC rejects new UDP flows to port 443 with ICMP port-unreachable
	// so browsers fall back to HTTP/2 immediately. Also auto-enabled when the
	// transport's datagram budget is too small to carry QUIC packets.
	BlockQUIC bool `json:"blockQUIC,omitempty"`
}

// ParseConfig deserializes a JSON config string into VPNTunnelConfig.
func ParseConfig(configJSON string) (*VPNTunnelConfig, error) {
	var cfg VPNTunnelConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, fmt.Errorf("vpntunnel: parse config: %w", err)
	}
	if cfg.TransportType != "ssh" && cfg.TransportType != "tssh" {
		return nil, fmt.Errorf("vpntunnel: invalid transport type: %q", cfg.TransportType)
	}
	// MTU <= 0 means "auto-resolve from transport" for TSSH.
	// The default (1500) is applied in StartTunnel after auto-resolution.
	return &cfg, nil
}
