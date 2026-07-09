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
	"fmt"
	"io"
	"log"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trzsz/tsshd/tsshd"
)

// DebugLogger receives debug messages from the VPN tunnel.
// Implement this in Swift to capture tsshd and tunnel diagnostics.
type DebugLogger interface {
	OnDebug(msg string)
}

var globalDebugLogger struct {
	sync.RWMutex
	logger DebugLogger
}

// SetDebugLogger sets the global debug logger for VPN tunnel diagnostics.
// Call before StartTunnel(). Pass nil to disable.
func SetDebugLogger(logger DebugLogger) {
	globalDebugLogger.Lock()
	defer globalDebugLogger.Unlock()
	globalDebugLogger.logger = logger
	if logger != nil {
		log.SetOutput(&debugLogWriter{logger: logger})
	} else {
		log.SetOutput(io.Discard)
	}
}

func getDebugLogger() DebugLogger {
	globalDebugLogger.RLock()
	defer globalDebugLogger.RUnlock()
	return globalDebugLogger.logger
}

// debugLogWriter adapts a DebugLogger to io.Writer for log.SetOutput().
type debugLogWriter struct {
	logger DebugLogger
}

func (w *debugLogWriter) Write(p []byte) (n int, err error) {
	w.logger.OnDebug(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

const (
	// Keep Go heap conservative inside NEPacketTunnelProvider's tight memory budget.
	// Use stricter limits for TSSH and looser limits for SOCKS5/SSH mode.
	tsshHeapLimitBytes = 34 * 1024 * 1024
	tsshGCPercent      = 90
	sshHeapLimitBytes  = -1 // rely on socket buffer caps for SSH memory control
	sshGCPercent       = 100
)

const (
	// IPv4 header (20) + UDP header (8): overhead between TUN MTU and the
	// inner UDP payload the tunnel actually relays.
	ipv4Overhead = 28
	// Minimum viable TUN MTU (IPv6 minimum link MTU).
	minTunMTU = 1280
	// QUIC requires paths that carry 1200-byte UDP payloads.
	minQUICPayload = 1200
)

// TunnelCallback is the gomobile interface for receiving tunnel events.
// Implement this in Swift to get notified of tunnel state changes.
type TunnelCallback interface {
	OnTunnelReady()
	OnTunnelError(message string)
	OnTunnelDisconnected(reason string)
	OnStatsUpdate(bytesIn int64, bytesOut int64, activeConns int)
}

// Global tunnel state (only one tunnel active at a time, per NEPacketTunnelProvider).
var (
	globalMu     sync.Mutex
	globalStack  *tunnelStack
	globalStats  *tunnelStats
	globalConfig *VPNTunnelConfig
	globalCB     TunnelCallback
	globalClient *tsshd.SshUdpClient // TSSH client (nil for SSH mode)
)

// StartTunnel initializes the netstack and starts processing packets.
// configJSON is a serialized VPNTunnelConfig.
// callback receives tunnel lifecycle events.
func StartTunnel(configJSON string, callback TunnelCallback) error {
	globalMu.Lock()
	defer globalMu.Unlock()

	if globalStack != nil {
		return fmt.Errorf("vpntunnel: tunnel already running")
	}

	cfg, err := ParseConfig(configJSON)
	if err != nil {
		return err
	}

	// Tune GC for extension memory constraints to reduce OOM terminations.
	if cfg.TransportType == "tssh" {
		debug.SetMemoryLimit(tsshHeapLimitBytes)
		debug.SetGCPercent(tsshGCPercent)
	} else {
		debug.SetMemoryLimit(sshHeapLimitBytes)
		debug.SetGCPercent(sshGCPercent)
	}

	stats := &tunnelStats{}
	globalStats = stats
	globalConfig = cfg
	globalCB = callback

	var tcpDial tcpDialer
	var udpDial udpDialer
	var datagramBudget int // transport max datagram payload (0 = no datagram path)

	switch cfg.TransportType {
	case "tssh":
		// Connect via tsshd (KCP/QUIC)
		c, err := connectTSSH(cfg)
		if err != nil {
			return fmt.Errorf("vpntunnel: tssh connect: %w", err)
		}
		globalClient = c
		d := &tsshDialer{client: c}
		tcpDial = d
		udpDial = d
		datagramBudget = int(c.GetMaxDatagramSize())

		// Auto-resolve TUN MTU from the transport's max datagram size.
		// The tunnel relays only the inner UDP payload (gVisor terminates
		// IP/UDP), so a full-MTU IPv4 UDP packet yields payload = MTU-28.
		// Sizing TUN = budget+28 means steady-state datagrams always fit
		// without the reliable-stream fallback. QUIC needs 1200-byte UDP
		// payloads; if the budget can't carry them, clamp to the minimum
		// viable TUN MTU and block QUIC so browsers get an immediate ICMP
		// refusal and fall back to HTTP/2 instead of black-holing.
		if cfg.MTU <= 0 {
			if maxDG := datagramBudget; maxDG > 0 {
				if maxDG >= minQUICPayload {
					cfg.MTU = max(maxDG+ipv4Overhead, minTunMTU)
					log.Printf("vpntunnel: auto-resolved TUN MTU=%d from transport datagram budget %d", cfg.MTU, maxDG)
				} else {
					cfg.MTU = minTunMTU
					cfg.BlockQUIC = true
					log.Printf("vpntunnel: transport datagram budget %d < %d, too small for QUIC; blocking UDP 443 (HTTP/2 fallback). Increase tsshd --mtu to at least 1297 (QUIC) / 1300 (KCP) for HTTP/3", maxDG, minQUICPayload)
				}
			} else {
				cfg.MTU = 1500
				log.Printf("vpntunnel: transport returned 0 max datagram size, falling back to TUN MTU=%d", cfg.MTU)
			}
		}

	case "ssh":
		// Use SOCKS5 proxy for TCP; no native UDP
		if cfg.SOCKS5Address == "" {
			return fmt.Errorf("vpntunnel: ssh mode requires socks5Address")
		}
		tcpDial = &socks5Dialer{proxyAddr: cfg.SOCKS5Address}
		udpDial = nil // no UDP for SSH

	default:
		return fmt.Errorf("vpntunnel: unsupported transport: %s", cfg.TransportType)
	}

	// Final fallback: if MTU is still unset (SSH mode or auto-resolve failed), default to 1500.
	if cfg.MTU <= 0 {
		cfg.MTU = 1500
	}

	ts, err := newTunnelStack(cfg, tcpDial, udpDial, stats, datagramBudget)
	if err != nil {
		if globalClient != nil {
			globalClient.Close()
			globalClient = nil
		}
		return fmt.Errorf("vpntunnel: create stack: %w", err)
	}
	globalStack = ts

	if callback != nil {
		callback.OnTunnelReady()
	}
	log.Printf("vpntunnel: tunnel started (transport=%s)", cfg.TransportType)

	return nil
}

// StopTunnel tears down the tunnel.
func StopTunnel() error {
	globalMu.Lock()
	defer globalMu.Unlock()

	if globalStack == nil {
		return nil
	}

	// Close TSSH client FIRST to send exit signal to tsshd before
	// the potentially-blocking netstack teardown (wg.Wait).
	// The client uses direct UDP (excluded from VPN routes) and
	// doesn't depend on the netstack.
	if globalClient != nil {
		globalClient.Close()
		globalClient = nil
	}

	globalStack.close()
	globalStack = nil

	if globalCB != nil {
		globalCB.OnTunnelDisconnected("user requested stop")
		globalCB = nil
	}

	globalStats = nil
	globalConfig = nil
	debug.FreeOSMemory()
	log.Printf("vpntunnel: tunnel stopped")

	return nil
}

// InjectPacket feeds an IP packet from NEPacketTunnelProvider into netstack.
// family: AF_INET=2 for IPv4, AF_INET6=30 (Darwin) for IPv6.
func InjectPacket(data []byte, family int) {
	globalMu.Lock()
	ts := globalStack
	globalMu.Unlock()

	if ts != nil {
		ts.injectPacket(data, family)
	}
}

// PacketResult holds a single outbound IP packet and its protocol family.
// gomobile requires structured returns instead of multiple return values.
type PacketResult struct {
	Data   []byte
	Family int
}

// ReadPacket returns the next outbound IP packet from netstack.
// This blocks until a packet is available or the tunnel is stopped.
// Returns nil when the tunnel is torn down.
// Family is AF_INET (2) or AF_INET6 (30 on Darwin).
func ReadPacket() *PacketResult {
	globalMu.Lock()
	ts := globalStack
	globalMu.Unlock()

	if ts == nil {
		return nil
	}
	data, family := ts.readPacket()
	if data == nil {
		return nil
	}
	return &PacketResult{Data: data, Family: family}
}

// ReadPacketNonBlocking returns the next outbound IP packet without blocking.
// Returns nil immediately if no packet is queued or the tunnel is stopped.
func ReadPacketNonBlocking() *PacketResult {
	globalMu.Lock()
	ts := globalStack
	globalMu.Unlock()

	if ts == nil {
		return nil
	}
	data, family := ts.readPacketNonBlocking()
	if data == nil {
		return nil
	}
	return &PacketResult{Data: data, Family: family}
}

// GetStatus returns JSON status including connected state and byte counters.
func GetStatus() string {
	globalMu.Lock()
	stats := globalStats
	cfg := globalConfig
	connected := globalStack != nil
	globalMu.Unlock()

	if stats == nil {
		return `{"connected":false}`
	}

	transportType := ""
	if cfg != nil {
		transportType = cfg.TransportType
	}
	return stats.toStatus(connected, transportType)
}

// GetEffectiveMTU returns the resolved TUN device MTU after StartTunnel.
// Returns 0 if the tunnel is not running.
func GetEffectiveMTU() int {
	globalMu.Lock()
	defer globalMu.Unlock()
	if globalConfig != nil {
		return globalConfig.MTU
	}
	return 0
}

// connectTSSH establishes a tsshd client connection using the config parameters.
// The VPN extension spawns tsshd via SSH, parses the JSON output, and passes
// all server info fields through VPNTunnelConfig.
func connectTSSH(cfg *VPNTunnelConfig) (*tsshd.SshUdpClient, error) {
	serverInfo := &tsshd.ServerInfo{
		ServerVer:  cfg.TSSHServerVer,
		Port:       cfg.TSSHPort,
		Mode:       cfg.TSSHMode,
		Pass:       cfg.TSSHPass,
		Salt:       cfg.TSSHSalt,
		ServerCert: cfg.TSSHServerCert,
		ClientCert: cfg.TSSHClientCert,
		ClientKey:  cfg.TSSHClientKey,
		ProxyKey:   cfg.TSSHProxyKey,
		ClientID:   cfg.TSSHClientID,
		ServerID:   cfg.TSSHServerID,
	}

	host := strings.TrimPrefix(cfg.TSSHHost, "[")
	host = strings.TrimSuffix(host, "]")
	addr := net.JoinHostPort(host, strconv.Itoa(cfg.TSSHPort))

	// VPN extension runs as a system daemon — use regular UDP sockets
	// (unlike the main app which uses in-process pipes because UDP dies on background).
	if cfg.TSSHMTU > 0 {
		serverInfo.MTU = uint16(cfg.TSSHMTU)
	}
	opts := &tsshd.UdpClientOptions{
		EnableWarning:    true,
		TsshdAddr:        addr,
		ServerInfo:       serverInfo,
		ConnectTimeout:   30 * time.Second,
		AliveTimeout:     24 * time.Hour,
		HeartbeatTimeout: 3 * time.Second,
		IntervalTime:     1 * time.Second,
	}

	if dl := getDebugLogger(); dl != nil {
		opts.EnableDebugging = true
		opts.DebugFunc = func(msec int64, msg string) {
			dl.OnDebug(fmt.Sprintf("[vpntunnel tsshd] %s", msg))
		}
		opts.WarningFunc = func(msg string) {
			dl.OnDebug(fmt.Sprintf("[vpntunnel tsshd WARN] %s", msg))
		}
	} else {
		opts.WarningFunc = func(msg string) {
			log.Printf("vpntunnel tssh: %s", msg)
		}
	}

	c, err := tsshd.NewSshUdpClient(opts)
	if err != nil {
		return nil, fmt.Errorf("tssh client connect to %s: %w", addr, err)
	}

	return c, nil
}
