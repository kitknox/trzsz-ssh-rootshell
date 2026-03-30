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

	ts, err := newTunnelStack(cfg, tcpDial, udpDial, stats)
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
