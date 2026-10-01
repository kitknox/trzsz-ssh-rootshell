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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultMaxBodyBytes    = 10 << 20
	defaultMaxSessionBytes = 500 << 20
	pinnedEmptyThreshold   = 2
	pinnedEmptyWindow      = 60 * time.Second
)

// captureConfig is the JSON accepted by CaptureConfigure and the "capture"
// field of the tunnel config. Mirrored by Swift's CaptureEngineConfig.
type captureConfig struct {
	Enabled            bool          `json:"enabled"`
	SessionID          string        `json:"sessionID"`
	SegmentNonce       string        `json:"segmentNonce"`
	SpoolDir           string        `json:"spoolDir"`
	MITMHosts          []string      `json:"mitmHosts"`
	CACertPEM          string        `json:"caCertPEM"`
	CAKeyPEM           string        `json:"caKeyPEM"`
	CAProfileB64       string        `json:"caProfileB64"`
	EnableH2           bool          `json:"enableH2"`
	SkipUpstreamVerify bool          `json:"skipUpstreamVerify"`
	AutoBypassPinned   bool          `json:"autoBypassPinned"`
	MaxBodyBytes       int64         `json:"maxBodyBytes"`
	MaxSessionBytes    int64         `json:"maxSessionBytes"`
	Pcap               bool          `json:"pcap"`
	RewriteRules       []rewriteRule `json:"rewriteRules"`
}

// captureState is an immutable snapshot swapped atomically on reconfigure.
type captureState struct {
	cfg       captureConfig
	hosts     *hostMatcher
	minter    *certMinter // nil without a CA
	rec       *recorder   // nil unless recording
	rewrites  *rewriteSet
	caProfile []byte
	mitmSem   chan struct{}
}

func (cs *captureState) recording() bool {
	return cs != nil && cs.cfg.Enabled && cs.rec.isActive()
}

// captureEnv is tunnel-scoped state that outlives config changes.
type captureEnv struct {
	transport string
	flows     *flowRegistry
	dns       *dnsCache
	udp       *udpForwarder
	blocking  atomic.Bool // QUIC + HTTPS-RR blocking while recording

	bypass   sync.Map // host → struct{}: clients that rejected our cert
	emptyMu  sync.Mutex
	empty    map[string][]time.Time
	mitmLive atomic.Int32
	overflow atomic.Int64
}

var (
	captureMu     sync.Mutex // serializes configure / stop
	captureCur    atomic.Pointer[captureState]
	captureEnvPtr atomic.Pointer[captureEnv]
)

func currentCaptureEnv() *captureEnv { return captureEnvPtr.Load() }

// resetCaptureTunnelState is called once per tunnel start.
func resetCaptureTunnelState(transport string, ts *tunnelStack) {
	env := &captureEnv{
		transport: transport,
		flows:     newFlowRegistry(),
		dns:       newDNSCache(),
		empty:     make(map[string][]time.Time),
	}
	if ts != nil {
		env.udp = ts.udpFwd
	}
	captureEnvPtr.Store(env)
}

func applyCaptureConfig(raw []byte) error {
	var cfg captureConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("capture config: %w", err)
	}
	env := currentCaptureEnv()
	if env == nil {
		return errors.New("capture config: tunnel not running")
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = defaultMaxBodyBytes
	}
	if cfg.MaxSessionBytes <= 0 {
		cfg.MaxSessionBytes = defaultMaxSessionBytes
	}

	captureMu.Lock()
	defer captureMu.Unlock()
	prev := captureCur.Load()

	next := &captureState{
		cfg:      cfg,
		hosts:    compileHostRules(cfg.MITMHosts),
		rewrites: compileRewriteRules(cfg.RewriteRules),
		mitmSem:  make(chan struct{}, mitmFlowCap(env.transport)),
	}
	if cfg.CAProfileB64 != "" {
		next.caProfile, _ = base64.StdEncoding.DecodeString(cfg.CAProfileB64)
	}
	if cfg.CACertPEM != "" {
		if prev != nil && prev.minter != nil && prev.minter.caPEM == cfg.CACertPEM {
			next.minter = prev.minter
		} else if m, err := newCertMinter(cfg.CACertPEM, cfg.CAKeyPEM); err == nil {
			next.minter = m
		} else {
			log.Printf("vpntunnel: %v", err)
		}
	}
	if prev != nil && prev.mitmSem != nil && cap(prev.mitmSem) == cap(next.mitmSem) {
		next.mitmSem = prev.mitmSem
	}

	sameSegment := prev != nil && prev.rec != nil &&
		prev.rec.sessionID == cfg.SessionID && prev.rec.nonce == cfg.SegmentNonce
	if cfg.Enabled && cfg.SessionID != "" && cfg.SpoolDir != "" {
		if sameSegment {
			next.rec = prev.rec
		} else {
			if prev != nil && prev.rec != nil {
				prev.rec.close("segmentEnd", "reconfigured")
			}
			rec, err := newRecorder(cfg.SpoolDir, cfg.SessionID, cfg.SegmentNonce, cfg.MaxBodyBytes, cfg.MaxSessionBytes, env.transport)
			if err != nil {
				next.cfg.Enabled = false
				captureCur.Store(next)
				applyCaptureMemoryLimits(env.transport, false)
				env.blocking.Store(false)
				return err
			}
			next.rec = rec
		}
		if next.rec != nil {
			next.rec.maxBody.Store(cfg.MaxBodyBytes)
			next.rec.maxSession.Store(cfg.MaxSessionBytes)
		}
	} else {
		next.cfg.Enabled = false
		if prev != nil && prev.rec != nil {
			prev.rec.close("stop", "user")
		}
	}

	captureCur.Store(next)
	env.blocking.Store(next.cfg.Enabled)
	applyCaptureMemoryLimits(env.transport, next.cfg.Enabled)
	return nil
}

// closeCapture ends recording. final=true means the session is over; false
// means the tunnel is going away and a later segment may continue it.
func closeCapture(reason string, final bool) {
	captureMu.Lock()
	defer captureMu.Unlock()
	cs := captureCur.Load()
	if cs == nil {
		if !final {
			captureEnvPtr.Store(nil)
		}
		return
	}
	kind := "segmentEnd"
	if final {
		kind = "stop"
	}
	cs.rec.close(kind, reason)
	if final {
		next := *cs
		next.cfg.Enabled = false
		next.rec = nil
		captureCur.Store(&next)
	} else {
		captureCur.Store(nil)
	}
	if env := currentCaptureEnv(); env != nil {
		env.blocking.Store(false)
		applyCaptureMemoryLimits(env.transport, false)
	}
	if !final {
		captureEnvPtr.Store(nil)
	}
}

// capturePacket records a TUN packet when pcap capture is on. dir: 0 = from
// apps into the tunnel, 1 = from the tunnel back to apps.
func capturePacket(dir byte, data []byte) {
	cs := captureCur.Load()
	if cs == nil || !cs.cfg.Pcap || !cs.recording() {
		return
	}
	cs.rec.packet(dir, data)
}

func captureBlocking() bool {
	env := currentCaptureEnv()
	return env != nil && env.blocking.Load()
}

func (e *captureEnv) isBypassed(host string) bool {
	_, ok := e.bypass.Load(host)
	return ok
}

// noteEmptyMITM counts intercepted connections that closed right after the
// handshake without a request, which is how pinning apps usually fail.
// Returns true when the host crosses the threshold.
func (e *captureEnv) noteEmptyMITM(host string) bool {
	e.emptyMu.Lock()
	defer e.emptyMu.Unlock()
	now := time.Now()
	var kept []time.Time
	for _, t := range e.empty[host] {
		if now.Sub(t) < pinnedEmptyWindow {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	e.empty[host] = kept
	return len(kept) >= pinnedEmptyThreshold
}

func (e *captureEnv) noteServedMITM(host string) {
	e.emptyMu.Lock()
	delete(e.empty, host)
	e.emptyMu.Unlock()
}

// Memory policy. iOS (GOOS=ios also covers Catalyst and visionOS) runs under the
// ~50 MB extension limit; the macOS system extension does not.

var baseMemory struct {
	sync.Mutex
	limit int64
	gc    int
}

func applyBaseMemoryLimits(transport string) {
	limit, gc := int64(sshHeapLimitBytes), sshGCPercent
	if transport == "tssh" || transport == "direct" {
		limit, gc = tsshHeapLimitBytes, tsshGCPercent
	}
	baseMemory.Lock()
	baseMemory.limit, baseMemory.gc = limit, gc
	baseMemory.Unlock()
	debug.SetMemoryLimit(limit)
	debug.SetGCPercent(gc)
}

// Capture only ever gives SSH mode (which has no Go limit) the soft limit TSSH
// already runs with. A lower limit than the live heap makes the GC run almost
// continuously and stalls the whole extension, so it never tightens further.
func applyCaptureMemoryLimits(transport string, enabled bool) {
	if runtime.GOOS != "ios" {
		return
	}
	if enabled {
		if transport == "ssh" {
			debug.SetMemoryLimit(tsshHeapLimitBytes)
			debug.SetGCPercent(tsshGCPercent)
		}
		return
	}
	baseMemory.Lock()
	limit, gc := baseMemory.limit, baseMemory.gc
	baseMemory.Unlock()
	if gc != 0 {
		debug.SetMemoryLimit(limit)
		debug.SetGCPercent(gc)
	}
}

func mitmFlowCap(transport string) int {
	if runtime.GOOS != "ios" {
		return 256
	}
	if transport == "ssh" {
		return 24
	}
	return 32
}

// captureStatus is embedded in GetStatus JSON.
type captureStatus struct {
	Enabled      bool   `json:"enabled"`
	SessionID    string `json:"sessionID,omitempty"`
	Segment      string `json:"segment,omitempty"`
	CALoaded     bool   `json:"caLoaded"`
	Transactions int64  `json:"transactions"`
	Tunnels      int64  `json:"tunnels"`
	TLSRejected  int64  `json:"tlsRejected"`
	Failures     int64  `json:"failures"`
	BytesWritten int64  `json:"bytesWritten"`
	DroppedBytes int64  `json:"droppedBytes"`
	ActiveMITM   int    `json:"activeMITM"`
	MITMOverflow int64  `json:"mitmOverflow"`
	StopReason   string `json:"stopReason,omitempty"`
}

func currentCaptureStatus() *captureStatus {
	cs := captureCur.Load()
	if cs == nil {
		return nil
	}
	st := &captureStatus{Enabled: cs.recording(), CALoaded: cs.minter != nil}
	if env := currentCaptureEnv(); env != nil {
		st.ActiveMITM = int(env.mitmLive.Load())
		st.MITMOverflow = env.overflow.Load()
	}
	if r := cs.rec; r != nil {
		st.SessionID = r.sessionID
		st.Segment = r.nonce
		st.Transactions = r.txCount.Load()
		st.Tunnels = r.tunnelCount.Load()
		st.TLSRejected = r.rejected.Load()
		st.Failures = r.failures.Load()
		st.BytesWritten = r.written.Load()
		st.DroppedBytes = r.dropped.Load()
		st.StopReason = r.stopReasonString()
	}
	return st
}

// CaptureConfigure applies an HTTP capture config (JSON) to the running tunnel.
// Calling it again with the same sessionID and segmentNonce updates rules in
// place; a new session or nonce starts a new recording segment.
func CaptureConfigure(configJSON string) error {
	return applyCaptureConfig([]byte(configJSON))
}

// CaptureStop ends the current capture session and returns its status JSON.
func CaptureStop() string {
	st := currentCaptureStatus()
	closeCapture("user", true)
	if st == nil {
		return "{}"
	}
	b, _ := json.Marshal(st)
	return string(b)
}

// CaptureResetFlows aborts every active TCP flow and QUIC (UDP 443) flow so
// apps reconnect and pass through the current capture rules. Returns the
// number of TCP flows reset.
func CaptureResetFlows() int {
	env := currentCaptureEnv()
	if env == nil {
		return 0
	}
	if env.udp != nil {
		env.udp.closePort(443)
	}
	return env.flows.abortAll()
}
