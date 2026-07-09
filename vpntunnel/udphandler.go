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
	"bytes"
	"context"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	udpIdleTimeout       = 60 * time.Second
	udpIdleTimeoutQUIC   = 180 * time.Second // browser QUIC (dst 443) idles between interactions
	udpCleanupInterval   = 5 * time.Second
	udpAdmissionEvictAge = 5 * time.Second
	udpBufferSize        = 16 * 1024
	maxActiveUDPFlows    = 512
)

// udpForwarder handles UDP packets from the netstack.
type udpForwarder struct {
	dialer     udpDialer
	stats      *tunnelStats
	isDNS      func(addr string) bool
	tcpDial    tcpDialer // for DNS-over-TCP fallback (SSH mode)
	blockQUIC  bool
	maxPayload int // largest inner UDP payload the TUN MTU can carry

	mu    sync.Mutex
	conns map[string]*udpConnTracker // key: "srcAddr->dstAddr"
}

// udpConnTracker tracks a single UDP "connection" (src→dst pair).
type udpConnTracker struct {
	remote      udpConn
	cancel      context.CancelFunc
	lastUse     time.Time
	idleTimeout time.Duration
}

func newUDPForwarder(dialer udpDialer, tcpDial tcpDialer, stats *tunnelStats, blockQUIC bool, tunMTU int, datagramBudget int) *udpForwarder {
	// Inbound cap: what the TUN can carry, and also what the transport's
	// datagram path can carry. Anything above the datagram budget only
	// arrives via an unpatched server's reliable-stream fallback (e.g.
	// origin PMTUD probes when the TUN MTU is clamped above budget+28);
	// dropping it preserves real-UDP semantics in the reverse direction.
	maxPayload := tunMTU - ipv4Overhead
	if datagramBudget > 0 && datagramBudget < maxPayload {
		maxPayload = datagramBudget
	}
	return &udpForwarder{
		dialer:     dialer,
		stats:      stats,
		tcpDial:    tcpDial,
		blockQUIC:  blockQUIC,
		maxPayload: maxPayload,
		isDNS: func(addr string) bool {
			_, port, _ := net.SplitHostPort(addr)
			return port == "53"
		},
		conns: make(map[string]*udpConnTracker),
	}
}

// allowFlow decides whether a new UDP flow to dstPort may be forwarded.
// Refused flows get an ICMP port-unreachable from gVisor, so browsers fall
// back to HTTP/2 immediately instead of black-holing on QUIC. Established
// flows are demuxed before this check and are never affected.
func (f *udpForwarder) allowFlow(dstPort uint16) bool {
	if f.dialer == nil {
		// SSH mode: only DNS (answered via DNS-over-TCP) is supported.
		return dstPort == 53
	}
	return !(f.blockQUIC && dstPort == 443)
}

// handleUDP is the UDP forwarder function registered with gVisor.
func (f *udpForwarder) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	dstAddr := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	srcAddr := net.JoinHostPort(id.RemoteAddress.String(), strconv.Itoa(int(id.RemotePort)))
	key := srcAddr + "->" + dstAddr

	var wq waiter.Queue
	ep, tcpipErr := r.CreateEndpoint(&wq)
	if tcpipErr != nil {
		log.Printf("vpntunnel: udp create endpoint for %s: %v", dstAddr, tcpipErr)
		return
	}

	f.mu.Lock()
	existing, ok := f.conns[key]
	if ok {
		existing.lastUse = time.Now()
		f.mu.Unlock()
		ep.Close()
		return
	}
	if len(f.conns) >= maxActiveUDPFlows {
		_ = f.evictOldestIdleLocked(udpAdmissionEvictAge)
		if len(f.conns) >= maxActiveUDPFlows {
			f.stats.udpCapacityDrop()
			f.mu.Unlock()
			ep.Close()
			return
		}
	}

	idleTimeout := udpIdleTimeout
	if id.LocalPort == 443 {
		idleTimeout = udpIdleTimeoutQUIC
	}
	ctx, cancel := context.WithCancel(context.Background())
	tracker := &udpConnTracker{cancel: cancel, lastUse: time.Now(), idleTimeout: idleTimeout}
	f.conns[key] = tracker
	f.mu.Unlock()

	f.stats.connOpenedUDP()

	go func() {
		defer func() {
			f.mu.Lock()
			delete(f.conns, key)
			f.mu.Unlock()
			f.stats.connClosedUDP()
			ep.Close()
			cancel()
			if tracker.remote != nil {
				tracker.remote.Close()
			}
		}()

		if f.dialer == nil {
			// SSH mode: only DNS reaches here (allowFlow rejects the rest
			// with ICMP port-unreachable); answer it via DNS-over-TCP.
			if f.isDNS(dstAddr) {
				f.handleDNSOverTCP(ctx, ep, &wq, dstAddr)
			}
			return
		}

		// TSSH mode: native UDP forwarding
		remote, err := f.dialer.DialUDP(ctx, dstAddr)
		if err != nil {
			log.Printf("vpntunnel: udp dial %s: %v", dstAddr, err)
			return
		}
		tracker.remote = remote

		// Forward data bidirectionally
		done := make(chan struct{}, 2)

		// netstack → remote
		go func() {
			defer func() { done <- struct{}{} }()
			buf := make([]byte, udpBufferSize)
			for {
				var res tcpip.ReadResult
				w, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
				wq.EventRegister(&w)
				for {
					var tcpipErr tcpip.Error
					sw := tcpip.SliceWriter(buf)
					res, tcpipErr = ep.Read(&sw, tcpip.ReadOptions{})
					if tcpipErr == nil {
						break
					}
					if _, ok := tcpipErr.(*tcpip.ErrWouldBlock); !ok {
						wq.EventUnregister(&w)
						return
					}
					select {
					case <-ch:
					case <-ctx.Done():
						wq.EventUnregister(&w)
						return
					}
				}
				wq.EventUnregister(&w)

				n := res.Count
				if n > 0 {
					f.mu.Lock()
					tracker.lastUse = time.Now()
					f.mu.Unlock()
					if err := remote.Write(buf[:n]); err != nil {
						return
					}
				}
			}
		}()

		// remote → netstack
		go func() {
			defer func() { done <- struct{}{} }()
			buf := make([]byte, udpBufferSize)
			for {
				n, err := remote.Read(buf)
				if err != nil {
					return
				}
				if n > 0 {
					f.mu.Lock()
					tracker.lastUse = time.Now()
					f.mu.Unlock()
					// Drop payloads the TUN MTU can't carry. Unpatched tsshd
					// servers deliver oversize packets (e.g. origin QUIC PMTUD
					// probes) via the reliable-stream fallback; dropping here
					// keeps them unacknowledged so the origin's PMTUD converges
					// below the datagram budget.
					if n > f.maxPayload {
						continue
					}
					data := buf[:n]
					ep.Write(bytes.NewReader(data), tcpip.WriteOptions{})
				}
			}
		}()

		<-done
	}()
}

func (f *udpForwarder) evictOldestIdleLocked(minIdle time.Duration) bool {
	now := time.Now()
	var victimKey string
	var victim *udpConnTracker
	oldest := now
	for key, tracker := range f.conns {
		if now.Sub(tracker.lastUse) < minIdle {
			continue
		}
		if victim == nil || tracker.lastUse.Before(oldest) {
			victim = tracker
			victimKey = key
			oldest = tracker.lastUse
		}
	}
	if victim == nil {
		return false
	}
	if victim.remote != nil {
		_ = victim.remote.Close()
	}
	victim.cancel()
	delete(f.conns, victimKey)
	return true
}

// handleDNSOverTCP forwards a DNS query over TCP (for SSH mode where UDP isn't available).
func (f *udpForwarder) handleDNSOverTCP(ctx context.Context, ep tcpip.Endpoint, wq *waiter.Queue, dstAddr string) {
	if f.tcpDial == nil {
		return
	}

	// Read the UDP DNS query from the endpoint
	buf := make([]byte, udpBufferSize)
	w, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&w)
	defer wq.EventUnregister(&w)

	var res tcpip.ReadResult
	for {
		var tcpipErr tcpip.Error
		sw := tcpip.SliceWriter(buf)
		res, tcpipErr = ep.Read(&sw, tcpip.ReadOptions{})
		if tcpipErr == nil {
			break
		}
		if _, ok := tcpipErr.(*tcpip.ErrWouldBlock); !ok {
			return
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return
		}
	}

	query := buf[:res.Count]
	if len(query) < 12 {
		return
	}

	// Connect to DNS server over TCP
	conn, err := f.tcpDial.DialTCP(ctx, dstAddr)
	if err != nil {
		log.Printf("vpntunnel: dns-over-tcp dial %s: %v", dstAddr, err)
		return
	}
	defer conn.Close()

	// DNS over TCP: prepend 2-byte length prefix
	tcpQuery := make([]byte, 2+len(query))
	tcpQuery[0] = byte(len(query) >> 8)
	tcpQuery[1] = byte(len(query) & 0xff)
	copy(tcpQuery[2:], query)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(tcpQuery); err != nil {
		return
	}

	// Read TCP DNS response (2-byte length prefix)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	lenBuf := make([]byte, 2)
	if _, err := readFull(conn, lenBuf); err != nil {
		return
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if respLen > udpBufferSize {
		return
	}

	resp := make([]byte, respLen)
	if _, err := readFull(conn, resp); err != nil {
		return
	}

	// Write DNS response back to netstack as UDP
	ep.Write(bytes.NewReader(resp), tcpip.WriteOptions{})
}

// cleanup closes idle UDP connections.
func (f *udpForwarder) cleanup() {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	for key, tracker := range f.conns {
		if now.Sub(tracker.lastUse) > tracker.idleTimeout {
			if tracker.remote != nil {
				_ = tracker.remote.Close()
			}
			tracker.cancel()
			delete(f.conns, key)
		}
	}
}
