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
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID                       = 1
	channelEndpointSize         = 1024      // packet queue size
	packetReaderChSize          = 128       // intermediary Go channel for batch reads
	tcpReceiveWindow            = 256 << 10 // 256KB
	tcpBridgeBufferSize         = 16 * 1024
	tcpForwarderMaxInFlight     = 1024
	tcpIdleTimeout              = 30 * time.Second
	tcpFlowAdmissionWait        = 350 * time.Millisecond
	tcpSendBufferMinSSH         = 16 << 10
	tcpSendBufferDefaultSSH     = 64 << 10
	tcpSendBufferMaxSSH         = 128 << 10
	tcpReceiveBufferMinSSH      = 16 << 10
	tcpReceiveBufferDefaultSSH  = 64 << 10
	tcpReceiveBufferMaxSSH      = 128 << 10
	tcpSendBufferMinTSSH        = 16 << 10
	tcpSendBufferDefaultTSSH    = 64 << 10
	tcpSendBufferMaxTSSH        = 128 << 10
	tcpReceiveBufferMinTSSH     = 16 << 10
	tcpReceiveBufferDefaultTSSH = 64 << 10
	tcpReceiveBufferMaxTSSH     = 128 << 10
	maxActiveTCPFlows           = 256
)

// packetEntry holds a single outbound packet read from the channel endpoint.
type packetEntry struct {
	data   []byte
	family int
}

// tunnelStack wraps the gVisor netstack and channel endpoint.
type tunnelStack struct {
	stack    *stack.Stack
	ep       *channel.Endpoint
	tcpDial  tcpDialer
	udpFwd   *udpForwarder
	stats    *tunnelStats
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mtu      int
	tcpSem   chan struct{}    // limits concurrent TCP flows
	packetCh chan packetEntry // outbound packets for batch reading
}

// newTunnelStack creates a new gVisor netstack with TCP/UDP forwarders.
func newTunnelStack(cfg *VPNTunnelConfig, tcpDial tcpDialer, udpDial udpDialer, stats *tunnelStats) (*tunnelStack, error) {
	ctx, cancel := context.WithCancel(context.Background())

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1500
	}

	// Create channel endpoint for packet injection
	ep := channel.New(channelEndpointSize, uint32(mtu), "")

	// Create the gVisor stack
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	}
	s := stack.New(opts)

	// Create NIC
	if err := s.CreateNIC(nicID, ep); err != nil {
		cancel()
		return nil, fmt.Errorf("create NIC: %v", err)
	}

	// Cap per-socket TCP buffers in both transports to keep RSS under
	// NEPacketTunnelProvider limits. TSSH stays tighter than SSH.
	var sendBuf tcpip.TCPSendBufferSizeRangeOption
	var recvBuf tcpip.TCPReceiveBufferSizeRangeOption
	moderateRecv := tcpip.TCPModerateReceiveBufferOption(true)
	if cfg.TransportType == "tssh" {
		sendBuf = tcpip.TCPSendBufferSizeRangeOption{
			Min:     tcpSendBufferMinTSSH,
			Default: tcpSendBufferDefaultTSSH,
			Max:     tcpSendBufferMaxTSSH,
		}
		recvBuf = tcpip.TCPReceiveBufferSizeRangeOption{
			Min:     tcpReceiveBufferMinTSSH,
			Default: tcpReceiveBufferDefaultTSSH,
			Max:     tcpReceiveBufferMaxTSSH,
		}
		// Keep receive buffers fixed in TSSH mode to avoid runaway growth.
		moderateRecv = tcpip.TCPModerateReceiveBufferOption(false)
	} else {
		sendBuf = tcpip.TCPSendBufferSizeRangeOption{
			Min:     tcpSendBufferMinSSH,
			Default: tcpSendBufferDefaultSSH,
			Max:     tcpSendBufferMaxSSH,
		}
		recvBuf = tcpip.TCPReceiveBufferSizeRangeOption{
			Min:     tcpReceiveBufferMinSSH,
			Default: tcpReceiveBufferDefaultSSH,
			Max:     tcpReceiveBufferMaxSSH,
		}
	}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sendBuf); err != nil {
		cancel()
		return nil, fmt.Errorf("set tcp send buffer range: %v", err)
	}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &recvBuf); err != nil {
		cancel()
		return nil, fmt.Errorf("set tcp receive buffer range: %v", err)
	}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &moderateRecv); err != nil {
		cancel()
		return nil, fmt.Errorf("set tcp receive buffer moderation: %v", err)
	}

	// Add default routes (catch-all)
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		},
	})

	// Enable promiscuous mode so we accept packets for any destination
	s.SetPromiscuousMode(nicID, true)

	// Enable spoofing so we can respond with any source address
	s.SetSpoofing(nicID, true)

	// Set up TCP forwarding.
	tcpSem := make(chan struct{}, maxActiveTCPFlows)
	tcpForwarder := tcp.NewForwarder(s, tcpReceiveWindow, tcpForwarderMaxInFlight, func(r *tcp.ForwarderRequest) {
		go handleTCPForward(ctx, r, tcpDial, stats, tcpSem)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	// Set up UDP forwarding
	udpFwd := newUDPForwarder(udpDial, tcpDial, stats)
	udpForwarderGvisor := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		udpFwd.handleUDP(r)
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarderGvisor.HandlePacket)

	packetCh := make(chan packetEntry, packetReaderChSize)

	ts := &tunnelStack{
		stack:    s,
		ep:       ep,
		tcpDial:  tcpDial,
		udpFwd:   udpFwd,
		stats:    stats,
		ctx:      ctx,
		cancel:   cancel,
		mtu:      mtu,
		tcpSem:   tcpSem,
		packetCh: packetCh,
	}

	// Start packet reader goroutine: drains the channel endpoint into a
	// Go channel so Swift can do non-blocking batch reads.
	ts.wg.Add(1)
	go func() {
		defer ts.wg.Done()
		defer close(packetCh)
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			family := 2 // AF_INET
			if pkt.NetworkProtocolNumber == header.IPv6ProtocolNumber {
				family = 30 // AF_INET6 on Darwin
			}
			data := pkt.ToView().AsSlice()
			stats.addBytesIn(len(data))
			entry := packetEntry{
				data:   append([]byte(nil), data...), // copy before DecRef
				family: family,
			}
			pkt.DecRef()

			select {
			case packetCh <- entry:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Start UDP cleanup goroutine
	ts.wg.Add(1)
	go func() {
		defer ts.wg.Done()
		ticker := time.NewTicker(udpCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				udpFwd.cleanup()
			case <-ctx.Done():
				return
			}
		}
	}()

	return ts, nil
}

// injectPacket feeds a raw IP packet into the netstack.
// family: syscall.AF_INET (2) or syscall.AF_INET6 (30 on Darwin).
func (ts *tunnelStack) injectPacket(data []byte, family int) {
	if len(data) == 0 {
		return
	}

	ts.stats.addBytesOut(len(data))

	var protocol tcpip.NetworkProtocolNumber
	switch family {
	case 2: // AF_INET
		protocol = header.IPv4ProtocolNumber
	case 30: // AF_INET6 (Darwin)
		protocol = header.IPv6ProtocolNumber
	default:
		return
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(data),
	})
	ts.ep.InjectInbound(protocol, pkt)
	pkt.DecRef()
}

// readPacket reads the next outbound IP packet (blocking).
// Returns the packet data and protocol family, or (nil, 0) on shutdown.
func (ts *tunnelStack) readPacket() ([]byte, int) {
	p, ok := <-ts.packetCh
	if !ok {
		return nil, 0
	}
	return p.data, p.family
}

// readPacketNonBlocking returns the next outbound packet without blocking.
// Returns (nil, 0) immediately if no packet is queued.
func (ts *tunnelStack) readPacketNonBlocking() ([]byte, int) {
	select {
	case p, ok := <-ts.packetCh:
		if !ok {
			return nil, 0
		}
		return p.data, p.family
	default:
		return nil, 0
	}
}

// close shuts down the netstack.
func (ts *tunnelStack) close() {
	ts.cancel()
	ts.wg.Wait()
	ts.stack.Close()
}

// handleTCPForward handles a single TCP connection from the netstack.
func handleTCPForward(ctx context.Context, r *tcp.ForwarderRequest, dialer tcpDialer, stats *tunnelStats, sem chan struct{}) {
	// Acquire semaphore slot. Allow a brief admission wait to smooth short
	// connection bursts from browsers, then RST only if still saturated.
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	default:
		timer := time.NewTimer(tcpFlowAdmissionWait)
		select {
		case sem <- struct{}{}:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			defer func() { <-sem }()
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			r.Complete(true)
			return
		case <-timer.C:
			stats.tcpCapacityDrop()
			r.Complete(true) // RST — at sustained capacity
			return
		}
	}

	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	id := r.ID()
	dstAddr := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))

	var wq waiter.Queue
	ep, tcpipErr := r.CreateEndpoint(&wq)
	if tcpipErr != nil {
		log.Printf("vpntunnel: tcp create endpoint for %s: %v", dstAddr, tcpipErr)
		r.Complete(true) // send RST
		return
	}
	r.Complete(false)
	defer ep.Close()

	stats.connOpenedTCP()
	defer stats.connClosedTCP()

	// Dial the remote
	remote, err := dialer.DialTCP(connCtx, dstAddr)
	if err != nil {
		log.Printf("vpntunnel: tcp dial %s: %v", dstAddr, err)
		return
	}
	// Bridge netstack endpoint ↔ remote connection
	done := make(chan struct{}, 2)

	// netstack → remote
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, tcpBridgeBufferSize)
		for {
			w, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
			wq.EventRegister(&w)
			for {
				var res tcpip.ReadResult
				var tcpipErr tcpip.Error
				sw := tcpip.SliceWriter(buf)
				res, tcpipErr = ep.Read(&sw, tcpip.ReadOptions{})
				if tcpipErr == nil {
					n := res.Count
					if n > 0 {
						_ = remote.SetWriteDeadline(time.Now().Add(tcpIdleTimeout))
						if _, err := remote.Write(buf[:n]); err != nil {
							wq.EventUnregister(&w)
							return
						}
					}
					break
				}
				if _, ok := tcpipErr.(*tcpip.ErrClosedForReceive); ok {
					wq.EventUnregister(&w)
					return
				}
				if _, ok := tcpipErr.(*tcpip.ErrWouldBlock); !ok {
					wq.EventUnregister(&w)
					return
				}
				select {
				case <-ch:
				case <-connCtx.Done():
					wq.EventUnregister(&w)
					return
				}
			}
			wq.EventUnregister(&w)
		}
	}()

	// remote → netstack
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, tcpBridgeBufferSize)
		for {
			_ = remote.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
			n, err := remote.Read(buf)
			if n > 0 {
				// Write all data to gVisor endpoint, handling partial writes
				// and back-pressure. ep.Write() with default Atomic=false may
				// write fewer bytes than requested (partial write, nil error)
				// or return ErrWouldBlock when the send buffer is completely
				// full. Both cases require retry to avoid data loss.
				data := buf[:n]
				for len(data) > 0 {
					nw, tcpipErr := ep.Write(bytes.NewReader(data), tcpip.WriteOptions{})
					if nw > 0 {
						data = data[nw:]
					}
					if tcpipErr == nil {
						continue
					}
					if _, ok := tcpipErr.(*tcpip.ErrWouldBlock); !ok {
						return
					}
					// Send buffer full — wait for space before retrying.
					ww, ch := waiter.NewChannelEntry(waiter.WritableEvents)
					wq.EventRegister(&ww)
					select {
					case <-ch:
					case <-connCtx.Done():
						wq.EventUnregister(&ww)
						return
					}
					wq.EventUnregister(&ww)
				}
			}
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					// Idle timeout: close stale connection to avoid resource leaks.
					return
				}
				if err != io.EOF {
					log.Printf("vpntunnel: tcp remote read %s: %v", dstAddr, err)
				}
				return
			}
		}
	}()

	// Wait for first direction to finish, then cancel the per-connection
	// context and close remote to unblock the other goroutine, then wait.
	<-done
	connCancel()
	remote.Close()
	<-done
}
