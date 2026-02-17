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
	nicID               = 1
	channelEndpointSize = 64        // packet queue size
	tcpReceiveWindow    = 256 << 10 // 256KB
	tcpBridgeBufferSize = 16 * 1024
)

// tunnelStack wraps the gVisor netstack and channel endpoint.
type tunnelStack struct {
	stack   *stack.Stack
	ep      *channel.Endpoint
	tcpDial tcpDialer
	udpFwd  *udpForwarder
	stats   *tunnelStats
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mtu     int
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

	// Set up TCP forwarding
	tcpForwarder := tcp.NewForwarder(s, tcpReceiveWindow, 1024, func(r *tcp.ForwarderRequest) {
		go handleTCPForward(ctx, r, tcpDial, stats)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	// Set up UDP forwarding
	udpFwd := newUDPForwarder(udpDial, tcpDial, stats)
	udpForwarderGvisor := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		udpFwd.handleUDP(r)
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarderGvisor.HandlePacket)

	ts := &tunnelStack{
		stack:   s,
		ep:      ep,
		tcpDial: tcpDial,
		udpFwd:  udpFwd,
		stats:   stats,
		ctx:     ctx,
		cancel:  cancel,
		mtu:     mtu,
	}

	// Start UDP cleanup goroutine
	ts.wg.Add(1)
	go func() {
		defer ts.wg.Done()
		ticker := time.NewTicker(10 * time.Second)
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

	ts.stats.addBytesIn(len(data))

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

// readPacket reads the next outbound IP packet from the netstack (blocking).
// Returns the packet data and protocol family.
func (ts *tunnelStack) readPacket() ([]byte, int) {
	pkt := ts.ep.ReadContext(ts.ctx)
	if pkt == nil {
		return nil, 0
	}
	defer pkt.DecRef()

	// Determine protocol family
	family := 2 // AF_INET
	if pkt.NetworkProtocolNumber == header.IPv6ProtocolNumber {
		family = 30 // AF_INET6 on Darwin
	}

	data := pkt.ToView().AsSlice()
	ts.stats.addBytesOut(len(data))
	return append([]byte(nil), data...), family // copy to avoid buffer reuse
}

// close shuts down the netstack.
func (ts *tunnelStack) close() {
	ts.cancel()
	ts.wg.Wait()
	ts.stack.Close()
}

// handleTCPForward handles a single TCP connection from the netstack.
func handleTCPForward(ctx context.Context, r *tcp.ForwarderRequest, dialer tcpDialer, stats *tunnelStats) {
	id := r.ID()
	dstAddr := fmt.Sprintf("%s:%d", id.LocalAddress.String(), id.LocalPort)

	var wq waiter.Queue
	ep, tcpipErr := r.CreateEndpoint(&wq)
	if tcpipErr != nil {
		log.Printf("vpntunnel: tcp create endpoint for %s: %v", dstAddr, tcpipErr)
		r.Complete(true) // send RST
		return
	}
	r.Complete(false)
	defer ep.Close()

	stats.connOpened()
	defer stats.connClosed()

	// Dial the remote
	remote, err := dialer.DialTCP(ctx, dstAddr)
	if err != nil {
		log.Printf("vpntunnel: tcp dial %s: %v", dstAddr, err)
		return
	}
	defer remote.Close()

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
						if _, err := remote.Write(buf[:n]); err != nil {
							wq.EventUnregister(&w)
							return
						}
						stats.addBytesOut(n)
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
				case <-ctx.Done():
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
			n, err := remote.Read(buf)
			if n > 0 {
				data := buf[:n]
				_, tcpipErr := ep.Write(bytes.NewReader(data), tcpip.WriteOptions{})
				if tcpipErr != nil {
					return
				}
				stats.addBytesIn(n)
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("vpntunnel: tcp remote read %s: %v", dstAddr, err)
				}
				return
			}
		}
	}()

	// Wait for either direction to finish
	<-done
}
