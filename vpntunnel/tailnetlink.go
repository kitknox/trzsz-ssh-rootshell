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
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// When HTTP capture terminates a tailnet flow, it re-dials the host from this
// stack over a second NIC that faces WireGuard: its packets go straight to
// Tailscale, and Tailscale's replies to it are pulled out of the outbound
// stream (claimLinkPacket). The extension's own sockets can't do this, since
// iOS won't let them use the tunnel's tailnet address.

const (
	tailnetLinkNIC   tcpip.NICID = 2
	tailnetLinkQueue             = 256
)

// tailnetLink returns the WireGuard-facing NIC, creating it on first use and
// giving it the node's addresses. out receives its outbound packets.
func (ts *tunnelStack) tailnetLink(addrs []netip.Addr, out func([]byte)) (*channel.Endpoint, error) {
	ts.linkMu.Lock()
	defer ts.linkMu.Unlock()
	if ts.link == nil {
		ep := channel.New(tailnetLinkQueue, uint32(ts.mtu), "")
		if err := ts.stack.CreateNIC(tailnetLinkNIC, ep); err != nil {
			return nil, fmt.Errorf("tailnet link NIC: %v", err)
		}
		// Routes for this NIC only match dials bound to it, so the
		// catch-all routes of the app-facing NIC are unaffected.
		ts.stack.SetRouteTable(append(ts.stack.GetRouteTable(),
			tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: tailnetLinkNIC},
			tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: tailnetLinkNIC},
		))
		ts.wg.Add(1)
		go func() {
			defer ts.wg.Done()
			for {
				pkt := ep.ReadContext(ts.ctx)
				if pkt == nil {
					return
				}
				data := append([]byte(nil), pkt.ToView().AsSlice()...)
				pkt.DecRef()
				out(data)
			}
		}()
		ts.link = ep
	}
	for _, a := range addrs {
		proto := ipv4.ProtocolNumber
		if a.Is6() {
			proto = ipv6.ProtocolNumber
		}
		// Already present after the first dial; that error is expected.
		_ = ts.stack.AddProtocolAddress(tailnetLinkNIC, tcpip.ProtocolAddress{
			Protocol:          proto,
			AddressWithPrefix: tcpip.AddrFromSlice(a.AsSlice()).WithPrefix(),
		}, stack.AddressProperties{})
	}
	return ts.link, nil
}

// dialOverLink opens a TCP connection to dst from src over the link.
func (ts *tunnelStack) dialOverLink(ctx context.Context, src netip.Addr, dst netip.AddrPort) (net.Conn, error) {
	proto := ipv4.ProtocolNumber
	if dst.Addr().Is6() {
		proto = ipv6.ProtocolNumber
	}
	c, err := gonet.DialTCPWithBind(ctx, ts.stack,
		tcpip.FullAddress{NIC: tailnetLinkNIC, Addr: tcpip.AddrFromSlice(src.AsSlice())},
		tcpip.FullAddress{NIC: tailnetLinkNIC, Addr: tcpip.AddrFromSlice(dst.Addr().AsSlice()), Port: dst.Port()},
		proto)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// claimLinkPacket injects pkt into the link when it answers one of the
// link's own connections, reporting whether it did.
func (ts *tunnelStack) claimLinkPacket(pkt []byte) bool {
	info, ok := parseIPPacket(pkt)
	if !ok || info.proto != ipProtoTCP || !info.hasL4Ports {
		return false
	}
	ts.linkMu.Lock()
	ep := ts.link
	ts.linkMu.Unlock()
	if ep == nil {
		return false
	}
	netProto := ipv4.ProtocolNumber
	if info.dst.Is6() {
		netProto = ipv6.ProtocolNumber
	}
	id := stack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFromSlice(info.dst.AsSlice()),
		LocalPort:     info.dstPort,
		RemoteAddress: tcpip.AddrFromSlice(info.src.AsSlice()),
		RemotePort:    info.srcPort,
	}
	if ts.stack.FindTransportEndpoint(netProto, tcp.ProtocolNumber, id, tailnetLinkNIC) == nil {
		return false
	}
	buf := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
	ep.InjectInbound(netProto, buf)
	buf.DecRef()
	return true
}

// linkConn counts the live link connections so the claim check runs only
// while there are any.
type linkConn struct {
	net.Conn
	once sync.Once
	done func()
}

func (c *linkConn) Close() error {
	c.once.Do(c.done)
	return c.Conn.Close()
}
