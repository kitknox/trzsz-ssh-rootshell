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
	"encoding/binary"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	ipProtoTCP = 6
	ipProtoUDP = 17
)

// ipPacketInfo is the part of an IP header the Tailscale demux routes on.
// IPv6 extension headers are not walked; proto is then the first next-header.
type ipPacketInfo struct {
	src, dst   netip.Addr
	proto      uint8
	l4         []byte // transport header and payload
	srcPort    uint16 // TCP/UDP only
	dstPort    uint16
	hasL4Ports bool
}

func parseIPPacket(pkt []byte) (ipPacketInfo, bool) {
	var info ipPacketInfo
	if len(pkt) < 1 {
		return info, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return info, false
		}
		ihl := int(pkt[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(pkt[2:4]))
		if ihl < 20 || total < ihl || total > len(pkt) {
			return info, false
		}
		info.src = netip.AddrFrom4([4]byte(pkt[12:16]))
		info.dst = netip.AddrFrom4([4]byte(pkt[16:20]))
		info.proto = pkt[9]
		// Only the first fragment carries ports.
		if binary.BigEndian.Uint16(pkt[6:8])&0x1fff == 0 {
			info.l4 = pkt[ihl:total]
		}
	case 6:
		if len(pkt) < 40 {
			return info, false
		}
		payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
		if 40+payloadLen > len(pkt) {
			return info, false
		}
		info.src = netip.AddrFrom16([16]byte(pkt[8:24]))
		info.dst = netip.AddrFrom16([16]byte(pkt[24:40]))
		info.proto = pkt[6]
		info.l4 = pkt[40 : 40+payloadLen]
	default:
		return info, false
	}
	if (info.proto == ipProtoTCP || info.proto == ipProtoUDP) && len(info.l4) >= 8 {
		info.srcPort = binary.BigEndian.Uint16(info.l4[0:2])
		info.dstPort = binary.BigEndian.Uint16(info.l4[2:4])
		info.hasL4Ports = true
	}
	return info, true
}

// udpPayload returns the datagram body of a UDP packet.
func (i ipPacketInfo) udpPayload() []byte {
	if i.proto != ipProtoUDP || len(i.l4) < 8 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(i.l4[4:6]))
	if n < 8 || n > len(i.l4) {
		return nil
	}
	return i.l4[8:n]
}

func checksumFold(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func checksumAdd(sum uint32, b []byte) uint32 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

// buildUDPPacket wraps payload in a UDP/IP packet from src to dst.
func buildUDPPacket(src, dst netip.AddrPort, payload []byte) []byte {
	udpLen := 8 + len(payload)
	var pkt []byte
	var l4 []byte
	var pseudo uint32
	if src.Addr().Is4() {
		pkt = make([]byte, 20+udpLen)
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
		pkt[8] = 64
		pkt[9] = ipProtoUDP
		s, d := src.Addr().As4(), dst.Addr().As4()
		copy(pkt[12:16], s[:])
		copy(pkt[16:20], d[:])
		binary.BigEndian.PutUint16(pkt[10:12], checksumFold(checksumAdd(0, pkt[:20])))
		pseudo = checksumAdd(0, pkt[12:20])
		l4 = pkt[20:]
	} else {
		pkt = make([]byte, 40+udpLen)
		pkt[0] = 0x60
		binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen))
		pkt[6] = ipProtoUDP
		pkt[7] = 64
		s, d := src.Addr().As16(), dst.Addr().As16()
		copy(pkt[8:24], s[:])
		copy(pkt[24:40], d[:])
		pseudo = checksumAdd(0, pkt[8:40])
		l4 = pkt[40:]
	}
	binary.BigEndian.PutUint16(l4[0:2], src.Port())
	binary.BigEndian.PutUint16(l4[2:4], dst.Port())
	binary.BigEndian.PutUint16(l4[4:6], uint16(udpLen))
	copy(l4[8:], payload)
	pseudo += uint32(ipProtoUDP) + uint32(udpLen)
	sum := checksumFold(checksumAdd(pseudo, l4))
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(l4[6:8], sum)
	return pkt
}

// dnsQuestion is the first question of a DNS query.
type dnsQuestion struct {
	header dnsmessage.Header
	q      dnsmessage.Question
	name   string // lower case, no trailing dot
}

func parseDNSQuery(msg []byte) (dnsQuestion, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || h.Response {
		return dnsQuestion{}, false
	}
	q, err := p.Question()
	if err != nil {
		return dnsQuestion{}, false
	}
	return dnsQuestion{
		header: h,
		q:      q,
		name:   strings.TrimSuffix(strings.ToLower(q.Name.String()), "."),
	}, true
}

// dnsAnswer builds a response to q. A non-nil a4 adds one A record; it is
// ignored unless the question is type A.
func dnsAnswer(q dnsQuestion, rcode dnsmessage.RCode, a4 *netip.Addr, ttl uint32) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 q.header.ID,
		Response:           true,
		OpCode:             q.header.OpCode,
		RecursionDesired:   q.header.RecursionDesired,
		RecursionAvailable: true,
		RCode:              rcode,
	})
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(q.q) != nil {
		return nil
	}
	if a4 != nil && a4.Is4() && q.q.Type == dnsmessage.TypeA {
		if b.StartAnswers() != nil {
			return nil
		}
		hdr := dnsmessage.ResourceHeader{Name: q.q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl}
		if b.AResource(hdr, dnsmessage.AResource{A: a4.As4()}) != nil {
			return nil
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// dnsAnswerAddrs returns the A and AAAA records of a DNS response.
func dnsAnswerAddrs(msg []byte) []netip.Addr {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || !h.Response || p.SkipAllQuestions() != nil {
		return nil
	}
	var out []netip.Addr
	for {
		ah, err := p.AnswerHeader()
		if err != nil {
			return out
		}
		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return out
			}
			out = append(out, netip.AddrFrom4(r.A))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return out
			}
			out = append(out, netip.AddrFrom16(r.AAAA))
		default:
			if p.SkipAnswer() != nil {
				return out
			}
		}
	}
}
