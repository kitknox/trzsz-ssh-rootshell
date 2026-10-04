//go:build darwin

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
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/net/route"
)

// NWPath lists every usable interface, including USB peer links (anpi*, an
// attached iPad) that have no default route; Direct sockets bound there loop
// or go nowhere. The routing table says which interfaces really reach a
// gateway.

// PickDirectInterface returns the first of candidates (comma-separated
// interface indexes, in the OS's preference order) that has a default route
// through a gateway and a routable address, or 0 when none does.
func PickDirectInterface(candidates string) int {
	gateways := defaultGatewayInterfaces()
	for _, field := range strings.Split(candidates, ",") {
		idx, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || idx <= 0 || !gateways[idx] {
			continue
		}
		if ifc, err := net.InterfaceByIndex(idx); err == nil && usableDirectInterface(ifc) {
			return idx
		}
	}
	return 0
}

// defaultGatewayInterfaces lists the interfaces with a default route through
// a gateway. Scoped ones count: while the tunnel holds the default route, the
// physical interfaces keep scoped defaults.
func defaultGatewayInterfaces() map[int]bool {
	out := make(map[int]bool)
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return out
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return out
	}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&syscall.RTF_UP == 0 || rm.Flags&syscall.RTF_GATEWAY == 0 {
			continue
		}
		if len(rm.Addrs) > syscall.RTAX_DST && isDefaultDestination(rm.Addrs) {
			out[rm.Index] = true
		}
	}
	return out
}

// isDefaultDestination reports a 0.0.0.0/0 or ::/0 route.
func isDefaultDestination(addrs []route.Addr) bool {
	var mask route.Addr
	if len(addrs) > syscall.RTAX_NETMASK {
		mask = addrs[syscall.RTAX_NETMASK]
	}
	switch dst := addrs[syscall.RTAX_DST].(type) {
	case *route.Inet4Addr:
		m, ok := mask.(*route.Inet4Addr)
		return dst.IP == [4]byte{} && (mask == nil || ok && m.IP == [4]byte{})
	case *route.Inet6Addr:
		m, ok := mask.(*route.Inet6Addr)
		return dst.IP == [16]byte{} && (mask == nil || ok && m.IP == [16]byte{})
	}
	return false
}

// usableDirectInterface rejects peer links and tunnels, and interfaces with
// only link-local addresses.
func usableDirectInterface(ifc *net.Interface) bool {
	if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
		return false
	}
	for _, prefix := range []string{"anpi", "utun", "ipsec", "awdl", "llw", "bridge"} {
		if strings.HasPrefix(ifc.Name, prefix) {
			return false
		}
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.Is4() && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() && !ip.IsUnspecified() {
			return true
		}
		if ip.Is6() && ip.IsGlobalUnicast() && !ip.IsPrivate() {
			return true
		}
	}
	return false
}
