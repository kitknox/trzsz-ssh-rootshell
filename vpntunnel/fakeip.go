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
	"sync"
)

// fakeIPPrefix is routed into the tunnel for names that must resolve on the
// SSH host (RFC 2544 benchmarking space, as Surge and Clash use).
var fakeIPPrefix = netip.MustParsePrefix("198.18.0.0/15")

const fakeIPCapacity = 8192

// fakeIPPool hands out addresses from a fixed ring. When it wraps, the oldest
// name loses its address; answers carry a 1s TTL so that is rarely visible.
type fakeIPPool struct {
	mu     sync.Mutex
	base   uint32
	next   uint32
	byHost map[string]uint32
	byIdx  []string
}

func newFakeIPPool() *fakeIPPool {
	b := fakeIPPrefix.Addr().As4()
	return &fakeIPPool{
		// Skip .0 and .1 so no answer looks like a network or gateway address.
		base:   binary.BigEndian.Uint32(b[:]) + 2,
		byHost: make(map[string]uint32),
		byIdx:  make([]string, fakeIPCapacity),
	}
}

func (p *fakeIPPool) addr(idx uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], p.base+idx)
	return netip.AddrFrom4(b)
}

// assign returns the address for host, allocating one if needed.
func (p *fakeIPPool) assign(host string) netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	if idx, ok := p.byHost[host]; ok {
		return p.addr(idx)
	}
	idx := p.next
	p.next = (p.next + 1) % fakeIPCapacity
	if old := p.byIdx[idx]; old != "" {
		delete(p.byHost, old)
	}
	p.byIdx[idx] = host
	p.byHost[host] = idx
	return p.addr(idx)
}

// host returns the name behind a fake address.
func (p *fakeIPPool) host(ip netip.Addr) (string, bool) {
	if !ip.Is4() {
		return "", false
	}
	b := ip.As4()
	v := binary.BigEndian.Uint32(b[:])
	if v < p.base || v-p.base >= fakeIPCapacity {
		return "", false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.byIdx[v-p.base]
	return h, h != ""
}

// recentIPs remembers the last N DNS answers for names with a direct rule, so
// a full-tunnel flow to one of those addresses leaves through the physical
// interface instead of SSH.
type recentIPs struct {
	mu    sync.Mutex
	cap   int
	order []netip.Addr
	set   map[netip.Addr]int // value: slot in order
	next  int
}

func newRecentIPs(capacity int) *recentIPs {
	return &recentIPs{cap: capacity, order: make([]netip.Addr, capacity), set: make(map[netip.Addr]int)}
}

func (l *recentIPs) add(ip netip.Addr) {
	ip = ip.Unmap()
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.set[ip]; ok {
		return
	}
	if old := l.order[l.next]; old.IsValid() {
		delete(l.set, old)
	}
	l.order[l.next] = ip
	l.set[ip] = l.next
	l.next = (l.next + 1) % l.cap
}

func (l *recentIPs) contains(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.set[ip.Unmap()]
	return ok
}
