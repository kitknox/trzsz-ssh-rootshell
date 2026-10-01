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
	"container/list"
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

const dnsCacheSize = 2048

// dnsCache maps resolved IPs back to the queried name, so flows without SNI
// (plain HTTP, ECH, non-TLS) still get a hostname label.
type dnsCache struct {
	mu    sync.Mutex
	items map[netip.Addr]*list.Element
	lru   *list.List
}

type dnsCacheEntry struct {
	ip   netip.Addr
	name string
}

func newDNSCache() *dnsCache {
	return &dnsCache{items: make(map[netip.Addr]*list.Element), lru: list.New()}
}

func (c *dnsCache) lookup(ip string) string {
	if c == nil {
		return ""
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[addr.Unmap()]; ok {
		c.lru.MoveToFront(el)
		return el.Value.(*dnsCacheEntry).name
	}
	return ""
}

func (c *dnsCache) put(addr netip.Addr, name string) {
	addr = addr.Unmap()
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[addr]; ok {
		el.Value.(*dnsCacheEntry).name = name
		c.lru.MoveToFront(el)
		return
	}
	c.items[addr] = c.lru.PushFront(&dnsCacheEntry{ip: addr, name: name})
	for c.lru.Len() > dnsCacheSize {
		old := c.lru.Back()
		c.lru.Remove(old)
		delete(c.items, old.Value.(*dnsCacheEntry).ip)
	}
}

// observe records A/AAAA answers from a DNS response, keyed to the original
// question name (not the CNAME target), which is what users recognize.
func (c *dnsCache) observe(msg []byte) {
	if c == nil {
		return
	}
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || !h.Response {
		return
	}
	q, err := p.Question()
	if err != nil {
		return
	}
	name := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")
	if err := p.SkipAllQuestions(); err != nil {
		return
	}
	for {
		ah, err := p.AnswerHeader()
		if err != nil {
			return
		}
		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return
			}
			c.put(netip.AddrFrom4(r.A), name)
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return
			}
			c.put(netip.AddrFrom16(r.AAAA), name)
		default:
			if err := p.SkipAnswer(); err != nil {
				return
			}
		}
	}
}

// dnsTypeHTTPS is the HTTPS/SVCB-style record (RFC 9460) that carries ECH keys.
const dnsTypeHTTPS = dnsmessage.Type(65)

// synthesizeHTTPSNoData answers an HTTPS-record query with NOERROR/NODATA so
// clients don't learn ECH configs and keep sending a readable SNI. Returns nil
// for any other query.
func synthesizeHTTPSNoData(query []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil || h.Response {
		return nil
	}
	q, err := p.Question()
	if err != nil || q.Type != dnsTypeHTTPS {
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 h.ID,
		Response:           true,
		OpCode:             h.OpCode,
		RecursionDesired:   h.RecursionDesired,
		RecursionAvailable: true,
		RCode:              dnsmessage.RCodeSuccess,
	})
	if err := b.StartQuestions(); err != nil {
		return nil
	}
	if err := b.Question(q); err != nil {
		return nil
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}
