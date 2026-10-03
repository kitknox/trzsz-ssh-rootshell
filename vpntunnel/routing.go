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
	"net/netip"
	"slices"
	"strings"
)

// routeAction is where a Tailscale-mode flow leaves the device.
type routeAction int

const (
	routeNone   routeAction = iota // no rule matched; the default applies
	routeSSH                       // through the SSH egress host
	routeDirect                    // straight out the physical interface
)

// routingRuleJSON is one user rule. Pattern is a CIDR, a bare domain (which
// also covers its subdomains), or a glob with * and ?.
type routingRuleJSON struct {
	Pattern string `json:"pattern"`
	Action  string `json:"action"` // "ssh" or "direct"
}

// routingConfigJSON is the optional "routing" object of the tunnel config.
type routingConfigJSON struct {
	SendAllViaSSH bool              `json:"sendAllViaSSH,omitempty"`
	Rules         []routingRuleJSON `json:"rules,omitempty"`
}

type routingRule struct {
	action routeAction
	prefix netip.Prefix // valid for CIDR and IP rules
	domain string       // bare domain: matches itself and subdomains
	glob   string       // glob pattern
}

// routeTable holds the compiled rules; the first match wins. sshEnabled is
// false without an SSH egress host, and then every SSH rule is inert.
type routeTable struct {
	rules         []routingRule
	sendAllViaSSH bool
	sshEnabled    bool
}

func compileRouteTable(cfg routingConfigJSON, sshEnabled bool) *routeTable {
	t := &routeTable{sendAllViaSSH: cfg.SendAllViaSSH && sshEnabled, sshEnabled: sshEnabled}
	for _, raw := range cfg.Rules {
		var r routingRule
		switch strings.ToLower(strings.TrimSpace(raw.Action)) {
		case "ssh":
			r.action = routeSSH
		case "direct":
			r.action = routeDirect
		default:
			continue
		}
		s := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw.Pattern)), ".")
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			r.prefix = p.Masked()
		} else if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
			r.prefix = netip.PrefixFrom(a, a.BitLen())
		} else if strings.ContainsAny(s, "*?") {
			r.glob = s
		} else {
			r.domain = s
		}
		t.rules = append(t.rules, r)
	}
	return t
}

func (r routingRule) isHostRule() bool { return r.domain != "" || r.glob != "" }

func (r routingRule) matchHost(host string) bool {
	if r.domain != "" {
		return host == r.domain || strings.HasSuffix(host, "."+r.domain)
	}
	return r.glob != "" && globMatch(r.glob, host)
}

// effective drops SSH verdicts when there is no SSH host to carry them.
func (t *routeTable) effective(a routeAction) routeAction {
	if a == routeSSH && !t.sshEnabled {
		return routeNone
	}
	return a
}

// matchHost returns the action for a DNS name.
func (t *routeTable) matchHost(host string) routeAction {
	if t == nil || host == "" {
		return routeNone
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, r := range t.rules {
		if r.isHostRule() && r.matchHost(host) {
			return t.effective(r.action)
		}
	}
	return routeNone
}

// matchIP returns the action for a destination address.
func (t *routeTable) matchIP(ip netip.Addr) routeAction {
	if t == nil || !ip.IsValid() {
		return routeNone
	}
	ip = ip.Unmap()
	for _, r := range t.rules {
		if r.prefix.IsValid() && r.prefix.Contains(ip) {
			return t.effective(r.action)
		}
	}
	return routeNone
}

// prefixes returns the CIDR rules with the given effective action.
func (t *routeTable) prefixes(a routeAction) []netip.Prefix {
	if t == nil {
		return nil
	}
	var out []netip.Prefix
	for _, r := range t.rules {
		if r.prefix.IsValid() && t.effective(r.action) == a {
			out = append(out, r.prefix)
		}
	}
	return out
}

// directExclusions returns the direct CIDR rules a full tunnel may exclude at
// the OS level. A rule overlapping an earlier SSH rule (or the fake-IP range)
// stays in the tunnel, where matchIP applies first-match order.
func (t *routeTable) directExclusions() []netip.Prefix {
	if t == nil {
		return nil
	}
	var ssh, out []netip.Prefix
	for _, r := range t.rules {
		if !r.prefix.IsValid() {
			continue
		}
		switch t.effective(r.action) {
		case routeSSH:
			ssh = append(ssh, r.prefix)
		case routeDirect:
			if !r.prefix.Overlaps(fakeIPPrefix) && !slices.ContainsFunc(ssh, r.prefix.Overlaps) {
				out = append(out, r.prefix)
			}
		}
	}
	return out
}

// dnsDomains returns the domain suffixes whose queries the tunnel must see to
// apply host rules with action a. A glob with no literal dot suffix (e.g. "*")
// yields "", meaning every query.
func (t *routeTable) dnsDomains(a routeAction) []string {
	if t == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	add := func(d string) {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	for _, r := range t.rules {
		if !r.isHostRule() || t.effective(r.action) != a {
			continue
		}
		if r.domain != "" {
			add(r.domain)
			continue
		}
		add(globSuffix(r.glob))
	}
	return out
}

// globSuffix is the longest dot-led literal tail of a glob, without the dot:
// "*.corp.example.com" and "api-?.example.com" give the names a resolver must
// route to us. "" means the pattern can match any name.
func globSuffix(glob string) string {
	i := strings.LastIndexAny(glob, "*?")
	tail := glob[i+1:]
	if j := strings.IndexByte(tail, '.'); j >= 0 {
		return strings.Trim(tail[j:], ".")
	}
	return ""
}
