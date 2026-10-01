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
	"strconv"
	"strings"
)

// hostRule is one Surge-style MITM hostname entry:
//
//	*.example.com      glob (* any run, ? one char), port 443
//	-*.apple.com       exclusion
//	example.com:8443   explicit port; :0 means any port
//	*                  everything on 443
//
// The first matching rule wins; no match means "do not intercept".
type hostRule struct {
	exclude bool
	pattern string
	port    int // -1 = default (443), 0 = any
	isIP    bool
}

type hostMatcher struct {
	rules   []hostRule
	ports   map[int]bool // explicit non-default ports named by include rules
	anyPort bool         // an include rule uses :0, so every port is worth peeking at
}

func compileHostRules(entries []string) *hostMatcher {
	m := &hostMatcher{ports: make(map[int]bool)}
	for _, raw := range entries {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		r := hostRule{port: -1}
		if strings.HasPrefix(s, "-") {
			r.exclude = true
			s = strings.TrimSpace(s[1:])
		}
		s = strings.TrimSuffix(s, ".")
		if host, portStr, ok := splitRulePort(s); ok {
			if p, err := strconv.Atoi(portStr); err == nil && p >= 0 && p <= 65535 {
				s = host
				r.port = p
			}
		}
		s = strings.Trim(s, "[]")
		if s == "" {
			continue
		}
		r.pattern = s
		r.isIP = net.ParseIP(s) != nil
		if !r.exclude && r.port > 0 {
			m.ports[r.port] = true
		}
		if !r.exclude && r.port == 0 {
			m.anyPort = true
		}
		m.rules = append(m.rules, r)
	}
	return m
}

// splitRulePort splits "host:port" but leaves bare IPv6 literals alone.
func splitRulePort(s string) (string, string, bool) {
	if strings.HasPrefix(s, "[") {
		if i := strings.LastIndex(s, "]:"); i > 0 {
			return s[:i+1], s[i+2:], true
		}
		return s, "", false
	}
	if strings.Count(s, ":") != 1 {
		return s, "", false
	}
	i := strings.LastIndexByte(s, ':')
	return s[:i], s[i+1:], true
}

func (r hostRule) portMatches(port int) bool {
	switch r.port {
	case -1:
		return port == 443
	case 0:
		return true
	default:
		return port == r.port
	}
}

// match reports whether host:port should be intercepted.
func (m *hostMatcher) match(host string, port int) bool {
	if m == nil || host == "" {
		return false
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, r := range m.rules {
		if !r.portMatches(port) {
			continue
		}
		if globMatch(r.pattern, host) {
			return !r.exclude
		}
	}
	return false
}

// hasExplicitPort reports whether an include rule names this port, so flows
// on it are worth peeking at.
func (m *hostMatcher) hasExplicitPort(port int) bool {
	return m != nil && (m.anyPort || m.ports[port])
}

// globMatch matches s against a pattern with * (any run) and ? (one char).
func globMatch(pattern, s string) bool {
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			star = p
			mark = i
			p++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
