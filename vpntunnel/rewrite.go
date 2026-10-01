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
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	rewriteBufferLimit = 1 << 20 // bodies larger than this pass through unmodified
	rewriteDecodeLimit = 4 << 20
)

// rewriteRule mirrors Swift's CaptureRewriteRule.
type rewriteRule struct {
	ID        string `json:"id"`
	Enabled   bool   `json:"enabled"`
	Match     string `json:"match"`
	IsRegex   bool   `json:"isRegex"`
	Phase     string `json:"phase"`  // "request" | "response"
	Action    string `json:"action"` // "addHeader" | "setHeader" | "removeHeader" | "replaceBody"
	Header    string `json:"header,omitempty"`
	Value     string `json:"value,omitempty"`
	Find      string `json:"find,omitempty"`
	Replace   string `json:"replace,omitempty"`
	BodyRegex bool   `json:"bodyRegex,omitempty"`
}

type compiledRewrite struct {
	rule   rewriteRule
	glob   string
	urlRe  *regexp.Regexp
	bodyRe *regexp.Regexp
}

type rewriteSet struct {
	rules []*compiledRewrite
	sem   chan struct{} // bounds concurrently buffered bodies
}

func compileRewriteRules(rules []rewriteRule) *rewriteSet {
	n := 2
	if runtime.GOOS != "ios" {
		n = 8
	}
	s := &rewriteSet{sem: make(chan struct{}, n)}
	for _, r := range rules {
		if !r.Enabled || strings.TrimSpace(r.Match) == "" {
			continue
		}
		c := &compiledRewrite{rule: r}
		if r.IsRegex {
			re, err := regexp.Compile(r.Match)
			if err != nil {
				continue
			}
			c.urlRe = re
		} else {
			c.glob = normalizeURLGlob(r.Match)
		}
		if r.Action == "replaceBody" {
			if r.Find == "" {
				continue
			}
			if r.BodyRegex {
				re, err := regexp.Compile(r.Find)
				if err != nil {
					continue
				}
				c.bodyRe = re
			}
		}
		s.rules = append(s.rules, c)
	}
	return s
}

// normalizeURLGlob lets users write "api.example.com" or "*.example.com/v1/*".
func normalizeURLGlob(p string) string {
	p = strings.TrimSpace(p)
	if !strings.Contains(p, "://") {
		p = "*://" + p
	}
	rest := p[strings.Index(p, "://")+3:]
	if !strings.Contains(rest, "/") {
		p += "/*"
	}
	return p
}

func (c *compiledRewrite) matches(url string) bool {
	if c.urlRe != nil {
		return c.urlRe.MatchString(url)
	}
	return globMatch(c.glob, url)
}

func (s *rewriteSet) matching(phase, url string) []*compiledRewrite {
	if s == nil {
		return nil
	}
	var out []*compiledRewrite
	for _, c := range s.rules {
		if c.rule.Phase == phase && c.matches(url) {
			out = append(out, c)
		}
	}
	return out
}

func hasBodyRule(rules []*compiledRewrite) bool {
	for _, c := range rules {
		if c.rule.Action == "replaceBody" {
			return true
		}
	}
	return false
}

// acquire waits briefly for a body-buffer slot; false means skip the body rewrite.
func (s *rewriteSet) acquire() bool {
	select {
	case s.sem <- struct{}{}:
		return true
	case <-time.After(5 * time.Second):
		return false
	}
}

func (s *rewriteSet) release() { <-s.sem }

// headerEditor abstracts ordered h1 header lists and http.Header.
type headerEditor interface {
	add(name, value string)
	set(name, value string)
	del(name string)
}

// applyHeaderRewrites runs header actions in order and returns applied rule IDs.
func applyHeaderRewrites(rules []*compiledRewrite, h headerEditor) []string {
	var applied []string
	for _, c := range rules {
		r := c.rule
		switch r.Action {
		case "addHeader":
			h.add(r.Header, r.Value)
		case "setHeader":
			h.set(r.Header, r.Value)
		case "removeHeader":
			h.del(r.Header)
		default:
			continue
		}
		applied = append(applied, r.ID)
	}
	return applied
}

// applyBodyRewrites runs replaceBody actions on a decoded body.
func applyBodyRewrites(rules []*compiledRewrite, body []byte) ([]byte, []string) {
	var applied []string
	for _, c := range rules {
		if c.rule.Action != "replaceBody" {
			continue
		}
		var next []byte
		if c.bodyRe != nil {
			next = c.bodyRe.ReplaceAll(body, []byte(c.rule.Replace))
		} else {
			next = bytes.ReplaceAll(body, []byte(c.rule.Find), []byte(c.rule.Replace))
		}
		if !bytes.Equal(next, body) {
			applied = append(applied, c.rule.ID)
		}
		body = next
	}
	return body, applied
}

// decodeBody undoes a Content-Encoding. ok=false for encodings we can't
// decode (br, zstd), in which case the body must pass through untouched.
func decodeBody(data []byte, encoding string) ([]byte, bool) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	var r io.Reader
	switch enc {
	case "", "identity":
		return data, true
	case "gzip", "x-gzip":
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false
		}
		r = gz
	case "deflate":
		if zr, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
			r = zr
		} else {
			r = flate.NewReader(bytes.NewReader(data))
		}
	default:
		return nil, false
	}
	out, err := io.ReadAll(io.LimitReader(r, rewriteDecodeLimit+1))
	if err != nil || len(out) > rewriteDecodeLimit {
		return nil, false
	}
	return out, true
}

// httpHeaderEditor adapts http.Header.
type httpHeaderEditor http.Header

func (h httpHeaderEditor) add(name, value string) { http.Header(h).Add(name, value) }
func (h httpHeaderEditor) set(name, value string) { http.Header(h).Set(name, value) }
func (h httpHeaderEditor) del(name string)        { http.Header(h).Del(name) }
