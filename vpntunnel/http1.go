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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Minimal HTTP/1.x message handling that keeps heads byte-exact (case and
// order) and forwards body framing untouched unless a rewrite needs it.

const maxHeadBytes = 64 << 10

var errHeadTooLarge = errors.New("http head too large")

type hdr struct{ name, value string }

type hdrList []hdr

func (h hdrList) get(name string) string {
	for _, kv := range h {
		if strings.EqualFold(kv.name, name) {
			return kv.value
		}
	}
	return ""
}

func (h hdrList) has(name string) bool {
	for _, kv := range h {
		if strings.EqualFold(kv.name, name) {
			return true
		}
	}
	return false
}

func (h hdrList) pairs() [][2]string {
	out := make([][2]string, len(h))
	for i, kv := range h {
		out[i] = [2]string{kv.name, kv.value}
	}
	return out
}

// tokens returns the comma-separated, lower-cased tokens of every field named name.
func (h hdrList) tokens(name string) []string {
	var out []string
	for _, kv := range h {
		if strings.EqualFold(kv.name, name) {
			for _, t := range strings.Split(kv.value, ",") {
				if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
					out = append(out, t)
				}
			}
		}
	}
	return out
}

func (h *hdrList) add(name, value string) { *h = append(*h, hdr{name, value}) }

func (h *hdrList) set(name, value string) {
	found := false
	out := (*h)[:0]
	for _, kv := range *h {
		if strings.EqualFold(kv.name, name) {
			if found {
				continue
			}
			kv.value = value
			found = true
		}
		out = append(out, kv)
	}
	*h = out
	if !found {
		h.add(name, value)
	}
}

func (h *hdrList) del(name string) {
	out := (*h)[:0]
	for _, kv := range *h {
		if !strings.EqualFold(kv.name, name) {
			out = append(out, kv)
		}
	}
	*h = out
}

func hasToken(tokens []string, tok string) bool {
	for _, t := range tokens {
		if t == tok {
			return true
		}
	}
	return false
}

type reqHead struct {
	method, target, proto string
	headers               hdrList
}

type resHead struct {
	proto   string
	status  int
	reason  string
	headers hdrList
}

// readHead returns the raw head including the terminating blank line.
// Stray CRLFs before a request line are skipped (RFC 9112 §2.2).
func readHead(br *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := br.ReadSlice('\n')
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			if buf.Len() == 0 && len(line) == 0 {
				return nil, err
			}
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if buf.Len() == 0 && (string(line) == "\r\n" || string(line) == "\n") {
			continue
		}
		buf.Write(line)
		if buf.Len() > maxHeadBytes {
			return nil, errHeadTooLarge
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if string(line) == "\r\n" || string(line) == "\n" {
			return buf.Bytes(), nil
		}
	}
}

func splitHeadLines(raw []byte) (string, hdrList, error) {
	text := strings.TrimRight(string(raw), "\r\n")
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return "", nil, errors.New("empty head")
	}
	first := strings.TrimRight(lines[0], "\r")
	var hs hdrList
	for _, l := range lines[1:] {
		l = strings.TrimRight(l, "\r")
		if l == "" {
			continue
		}
		if (l[0] == ' ' || l[0] == '\t') && len(hs) > 0 {
			hs[len(hs)-1].value += " " + strings.TrimSpace(l) // obs-fold
			continue
		}
		i := strings.IndexByte(l, ':')
		if i <= 0 {
			return "", nil, fmt.Errorf("malformed header line %q", l)
		}
		hs = append(hs, hdr{name: l[:i], value: strings.TrimSpace(l[i+1:])})
	}
	return first, hs, nil
}

func parseRequestHead(raw []byte) (*reqHead, error) {
	first, hs, err := splitHeadLines(raw)
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(first, " ", 3)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return nil, fmt.Errorf("malformed request line %q", first)
	}
	return &reqHead{method: parts[0], target: parts[1], proto: parts[2], headers: hs}, nil
}

func parseResponseHead(raw []byte) (*resHead, error) {
	first, hs, err := splitHeadLines(raw)
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(first, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return nil, fmt.Errorf("malformed status line %q", first)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil || code < 100 || code > 999 {
		return nil, fmt.Errorf("malformed status code %q", parts[1])
	}
	r := &resHead{proto: parts[0], status: code, headers: hs}
	if len(parts) == 3 {
		r.reason = parts[2]
	}
	return r, nil
}

func serializeHead(first string, hs hdrList) []byte {
	var b bytes.Buffer
	b.WriteString(first)
	b.WriteString("\r\n")
	for _, kv := range hs {
		b.WriteString(kv.name)
		b.WriteString(": ")
		b.WriteString(kv.value)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

func (r *reqHead) serialize() []byte {
	return serializeHead(r.method+" "+r.target+" "+r.proto, r.headers)
}

func (r *resHead) serialize() []byte {
	first := r.proto + " " + strconv.Itoa(r.status)
	if r.reason != "" {
		first += " " + r.reason
	}
	return serializeHead(first, r.headers)
}

type framingKind int

const (
	framingNone framingKind = iota
	framingLength
	framingChunked
	framingUntilClose
)

func contentLength(hs hdrList) (int64, bool, error) {
	v := ""
	for _, kv := range hs {
		if strings.EqualFold(kv.name, "Content-Length") {
			val := strings.TrimSpace(kv.value)
			if v != "" && v != val {
				return 0, true, errors.New("conflicting Content-Length")
			}
			v = val
		}
	}
	if v == "" {
		return 0, false, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, true, fmt.Errorf("bad Content-Length %q", v)
	}
	return n, true, nil
}

func requestFraming(r *reqHead) (framingKind, int64, error) {
	if te := r.headers.tokens("Transfer-Encoding"); len(te) > 0 {
		if te[len(te)-1] == "chunked" {
			return framingChunked, 0, nil
		}
		return 0, 0, errors.New("unsupported request transfer-encoding")
	}
	n, ok, err := contentLength(r.headers)
	if err != nil {
		return 0, 0, err
	}
	if ok && n > 0 {
		return framingLength, n, nil
	}
	return framingNone, 0, nil
}

func responseFraming(method string, r *resHead) (framingKind, int64, error) {
	if method == "HEAD" || r.status == 204 || r.status == 304 || (r.status >= 100 && r.status < 200) {
		return framingNone, 0, nil
	}
	if method == "CONNECT" && r.status >= 200 && r.status < 300 {
		return framingUntilClose, 0, nil
	}
	if te := r.headers.tokens("Transfer-Encoding"); len(te) > 0 {
		if te[len(te)-1] == "chunked" {
			return framingChunked, 0, nil
		}
		return framingUntilClose, 0, nil
	}
	n, ok, err := contentLength(r.headers)
	if err != nil {
		return 0, 0, err
	}
	if ok {
		if n == 0 {
			return framingNone, 0, nil
		}
		return framingLength, n, nil
	}
	return framingUntilClose, 0, nil
}

// copyBody forwards one body with its original framing to dst and writes the
// de-framed payload to sink (sink is written before dst for every piece).
func copyBody(dst io.Writer, src *bufio.Reader, kind framingKind, n int64, sink io.Writer) error {
	if sink == nil {
		sink = io.Discard
	}
	switch kind {
	case framingNone:
		return nil
	case framingLength:
		_, err := io.CopyN(dst, io.TeeReader(src, sink), n)
		return err
	case framingUntilClose:
		_, err := io.Copy(dst, io.TeeReader(src, sink))
		return err
	case framingChunked:
		return copyChunked(dst, src, sink)
	}
	return nil
}

func copyChunked(dst io.Writer, src *bufio.Reader, sink io.Writer) error {
	for {
		line, err := readLine(src)
		if err != nil {
			return err
		}
		sizeStr := strings.TrimSpace(string(line))
		if i := strings.IndexByte(sizeStr, ';'); i >= 0 {
			sizeStr = strings.TrimSpace(sizeStr[:i])
		}
		size, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil || size < 0 {
			return fmt.Errorf("bad chunk size %q", sizeStr)
		}
		if _, err := dst.Write(line); err != nil {
			return err
		}
		if size == 0 {
			for {
				tl, err := readLine(src)
				if err != nil {
					return err
				}
				if _, err := dst.Write(tl); err != nil {
					return err
				}
				if string(tl) == "\r\n" || string(tl) == "\n" {
					return nil
				}
			}
		}
		if _, err := io.CopyN(dst, io.TeeReader(src, sink), size); err != nil {
			return err
		}
		crlf, err := readLine(src)
		if err != nil {
			return err
		}
		if _, err := dst.Write(crlf); err != nil {
			return err
		}
	}
}

func readLine(br *bufio.Reader) ([]byte, error) {
	line, err := br.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, errors.New("chunk line too long")
		}
		return nil, err
	}
	return append([]byte(nil), line...), nil
}

// spillBuffer holds a framed body (raw) and its payload (data) for a rewrite.
// Once the payload exceeds limit it gives up: onSpill writes the head, the
// buffered raw bytes are flushed, and the rest streams straight to dst.
type spillBuffer struct {
	raw, data bytes.Buffer
	limit     int
	spilled   bool
	dst       io.Writer
	onSpill   func() error
	sink      io.Writer // recorder; only fed once spilled
	err       error
}

// rawLimit bounds the framed bytes too: tiny chunks with long extensions or
// large trailers must not grow the buffer while the payload stays small.
func (s *spillBuffer) rawLimit() int { return s.limit + 64<<10 }

// spill writes the head and everything buffered so far, then streams the rest.
func (s *spillBuffer) spill() error {
	if err := s.onSpill(); err != nil {
		s.err = err
		return err
	}
	if _, err := s.dst.Write(s.raw.Bytes()); err != nil {
		s.err = err
		return err
	}
	if s.sink != nil {
		_, _ = s.sink.Write(s.data.Bytes())
	}
	s.raw.Reset()
	s.data.Reset()
	s.spilled = true
	return nil
}

type spillRaw struct{ s *spillBuffer }

func (w spillRaw) Write(p []byte) (int, error) {
	s := w.s
	if s.err != nil {
		return 0, s.err
	}
	if !s.spilled && s.raw.Len()+len(p) > s.rawLimit() {
		if err := s.spill(); err != nil {
			return 0, err
		}
	}
	if s.spilled {
		return s.dst.Write(p)
	}
	return s.raw.Write(p)
}

type spillData struct{ s *spillBuffer }

func (w spillData) Write(p []byte) (int, error) {
	s := w.s
	if s.spilled {
		if s.sink != nil {
			_, _ = s.sink.Write(p)
		}
		return len(p), nil
	}
	s.data.Write(p)
	if s.data.Len() > s.limit {
		if err := s.spill(); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}
