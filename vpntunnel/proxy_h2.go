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
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httputil"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/net/http2"
)

// HTTP/2 is proxied stream-by-stream: the client side is served by
// http2.Server, each stream is forwarded with ReverseProxy over a single
// upstream ClientConn. Header order is not preserved (http.Header is a map),
// so h2 headers are recorded sorted after the pseudo-headers.

type h2TxKey struct{}

type h2Tx struct {
	id         string
	rec        *recorder   // the session the request was recorded in
	rewrites   *rewriteSet // rules in force when the stream started
	resRules   []*compiledRewrite
	resApplied []string
	resSink    *bodySink
	err        string
	note       string
}

type h2Proxy struct {
	fc     *flowCtx
	meta   *connMeta
	rp     *httputil.ReverseProxy
	served atomic.Int32
}

type bufferPool struct{ p sync.Pool }

func (b *bufferPool) Get() []byte  { return *(b.p.Get().(*[]byte)) }
func (b *bufferPool) Put(v []byte) { b.p.Put(&v) }

var h2Buffers = &bufferPool{p: sync.Pool{New: func() any { b := make([]byte, 16<<10); return &b }}}

// h2Windows bounds what one intercepted h2 connection can buffer when a side
// reads slowly. iOS gets the tight budget (extension memory limit).
func h2Windows() (recvConn, recvStream, upConn, upStream int32) {
	if runtime.GOOS == "ios" {
		return 256 << 10, 64 << 10, 128 << 10, 64 << 10
	}
	return 1 << 20, 256 << 10, 1 << 20, 256 << 10
}

func serveHTTP2(fc *flowCtx, client *tls.Conn, up *tls.Conn, meta *connMeta) {
	recvConn, recvStream, upConn, upStream := h2Windows()
	t1 := &http.Transport{HTTP2: &http.HTTP2Config{
		MaxReceiveBufferPerConnection: int(recvConn),
		MaxReceiveBufferPerStream:     int(recvStream),
	}}
	t2, err := http2.ConfigureTransports(t1)
	if err != nil {
		_ = up.Close()
		return
	}
	t2.DisableCompression = true
	cc, err := t2.NewClientConn(up)
	if err != nil {
		_ = up.Close()
		return
	}
	defer cc.Close()

	p := &h2Proxy{fc: fc, meta: meta}
	p.rp = &httputil.ReverseProxy{
		Director:       p.direct,
		Transport:      cc,
		FlushInterval:  -1,
		BufferPool:     h2Buffers,
		ModifyResponse: p.modifyResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if tx, ok := r.Context().Value(h2TxKey{}).(*h2Tx); ok {
				tx.err = err.Error()
			}
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	srv := &http2.Server{
		MaxConcurrentStreams:         32,
		MaxUploadBufferPerConnection: upConn,
		MaxUploadBufferPerStream:     upStream,
		IdleTimeout:                  tcpIdleTimeout,
	}
	srv.ServeConn(client, &http2.ServeConnOpts{Context: fc.ctx, Handler: p, BaseConfig: &http.Server{}})
	meta.served = int(p.served.Load())
}

func (p *h2Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fc, meta := p.fc, p.meta
	rec := fc.rec()
	tx := &h2Tx{id: rec.nextTxID(), rec: rec, rewrites: liveRewrites()}
	rw := tx.rewrites
	started := nowMs()
	reused := p.served.Add(1) > 1

	host := r.Host
	if host == "" {
		host = meta.defaultHost
		r.Host = host
	}
	url := "https://" + strings.ToLower(host) + r.URL.RequestURI()
	reqRules := rw.matching("request", url)
	tx.resRules = rw.matching("response", url)
	reqApplied := applyHeaderRewrites(reqRules, httpHeaderEditor(r.Header))

	if hasBodyRule(reqRules) && r.Body != nil && r.ContentLength != 0 && rw.acquire() {
		ids, body, n := rewriteStream(r.Body, r.Header, reqRules)
		rw.release()
		r.Body = body
		if n >= 0 {
			r.ContentLength = n
		}
		reqApplied = append(reqApplied, ids...)
	}
	reqSink := rec.newBodySink(tx.id, "req")
	if r.Body != nil && reqSink != nil {
		r.Body = &teeBody{rc: r.Body, w: reqSink}
	}

	if rec != nil {
		rec.txCount.Add(1)
		rec.event(evTxStart{
			T: "txStart", ID: tx.id, Conn: meta.connID, TS: started,
			Method: r.Method, URL: url, Host: hostOnly(host), Scheme: "https", Proto: "HTTP/2.0",
			ReqHeaders: h2RequestPairs(r, host),
			Client:     meta.client, Server: meta.server, SNI: meta.sni, TLS: meta.tlsVersion, ALPN: meta.alpn,
			ConnectMs: ifFirst(!reused, meta.connectMs), TLSMs: ifFirst(!reused, meta.tlsMs), Reused: reused,
			Rewritten: reqApplied,
		})
	}

	p.rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), h2TxKey{}, tx)))
	endTx(rec, tx.id, reqSink, tx.resSink, tx.err, false, tx.note)
}

func (p *h2Proxy) direct(out *http.Request) {
	out.URL.Scheme = "https"
	out.URL.Host = out.Host
	if _, ok := out.Header["X-Forwarded-For"]; !ok {
		out.Header["X-Forwarded-For"] = nil // don't add one
	}
	if tx, ok := out.Context().Value(h2TxKey{}).(*h2Tx); ok && hasBodyRule(tx.resRules) && out.Header.Get("Accept-Encoding") != "" {
		out.Header.Set("Accept-Encoding", "gzip")
	}
}

func (p *h2Proxy) modifyResponse(resp *http.Response) error {
	tx, ok := resp.Request.Context().Value(h2TxKey{}).(*h2Tx)
	if !ok {
		return nil
	}
	rec := tx.rec
	tx.resApplied = applyHeaderRewrites(tx.resRules, httpHeaderEditor(resp.Header))
	if hasBodyRule(tx.resRules) && resp.Body != nil && tx.rewrites.acquire() {
		ids, body, n := rewriteStream(resp.Body, resp.Header, tx.resRules)
		tx.rewrites.release()
		resp.Body = body
		if n >= 0 {
			resp.ContentLength = n
		} else {
			tx.note = "body rewrite skipped (too large or undecodable)"
		}
		tx.resApplied = append(tx.resApplied, ids...)
	}
	if rec != nil {
		rec.event(evTxResponse{
			T: "txResponse", ID: tx.id, TS: nowMs(), Status: resp.StatusCode, Proto: "HTTP/2.0",
			ResHeaders: h2ResponsePairs(resp), Rewritten: tx.resApplied,
		})
		tx.resSink = rec.newBodySink(tx.id, "res")
		if resp.Body != nil {
			resp.Body = &teeBody{rc: resp.Body, w: tx.resSink}
		}
	}
	return nil
}

// rewriteStream buffers up to rewriteBufferLimit and applies body rules.
// n is the new length, or -1 when the body was left as-is.
func rewriteStream(body io.ReadCloser, h http.Header, rules []*compiledRewrite) ([]string, io.ReadCloser, int64) {
	data, err := io.ReadAll(io.LimitReader(body, rewriteBufferLimit+1))
	if err != nil || len(data) > rewriteBufferLimit {
		return nil, multiReadCloser{Reader: io.MultiReader(bytes.NewReader(data), body), c: body}, -1
	}
	_ = body.Close()
	decoded, ok := decodeBody(data, h.Get("Content-Encoding"))
	if !ok {
		return nil, io.NopCloser(bytes.NewReader(data)), -1
	}
	out, ids := applyBodyRewrites(rules, decoded)
	if len(ids) == 0 {
		return nil, io.NopCloser(bytes.NewReader(data)), int64(len(data))
	}
	h.Del("Content-Encoding")
	h.Set("Content-Length", strconv.Itoa(len(out)))
	return ids, io.NopCloser(bytes.NewReader(out)), int64(len(out))
}

type multiReadCloser struct {
	io.Reader
	c io.Closer
}

func (m multiReadCloser) Close() error { return m.c.Close() }

// teeBody copies everything read to w (the body sink).
type teeBody struct {
	rc io.ReadCloser
	w  io.Writer
}

func (t *teeBody) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 {
		_, _ = t.w.Write(p[:n])
	}
	return n, err
}

func (t *teeBody) Close() error { return t.rc.Close() }

func sortedHeaderPairs(h http.Header) [][2]string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out [][2]string
	for _, k := range keys {
		for _, v := range h[k] {
			out = append(out, [2]string{strings.ToLower(k), v})
		}
	}
	return out
}

func h2RequestPairs(r *http.Request, host string) [][2]string {
	out := [][2]string{{":method", r.Method}, {":scheme", "https"}, {":authority", host}, {":path", r.URL.RequestURI()}}
	return append(out, sortedHeaderPairs(r.Header)...)
}

func h2ResponsePairs(resp *http.Response) [][2]string {
	out := [][2]string{{":status", strconv.Itoa(resp.StatusCode)}}
	return append(out, sortedHeaderPairs(resp.Header)...)
}
