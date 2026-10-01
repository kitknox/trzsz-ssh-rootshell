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
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	h1BufferSize      = 4096
	longLivedIdle     = 10 * time.Minute // WebSocket and event streams
	requestBodyWindow = 5 * time.Second  // wait for the request body after the response ends
)

// readerConn reads through r (a bufio.Reader over the same conn) so bytes it
// already buffered are not lost.
type readerConn struct {
	net.Conn
	r io.Reader
}

func (c readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// serveHTTP1 proxies HTTP/1.x requests on one client connection. up may be nil
// for plain HTTP, in which case the upstream is dialed on the first request.
func serveHTTP1(fc *flowCtx, client net.Conn, up net.Conn, meta *connMeta) {
	clientIdle := newIdleConn(client, tcpIdleTimeout)
	cr := bufio.NewReaderSize(clientIdle, h1BufferSize)
	var upIdle *idleConn
	var ur *bufio.Reader
	attachUp := func(c net.Conn) {
		upIdle = newIdleConn(c, tcpIdleTimeout)
		ur = bufio.NewReaderSize(upIdle, h1BufferSize)
	}
	if up != nil {
		attachUp(up)
	}
	defer func() {
		if upIdle != nil {
			_ = upIdle.Close()
		}
	}()

	for {
		rawHead, err := readHead(cr)
		if err != nil {
			return
		}
		req, err := parseRequestHead(rawHead)
		if err != nil {
			return
		}
		rec := fc.rec()
		txID := rec.nextTxID()
		started := nowMs()

		host := req.headers.get("Host")
		if host == "" {
			host = meta.defaultHost
		}
		url := buildURL(meta.scheme, host, req.target)

		rw := liveRewrites()
		reqRules := rw.matching("request", url)
		resRules := rw.matching("response", url)
		var reqApplied, resApplied []string
		headChanged := false
		if ids := applyHeaderRewrites(reqRules, &req.headers); len(ids) > 0 {
			reqApplied = append(reqApplied, ids...)
			headChanged = true
		}
		isWS := hasToken(req.headers.tokens("Upgrade"), "websocket")
		if isWS && req.headers.has("Sec-WebSocket-Extensions") {
			// No permessage-deflate, so captured frames stay readable.
			req.headers.del("Sec-WebSocket-Extensions")
			headChanged = true
		}
		bufferRes := hasBodyRule(resRules) && !isWS
		if bufferRes && !strings.EqualFold(req.headers.get("Accept-Encoding"), "gzip") && req.headers.has("Accept-Encoding") {
			req.headers.set("Accept-Encoding", "gzip") // a body we can decode and rewrite
			headChanged = true
		}

		reqKind, reqLen, err := requestFraming(req)
		if err != nil {
			return
		}
		meta.served++
		reused := meta.served > 1

		if ur == nil {
			t0 := time.Now()
			c, err := fc.dial(fc.ctx)
			if err != nil {
				writeProxyError(client, 502, "upstream connect failed: "+err.Error())
				recordTxFailure(rec, txID, meta, req, url, host, started, err.Error())
				return
			}
			meta.connectMs = msSince(t0)
			attachUp(c)
		}

		// Request body: buffered when a rewrite needs the whole thing,
		// otherwise streamed concurrently with reading the response so
		// Expect: 100-continue and early responses work.
		reqSink := rec.newBodySink(txID, "req")
		reqBodyDone := make(chan error, 1)
		bufferReq := hasBodyRule(reqRules) && reqKind != framingNone
		if bufferReq && rw.acquire() {
			if hasToken(req.headers.tokens("Expect"), "100-continue") {
				req.headers.del("Expect")
				headChanged = true
				_, _ = client.Write([]byte("HTTP/1.1 100 Continue\r\n\r\n"))
			}
			ids, err := forwardBufferedBody(upIdle, cr, reqKind, reqLen, reqSink, reqRules, req.headers.get("Content-Encoding"),
				func(newBody []byte) []byte {
					if newBody != nil {
						req.headers.del("Transfer-Encoding")
						req.headers.del("Content-Encoding")
						req.headers.set("Content-Length", strconv.Itoa(len(newBody)))
						return req.serialize()
					}
					if headChanged {
						return req.serialize()
					}
					return rawHead
				})
			rw.release()
			reqApplied = append(reqApplied, ids...)
			reqBodyDone <- err
			if err != nil {
				return
			}
		} else {
			head := rawHead
			if headChanged {
				head = req.serialize()
			}
			if _, err := upIdle.Write(head); err != nil {
				recordTxFailure(rec, txID, meta, req, url, host, started, err.Error())
				return
			}
			go func() {
				reqBodyDone <- copyBody(upIdle, cr, reqKind, reqLen, reqSink)
			}()
		}
		sentHead := rawHead
		if headChanged || len(reqApplied) > 0 {
			sentHead = req.serialize()
		}
		if rec != nil {
			rec.txCount.Add(1)
			rec.event(evTxStart{
				T: "txStart", ID: txID, Conn: meta.connID, TS: started,
				Method: req.method, URL: url, Host: hostOnly(host), Scheme: meta.scheme, Proto: req.proto,
				ReqHeaders: req.headers.pairs(), ReqHead: string(sentHead),
				Client: meta.client, Server: meta.server, SNI: meta.sni, TLS: meta.tlsVersion, ALPN: meta.alpn,
				ConnectMs: ifFirst(!reused, meta.connectMs), TLSMs: ifFirst(!reused, meta.tlsMs), Reused: reused,
				Rewritten: reqApplied,
			})
		}

		// Response head, forwarding interim 1xx responses.
		var res *resHead
		var resRaw []byte
		for {
			resRaw, err = readHead(ur)
			if err != nil {
				writeProxyError(client, 502, "upstream closed before responding")
				endTx(rec, txID, reqSink, nil, "upstream: "+err.Error(), false, "")
				return
			}
			res, err = parseResponseHead(resRaw)
			if err != nil {
				endTx(rec, txID, reqSink, nil, err.Error(), false, "")
				return
			}
			if res.status >= 100 && res.status < 200 && res.status != 101 {
				if _, err := client.Write(resRaw); err != nil {
					return
				}
				continue
			}
			break
		}
		resHeadChanged := false
		if ids := applyHeaderRewrites(resRules, &res.headers); len(ids) > 0 {
			resApplied = append(resApplied, ids...)
			resHeadChanged = true
		}
		emitResponse := func(head []byte) {
			if rec != nil {
				rec.event(evTxResponse{
					T: "txResponse", ID: txID, TS: nowMs(), Status: res.status, Reason: res.reason, Proto: res.proto,
					ResHeaders: res.headers.pairs(), ResHead: string(head), Rewritten: resApplied,
				})
			}
		}

		// 101 (WebSocket and other upgrades) and a successful CONNECT both turn
		// the connection into a raw byte stream; the buffered readers carry over.
		if res.status == 101 || (req.method == "CONNECT" && res.status >= 200 && res.status < 300) {
			head := resRaw
			if resHeadChanged {
				head = res.serialize()
			}
			if _, err := client.Write(head); err != nil {
				return
			}
			emitResponse(head)
			waitBody(reqBodyDone)
			clientIdle.setIdle(longLivedIdle)
			upIdle.setIdle(longLivedIdle)
			var outTap, inTap io.Writer = io.Discard, io.Discard
			if rec != nil && isWS {
				rec.markWebSocket(txID)
				outTap = newWSTap(rec, txID, "out")
				inTap = newWSTap(rec, txID, "in")
			}
			clientSide := readerConn{Conn: clientIdle, r: io.TeeReader(cr, outTap)}
			upSide := readerConn{Conn: upIdle, r: io.TeeReader(ur, inTap)}
			upBytes, downBytes := relayConns(fc.ctx, clientSide, clientIdle, upSide)
			rec.endTxOnce(txID, evTxEnd{T: "txEnd", ID: txID, TS: nowMs(), ReqBytes: upBytes, ResBytes: downBytes, WS: isWS})
			return
		}

		if strings.Contains(strings.ToLower(res.headers.get("Content-Type")), "text/event-stream") {
			clientIdle.setIdle(longLivedIdle)
			upIdle.setIdle(longLivedIdle)
		}
		resKind, resLen, err := responseFraming(req.method, res)
		if err != nil {
			return
		}
		resSink := rec.newBodySink(txID, "res")
		var bodyErr error
		note := ""
		if bufferRes && resKind != framingNone && rw.acquire() {
			var sent []byte
			ids, err := forwardBufferedBody(client, ur, resKind, resLen, resSink, resRules, res.headers.get("Content-Encoding"),
				func(newBody []byte) []byte {
					if newBody != nil {
						res.headers.del("Transfer-Encoding")
						res.headers.del("Content-Encoding")
						res.headers.set("Content-Length", strconv.Itoa(len(newBody)))
						sent = res.serialize()
					} else if resHeadChanged {
						sent = res.serialize()
					} else {
						sent = resRaw
					}
					return sent
				})
			rw.release()
			resApplied = append(resApplied, ids...)
			emitResponse(sent)
			bodyErr = err
			if err == nil && len(ids) == 0 {
				note = "body rewrite did not apply"
			}
		} else {
			head := resRaw
			if resHeadChanged {
				head = res.serialize()
			}
			if _, err := client.Write(head); err != nil {
				return
			}
			emitResponse(head)
			bodyErr = copyBody(client, ur, resKind, resLen, resSink)
		}
		reqErr := waitBody(reqBodyDone)
		errText := ""
		if bodyErr != nil && bodyErr != io.EOF {
			errText = bodyErr.Error()
		} else if reqErr != nil && reqErr != io.EOF {
			errText = "request body: " + reqErr.Error()
		}
		endTx(rec, txID, reqSink, resSink, errText, false, note)

		if bodyErr != nil || reqErr != nil || resKind == framingUntilClose || !keepAlive(req.proto, req.headers) || !keepAlive(res.proto, res.headers) {
			return
		}
	}
}

// forwardBufferedBody reads a whole body for rewriting. If it fits, the
// rewritten (or original) message is written via headFor; if it is too big,
// the original head and body stream through untouched.
func forwardBufferedBody(dst io.Writer, src *bufio.Reader, kind framingKind, n int64, sink *bodySink,
	rules []*compiledRewrite, encoding string, headFor func(newBody []byte) []byte) ([]string, error) {
	sp := &spillBuffer{limit: rewriteBufferLimit, dst: dst}
	sp.sink = sinkWriter(sink)
	sp.onSpill = func() error {
		_, err := dst.Write(headFor(nil))
		return err
	}
	if err := copyBody(spillRaw{sp}, src, kind, n, spillData{sp}); err != nil {
		return nil, err
	}
	if sp.spilled {
		return nil, nil
	}
	decoded, ok := decodeBody(sp.data.Bytes(), encoding)
	if ok {
		if out, ids := applyBodyRewrites(rules, decoded); len(ids) > 0 {
			if _, err := dst.Write(append(headFor(out), out...)); err != nil {
				return nil, err
			}
			_, _ = sinkWriter(sink).Write(out)
			return ids, nil
		}
	}
	if _, err := dst.Write(append(headFor(nil), sp.raw.Bytes()...)); err != nil {
		return nil, err
	}
	_, _ = sinkWriter(sink).Write(sp.data.Bytes())
	return nil, nil
}

func sinkWriter(s *bodySink) io.Writer {
	if s == nil {
		return io.Discard
	}
	return s
}

func waitBody(ch chan error) error {
	select {
	case err := <-ch:
		return err
	case <-time.After(requestBodyWindow):
		return io.ErrUnexpectedEOF
	}
}

func endTx(rec *recorder, txID string, reqSink, resSink *bodySink, errText string, ws bool, note string) {
	if rec == nil {
		return
	}
	ev := evTxEnd{T: "txEnd", ID: txID, TS: nowMs(), Error: errText, WS: ws, Note: note}
	ev.ReqBodyFile, _, ev.ReqBytes, ev.ReqTruncated = reqSink.finish()
	ev.ResBodyFile, _, ev.ResBytes, ev.ResTruncated = resSink.finish()
	rec.endTxOnce(txID, ev)
}

func recordTxFailure(rec *recorder, txID string, meta *connMeta, req *reqHead, url, host string, started float64, errText string) {
	if rec == nil {
		return
	}
	rec.txCount.Add(1)
	rec.event(evTxStart{T: "txStart", ID: txID, Conn: meta.connID, TS: started, Method: req.method, URL: url,
		Host: hostOnly(host), Scheme: meta.scheme, Proto: req.proto, ReqHeaders: req.headers.pairs(),
		Client: meta.client, Server: meta.server, SNI: meta.sni})
	rec.endTxOnce(txID, evTxEnd{T: "txEnd", ID: txID, TS: nowMs(), Error: errText})
}

func ifFirst(first bool, v float64) float64 {
	if first {
		return v
	}
	return 0
}

func keepAlive(proto string, hs hdrList) bool {
	conn := hs.tokens("Connection")
	if hasToken(conn, "close") {
		return false
	}
	if proto == "HTTP/1.0" {
		return hasToken(conn, "keep-alive")
	}
	return true
}

func buildURL(scheme, host, target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
	if target == "*" {
		target = ""
	}
	return scheme + "://" + strings.ToLower(host) + target
}

// hostOnly strips a port from an authority.
func hostOnly(authority string) string {
	if h, _, err := net.SplitHostPort(authority); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(strings.Trim(authority, "[]"))
}

func writeProxyError(w io.Writer, status int, msg string) {
	body := "rootshell capture: " + msg + "\n"
	var b bytes.Buffer
	b.WriteString("HTTP/1.1 " + strconv.Itoa(status) + " Bad Gateway\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n")
	b.WriteString(body)
	_, _ = w.Write(b.Bytes())
}
