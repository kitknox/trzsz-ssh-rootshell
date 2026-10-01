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
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

const caIndexPage = `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>rootshell Capture CA</title>
<style>body{font:17px -apple-system,system-ui,sans-serif;max-width:32em;margin:2em auto;padding:0 1em;line-height:1.5}
a{display:block;margin:.6em 0;padding:.8em 1em;border-radius:10px;background:#0a84ff;color:#fff;text-decoration:none;text-align:center}
@media(prefers-color-scheme:dark){body{background:#000;color:#eee}}</style></head><body>
<h2>rootshell Capture CA</h2>
<p>Install this certificate so rootshell can decrypt HTTPS traffic for the hosts you choose.</p>
<a href="/ca.mobileconfig">Install profile (iOS, iPadOS, visionOS)</a>
<a href="/ca.cer">Download certificate (.cer)</a>
<a href="/ca.pem">Download certificate (.pem)</a>
<p>On iOS, install the downloaded profile in Settings, then enable full trust under General › About › Certificate Trust Settings.</p>
</body></html>`

// serveCAEndpoint answers plain HTTP on the tunnel gateway with the capture CA.
func serveCAEndpoint(fc *flowCtx) {
	cs := fc.cs
	br := bufio.NewReader(fc.client)
	_ = fc.client.SetDeadline(time.Now().Add(30 * time.Second))
	for {
		raw, err := readHead(br)
		if err != nil {
			return
		}
		req, err := parseRequestHead(raw)
		if err != nil {
			return
		}
		path := req.target
		if i := strings.IndexAny(path, "?#"); i >= 0 {
			path = path[:i]
		}
		var body []byte
		ctype := "text/html; charset=utf-8"
		extra := ""
		status := "200 OK"
		switch {
		case path == "/ca.mobileconfig" && cs.caProfile != nil:
			body = cs.caProfile
			ctype = "application/x-apple-aspen-config"
			extra = "Content-Disposition: attachment; filename=\"rootshell-capture-ca.mobileconfig\"\r\n"
		case path == "/ca.cer" && cs.minter != nil:
			body = cs.minter.caDER()
			ctype = "application/x-x509-ca-cert"
			extra = "Content-Disposition: attachment; filename=\"rootshell-capture-ca.cer\"\r\n"
		case path == "/ca.pem" && cs.minter != nil:
			body = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cs.minter.caDER()})
			ctype = "application/x-pem-file"
			extra = "Content-Disposition: attachment; filename=\"rootshell-capture-ca.pem\"\r\n"
		case path == "/" || path == "/ca":
			body = []byte(caIndexPage)
		default:
			status = "404 Not Found"
			body = []byte("not found\n")
			ctype = "text/plain; charset=utf-8"
		}
		head := fmt.Sprintf("HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nCache-Control: no-store\r\n%s\r\n", status, ctype, len(body), extra)
		if req.method == "HEAD" {
			body = nil
		}
		if _, err := fc.client.Write(append([]byte(head), body...)); err != nil {
			return
		}
		if strings.EqualFold(req.headers.get("Connection"), "close") {
			return
		}
	}
}
