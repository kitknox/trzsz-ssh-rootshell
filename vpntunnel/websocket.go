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
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"unicode/utf8"
)

const wsFramePayloadCap = 64 << 10

// wsTap parses a WebSocket byte stream (one direction) passively and records
// each frame. It never alters the stream.
type wsTap struct {
	rec  *recorder
	path string
	dir  string // "out" (client→server) or "in"

	hdr       []byte
	need      int // header bytes needed for the current frame
	remaining uint64
	offset    uint64
	mask      [4]byte
	masked    bool
	op        byte
	fin       bool
	rsv1      bool
	length    uint64
	payload   []byte
	msgOp     byte // data opcode of the message being continued
	broken    bool
}

type wsFrameEvent struct {
	TS         float64 `json:"ts"`
	Dir        string  `json:"dir"`
	Op         byte    `json:"op"`
	Fin        bool    `json:"fin"`
	Len        uint64  `json:"len"`
	Text       *string `json:"text,omitempty"`
	B64        string  `json:"b64,omitempty"`
	Truncated  bool    `json:"truncated,omitempty"`
	Compressed bool    `json:"compressed,omitempty"`
}

func newWSTap(rec *recorder, txID, dir string) *wsTap {
	return &wsTap{rec: rec, path: "ws/" + txID + ".jsonl", dir: dir, need: 2}
}

func (t *wsTap) Write(p []byte) (int, error) {
	if t == nil || t.rec == nil || t.broken {
		return len(p), nil
	}
	n := len(p)
	for len(p) > 0 {
		if t.need > 0 {
			k := t.need - len(t.hdr)
			if k > len(p) {
				k = len(p)
			}
			t.hdr = append(t.hdr, p[:k]...)
			p = p[k:]
			if len(t.hdr) < t.need {
				break
			}
			if !t.parseHeader() {
				if t.broken {
					return n, nil
				}
				continue
			}
			if t.remaining == 0 {
				t.emit()
			}
			continue
		}
		k := uint64(len(p))
		if k > t.remaining {
			k = t.remaining
		}
		chunk := p[:k]
		if room := wsFramePayloadCap - uint64(len(t.payload)); room > 0 {
			take := chunk
			if uint64(len(take)) > room {
				take = take[:room]
			}
			start := len(t.payload)
			t.payload = append(t.payload, take...)
			if t.masked {
				for i := range take {
					t.payload[start+i] ^= t.mask[(t.offset+uint64(i))%4]
				}
			}
		}
		t.offset += k
		t.remaining -= k
		p = p[k:]
		if t.remaining == 0 {
			t.emit()
		}
	}
	return n, nil
}

// parseHeader returns true once the full header is in hdr.
func (t *wsTap) parseHeader() bool {
	b0, b1 := t.hdr[0], t.hdr[1]
	t.fin = b0&0x80 != 0
	t.rsv1 = b0&0x40 != 0
	t.op = b0 & 0x0f
	t.masked = b1&0x80 != 0
	l7 := b1 & 0x7f
	want := 2
	switch l7 {
	case 126:
		want += 2
	case 127:
		want += 8
	}
	if t.masked {
		want += 4
	}
	if len(t.hdr) < want {
		t.need = want
		return false
	}
	pos := 2
	switch l7 {
	case 126:
		t.length = uint64(binary.BigEndian.Uint16(t.hdr[2:4]))
		pos = 4
	case 127:
		t.length = binary.BigEndian.Uint64(t.hdr[2:10])
		pos = 10
		if t.length>>63 != 0 {
			t.broken = true
			return false
		}
	default:
		t.length = uint64(l7)
	}
	if t.masked {
		copy(t.mask[:], t.hdr[pos:pos+4])
	}
	t.remaining = t.length
	t.offset = 0
	t.payload = t.payload[:0]
	t.need = 0
	return true
}

func (t *wsTap) emit() {
	op := t.op
	if op == 1 || op == 2 {
		t.msgOp = op
	}
	effective := op
	if op == 0 {
		effective = t.msgOp
	}
	ev := wsFrameEvent{
		TS:         nowMs(),
		Dir:        t.dir,
		Op:         op,
		Fin:        t.fin,
		Len:        t.length,
		Truncated:  t.length > uint64(len(t.payload)),
		Compressed: t.rsv1,
	}
	if effective == 1 && !t.rsv1 && utf8.Valid(t.payload) {
		s := string(t.payload)
		ev.Text = &s
	} else if len(t.payload) > 0 {
		ev.B64 = base64.StdEncoding.EncodeToString(t.payload)
	}
	if b, err := json.Marshal(ev); err == nil {
		t.rec.appendFile(t.path, append(b, '\n'), true)
	}
	t.hdr = t.hdr[:0]
	t.need = 2
	t.payload = t.payload[:0]
}
