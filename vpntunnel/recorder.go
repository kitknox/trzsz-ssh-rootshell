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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	recorderQueueLimit   = 2 << 20 // droppable bytes queued before body/packet data is dropped
	recorderMaxQueuedOps = 8192
	recorderMaxOpenFiles = 64
	indexFileName        = "index.jsonl"
	packetsFileName      = "packets.bin"
	keylogFileName       = "keylog.txt"
)

// Spool layout (one directory per session, shared by every segment):
//
//	index.jsonl          one JSON event per line (see ev* types)
//	bodies/<txid>.req    request body as received (content-encoded, de-chunked)
//	bodies/<txid>.res    response body as received
//	ws/<txid>.jsonl      WebSocket frames
//	packets.bin          TUN packets: u64 unix-ns, u32 len, u8 dir (0 out, 1 in), payload
//	keylog.txt           NSS key log for MITM client-side TLS
type recorder struct {
	dir        string
	sessionID  string
	nonce      string
	maxBody    atomic.Int64 // updated live by CaptureConfigure
	maxSession atomic.Int64

	mu      sync.Mutex
	queue   []recOp
	qBytes  int64
	wake    chan struct{}
	closing bool
	done    chan struct{}

	// active: accepting new data. halted: limit hit or write failed, so even
	// queued data is discarded. Stopping clears active but drains the queue.
	active     atomic.Bool
	halted     atomic.Bool
	stopReason atomic.Value // string
	txSeq      atomic.Int64
	connSeq    atomic.Int64

	written     atomic.Int64
	dropped     atomic.Int64
	txCount     atomic.Int64
	tunnelCount atomic.Int64
	rejected    atomic.Int64
	failures    atomic.Int64

	// writer goroutine only
	files map[string]*os.File
	order []string
}

type recOp struct {
	path      string // relative to dir; "" = close-all marker
	data      []byte
	close     bool
	droppable bool
}

func newRecorder(dir, sessionID, nonce string, maxBody, maxSession int64, transport string) (*recorder, error) {
	for _, sub := range []string{"", "bodies", "ws"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, fmt.Errorf("capture spool: %w", err)
		}
	}
	r := &recorder{
		dir:       dir,
		sessionID: sessionID,
		nonce:     nonce,
		wake:      make(chan struct{}, 1),
		done:      make(chan struct{}),
		files:     make(map[string]*os.File),
	}
	r.maxBody.Store(maxBody)
	r.maxSession.Store(maxSession)
	// A resumed session counts everything already on disk toward its limit.
	r.written.Store(directorySize(dir))
	r.active.Store(true)
	go r.run()
	r.event(evSegment{T: "segment", TS: nowMs(), Seg: nonce, Session: sessionID, Transport: transport})
	return r, nil
}

func nowMs() float64 { return float64(time.Now().UnixNano()) / 1e6 }

func directorySize(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}

// A nil *recorder is valid everywhere and records nothing, so proxy code can
// keep running after recording stops.

func (r *recorder) nextTxID() string {
	if r == nil {
		return ""
	}
	return r.nonce + "-" + strconv.FormatInt(r.txSeq.Add(1), 10)
}

func (r *recorder) nextConnID() string {
	if r == nil {
		return ""
	}
	return r.nonce + "-c" + strconv.FormatInt(r.connSeq.Add(1), 10)
}

func (r *recorder) isActive() bool { return r != nil && r.active.Load() }

// event appends one JSON line to the index. Events are never dropped for
// size, only when the op queue itself is saturated.
func (r *recorder) event(v any) {
	if r == nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	r.enqueue(recOp{path: indexFileName, data: append(b, '\n')})
}

func (r *recorder) appendFile(rel string, data []byte, droppable bool) {
	r.enqueue(recOp{path: rel, data: data, droppable: droppable})
}

func (r *recorder) closeFile(rel string) {
	r.enqueue(recOp{path: rel, close: true})
}

func (r *recorder) enqueue(op recOp) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.closing || (op.data != nil && !r.active.Load() && op.path != indexFileName) {
		r.mu.Unlock()
		return
	}
	if len(r.queue) >= recorderMaxQueuedOps || (op.droppable && r.qBytes+int64(len(op.data)) > recorderQueueLimit) {
		r.mu.Unlock()
		r.dropped.Add(int64(len(op.data)))
		return
	}
	r.queue = append(r.queue, op)
	if op.droppable {
		r.qBytes += int64(len(op.data))
	}
	r.mu.Unlock()
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *recorder) run() {
	defer close(r.done)
	for {
		<-r.wake
		r.mu.Lock()
		ops := r.queue
		r.queue = nil
		r.qBytes = 0
		closing := r.closing
		r.mu.Unlock()

		for _, op := range ops {
			r.apply(op)
		}
		if closing {
			r.mu.Lock()
			rest := r.queue
			r.queue = nil
			r.mu.Unlock()
			for _, op := range rest {
				r.apply(op)
			}
			for _, f := range r.files {
				_ = f.Close()
			}
			r.files = nil
			return
		}
	}
}

func (r *recorder) apply(op recOp) {
	if op.close {
		if f, ok := r.files[op.path]; ok {
			_ = f.Close()
			delete(r.files, op.path)
		}
		return
	}
	if len(op.data) == 0 {
		return
	}
	if op.path != indexFileName && r.halted.Load() {
		return
	}
	f, err := r.file(op.path)
	if err == nil {
		_, err = f.Write(op.data)
	}
	if err != nil {
		// Typically "before first unlock": stop rather than spin on errors.
		log.Printf("vpntunnel: capture write %s: %v", op.path, err)
		r.autoStop("writeError")
		return
	}
	total := r.written.Add(int64(len(op.data)))
	if limit := r.maxSession.Load(); limit > 0 && total > limit {
		r.autoStop("sizeLimit")
	}
}

func (r *recorder) file(rel string) (*os.File, error) {
	if f, ok := r.files[rel]; ok {
		return f, nil
	}
	if len(r.files) >= recorderMaxOpenFiles {
		// Close the oldest body file; later writes reopen it in append mode.
		for len(r.order) > 0 {
			victim := r.order[0]
			r.order = r.order[1:]
			if f, ok := r.files[victim]; ok && victim != indexFileName {
				_ = f.Close()
				delete(r.files, victim)
				break
			}
		}
	}
	f, err := os.OpenFile(filepath.Join(r.dir, rel), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	r.files[rel] = f
	r.order = append(r.order, rel)
	if len(r.order) > 4*recorderMaxOpenFiles {
		live := r.order[:0]
		for _, p := range r.order {
			if _, ok := r.files[p]; ok {
				live = append(live, p)
			}
		}
		r.order = live
	}
	return f, nil
}

// autoStop ends recording but keeps the index writable for the stop event.
// Runs on the writer goroutine, so it writes the event directly.
func (r *recorder) autoStop(reason string) {
	if !r.halted.CompareAndSwap(false, true) {
		return
	}
	r.active.Store(false)
	r.stopReason.Store(reason)
	b, _ := json.Marshal(evStop{T: "stop", TS: nowMs(), Reason: reason})
	if f, err := r.file(indexFileName); err == nil {
		_, _ = f.Write(append(b, '\n'))
	}
}

// close writes a final event and flushes. kind is "stop" (session over) or
// "segmentEnd" (tunnel restarting; the next segment appends).
func (r *recorder) close(kind, reason string) {
	if r == nil {
		return
	}
	if r.active.Load() {
		r.event(evStop{T: kind, TS: nowMs(), Reason: reason})
	}
	r.active.Store(false)
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return
	}
	r.closing = true
	r.mu.Unlock()
	select {
	case r.wake <- struct{}{}:
	default:
	}
	select {
	case <-r.done:
	case <-time.After(3 * time.Second):
	}
}

func (r *recorder) stopReasonString() string {
	if v, ok := r.stopReason.Load().(string); ok {
		return v
	}
	return ""
}

// packet appends one TUN packet record.
func (r *recorder) packet(dir byte, data []byte) {
	if r == nil {
		return
	}
	rec := make([]byte, 13+len(data))
	binary.BigEndian.PutUint64(rec[0:8], uint64(time.Now().UnixNano()))
	binary.BigEndian.PutUint32(rec[8:12], uint32(len(data)))
	rec[12] = dir
	copy(rec[13:], data)
	r.appendFile(packetsFileName, rec, true)
}

// keylogWriter feeds tls.Config.KeyLogWriter.
type keylogWriter struct{ r *recorder }

func (w keylogWriter) Write(p []byte) (int, error) {
	w.r.appendFile(keylogFileName, append([]byte(nil), p...), false)
	return len(p), nil
}

// bodySink stores up to max bytes of one body and counts the rest.
type bodySink struct {
	r         *recorder
	rel       string
	max       int64
	stored    int64
	total     int64
	truncated bool
}

func (r *recorder) newBodySink(txID, ext string) *bodySink {
	if r == nil {
		return nil
	}
	return &bodySink{r: r, rel: "bodies/" + txID + "." + ext, max: r.maxBody.Load()}
}

func (s *bodySink) Write(p []byte) (int, error) {
	if s == nil {
		return len(p), nil
	}
	s.total += int64(len(p))
	room := s.max - s.stored
	if room <= 0 {
		if len(p) > 0 {
			s.truncated = true
		}
		return len(p), nil
	}
	k := int64(len(p))
	if k > room {
		k = room
		s.truncated = true
	}
	s.r.appendFile(s.rel, append([]byte(nil), p[:k]...), true)
	s.stored += k
	return len(p), nil
}

func (s *bodySink) finish() (file string, stored, total int64, truncated bool) {
	if s == nil {
		return "", 0, 0, false
	}
	if s.stored > 0 {
		s.r.closeFile(s.rel)
		file = s.rel
	}
	return file, s.stored, s.total, s.truncated
}

// Index events. Field names are mirrored by the Swift CaptureProtocol types.

type evSegment struct {
	T         string  `json:"t"`
	TS        float64 `json:"ts"`
	Seg       string  `json:"seg"`
	Session   string  `json:"session"`
	Transport string  `json:"transport"`
}

type evStop struct {
	T      string  `json:"t"`
	TS     float64 `json:"ts"`
	Reason string  `json:"reason"`
}

type evTxStart struct {
	T          string      `json:"t"`
	ID         string      `json:"id"`
	Conn       string      `json:"conn"`
	TS         float64     `json:"ts"`
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Host       string      `json:"host"`
	Scheme     string      `json:"scheme"`
	Proto      string      `json:"proto"`
	ReqHeaders [][2]string `json:"reqHeaders"`
	ReqHead    string      `json:"reqHead,omitempty"`
	Client     string      `json:"client,omitempty"`
	Server     string      `json:"server,omitempty"`
	SNI        string      `json:"sni,omitempty"`
	TLS        string      `json:"tls,omitempty"`
	ALPN       string      `json:"alpn,omitempty"`
	ConnectMs  float64     `json:"connectMs,omitempty"`
	TLSMs      float64     `json:"tlsMs,omitempty"`
	Reused     bool        `json:"reused,omitempty"`
	Rewritten  []string    `json:"rewritten,omitempty"`
}

type evTxResponse struct {
	T          string      `json:"t"`
	ID         string      `json:"id"`
	TS         float64     `json:"ts"`
	Status     int         `json:"status"`
	Reason     string      `json:"reason,omitempty"`
	Proto      string      `json:"proto"`
	ResHeaders [][2]string `json:"resHeaders"`
	ResHead    string      `json:"resHead,omitempty"`
	Rewritten  []string    `json:"rewritten,omitempty"`
}

type evTxEnd struct {
	T            string  `json:"t"`
	ID           string  `json:"id"`
	TS           float64 `json:"ts"`
	ReqBytes     int64   `json:"reqBytes"`
	ResBytes     int64   `json:"resBytes"`
	ReqBodyFile  string  `json:"reqBodyFile,omitempty"`
	ResBodyFile  string  `json:"resBodyFile,omitempty"`
	ReqTruncated bool    `json:"reqTruncated,omitempty"`
	ResTruncated bool    `json:"resTruncated,omitempty"`
	Error        string  `json:"error,omitempty"`
	WS           bool    `json:"ws,omitempty"`
	Note         string  `json:"note,omitempty"`
}

type evTunnel struct {
	T         string  `json:"t"`
	ID        string  `json:"id"`
	TS        float64 `json:"ts"`
	Start     float64 `json:"start"`
	Client    string  `json:"client,omitempty"`
	Server    string  `json:"server"`
	Host      string  `json:"host,omitempty"`
	SNI       string  `json:"sni,omitempty"`
	ALPN      string  `json:"alpn,omitempty"`
	Reason    string  `json:"reason"`
	Error     string  `json:"error,omitempty"`
	BytesUp   int64   `json:"bytesUp"`
	BytesDown int64   `json:"bytesDown"`
}

type evTLSRejected struct {
	T        string  `json:"t"`
	ID       string  `json:"id"`
	TS       float64 `json:"ts"`
	Host     string  `json:"host"`
	Server   string  `json:"server"`
	Detail   string  `json:"detail"`
	Bypassed bool    `json:"bypassed"`
}

type evFailure struct {
	T      string  `json:"t"`
	ID     string  `json:"id"`
	TS     float64 `json:"ts"`
	Host   string  `json:"host,omitempty"`
	Server string  `json:"server"`
	Stage  string  `json:"stage"`
	Error  string  `json:"error"`
}
