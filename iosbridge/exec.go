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

package iosbridge

// Auxiliary exec channels with piped stdio over the TSSHD UDP transport.
//
// Where probe.go's RunCommand is a one-shot CombinedOutput for short
// probes, this is the streaming equivalent for remote CLIs that read
// stdin and produce ongoing output (e.g. `herdr terminal session
// control ...`). Each OpenExec spawns its own auxiliary session via
// t.client.NewSession() — deliberately bypassing the Transport's
// single-primary-session guard, exactly like RunCommand — so exec
// channels never disturb the interactive shell session.
//
// The Swift side gets an opaque int64 reference and drives byte I/O
// through ExecRead / ExecReadStderr / ExecWrite / ExecCloseStdin /
// ExecClose, mirroring the StreamLocal* handle-table pattern. No PTY is
// requested, so stdout and stderr stay separate streams.

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/trzsz/tsshd/tsshd"
)

// execChannel is the per-invocation state for one auxiliary exec
// session: the tsshd session itself, its three stdio pipes, and the
// exit bookkeeping filled in by the wait goroutine.
type execChannel struct {
	session *tsshd.SshUdpSession
	stdin   io.WriteCloser
	stdout  io.Reader
	stderr  io.Reader

	// exitCode is written by the wait goroutine before done is closed;
	// readers must observe done closed first (channel close gives the
	// happens-before edge), then may read exitCode without locking.
	exitCode int
	done     chan struct{}
}

// OpenExec starts `command` on the remote host in a fresh auxiliary
// session with piped (non-PTY) stdio, and returns an opaque channel
// reference for the Exec* byte-transport methods. The caller owns the
// channel and must ExecClose it when done; Transport.Close also tears
// down any still-open exec channels.
//
// The parameter is named `command`, not `cmd` — see the gomobile
// `_cmd` SEL collision note on RunCommand in probe.go.
func (t *Transport) OpenExec(command string) (int64, error) {
	if t.closed.Load() {
		return 0, fmt.Errorf("transport is closed")
	}
	if command == "" {
		return 0, fmt.Errorf("command is empty")
	}

	session, err := t.client.NewSession()
	if err != nil {
		return 0, fmt.Errorf("new session for OpenExec failed: %w", err)
	}

	// All three pipes must be requested before Start — tsshd's
	// startSession only wires up forwarding for pipes that already
	// exist when the start message is sent (same ordering
	// CombinedOutput uses).
	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return 0, fmt.Errorf("stdin pipe for OpenExec failed: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		return 0, fmt.Errorf("stdout pipe for OpenExec failed: %w", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		_ = session.Close()
		return 0, fmt.Errorf("stderr pipe for OpenExec failed: %w", err)
	}

	if err := session.Start(command); err != nil {
		_ = session.Close()
		return 0, fmt.Errorf("start command [%s] failed: %w", command, err)
	}

	ec := &execChannel{
		session: session,
		stdin:   stdin,
		stdout:  stdout,
		stderr:  stderr,
		done:    make(chan struct{}),
	}

	// Capture the exit code as soon as the remote process finishes.
	// tsshd's Wait always returns nil; the code arrives via the bus
	// "exit" message and is read back with GetExitCode.
	go func() {
		_ = session.Wait()
		ec.exitCode = session.GetExitCode()
		close(ec.done)
	}()

	ref := atomic.AddInt64(&t.nextExecRef, 1)
	t.mu.Lock()
	if t.execChannels == nil {
		t.execChannels = make(map[int64]*execChannel)
	}
	t.execChannels[ref] = ec
	t.mu.Unlock()

	// Close raced with the start: closeAllExec may have already drained
	// the handle table before we registered, which would leak the
	// session. ExecClose is idempotent, so unwind here.
	if t.closed.Load() {
		_ = t.ExecClose(ref)
		return 0, fmt.Errorf("transport is closed")
	}

	if dl := getDebugLogger(); dl != nil {
		dl.OnDebug(fmt.Sprintf("[exec] started [%s], channel %d", command, ref))
	}
	return ref, nil
}

// lookupExecChannel returns the execChannel for a ref, or nil if it's
// been closed / never existed. Held under the transport's mutex briefly
// so concurrent Close calls don't race.
func (t *Transport) lookupExecChannel(ref int64) *execChannel {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.execChannels == nil {
		return nil
	}
	return t.execChannels[ref]
}

// ExecRead reads up to maxBytes from the command's stdout, blocking
// until data is available. Returns nil data with nil error on clean
// EOF — Swift callers should treat that as "stream ended, stop
// reading" (same convention as StreamLocalRead).
func (t *Transport) ExecRead(ref int64, maxBytes int) ([]byte, error) {
	ec := t.lookupExecChannel(ref)
	if ec == nil {
		return nil, fmt.Errorf("unknown exec channel %d", ref)
	}
	return readExecStream(ec.stdout, maxBytes)
}

// ExecReadStderr reads up to maxBytes from the command's stderr,
// blocking until data is available. EOF convention matches ExecRead.
func (t *Transport) ExecReadStderr(ref int64, maxBytes int) ([]byte, error) {
	ec := t.lookupExecChannel(ref)
	if ec == nil {
		return nil, fmt.Errorf("unknown exec channel %d", ref)
	}
	return readExecStream(ec.stderr, maxBytes)
}

func readExecStream(r io.Reader, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, nil
	}
	buf := make([]byte, maxBytes)
	n, err := r.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	if err == io.EOF {
		// Signal clean close via nil data + nil error so the Swift
		// AsyncBytePipe adapter can return nil from its read() to mark
		// end-of-stream without throwing.
		return nil, nil
	}
	return nil, err
}

// ExecWrite writes data to the command's stdin. Returns the number of
// bytes written (all of them unless the pipe has been closed).
func (t *Transport) ExecWrite(ref int64, data []byte) (int32, error) {
	ec := t.lookupExecChannel(ref)
	if ec == nil {
		return 0, fmt.Errorf("unknown exec channel %d", ref)
	}
	n, err := ec.stdin.Write(data)
	return int32(n), err
}

// ExecCloseStdin closes only the command's stdin, delivering EOF to the
// remote process while stdout/stderr stay readable. Safe to call more
// than once.
func (t *Transport) ExecCloseStdin(ref int64) error {
	ec := t.lookupExecChannel(ref)
	if ec == nil {
		return fmt.Errorf("unknown exec channel %d", ref)
	}
	return ec.stdin.Close()
}

// ExecExitCode returns the command's exit code if the remote process
// has finished, or -1 if it is still running. Call this after ExecRead
// hits EOF and BEFORE ExecClose — ExecClose removes the channel from
// the handle table, after which this returns -1 for the unknown ref.
func (t *Transport) ExecExitCode(ref int64) int {
	ec := t.lookupExecChannel(ref)
	if ec == nil {
		return -1
	}
	select {
	case <-ec.done:
		return ec.exitCode
	default:
		return -1
	}
}

// ExecClose tears down the exec channel: closes stdin, closes the
// session (which asks the server to end the process), waits briefly for
// the exit notification, and removes the channel from the handle table.
// Idempotent — calling for an unknown ref is silent success.
func (t *Transport) ExecClose(ref int64) error {
	t.mu.Lock()
	ec, ok := t.execChannels[ref]
	if ok {
		delete(t.execChannels, ref)
	}
	t.mu.Unlock()
	if !ok {
		return nil
	}
	return ec.close()
}

// close shuts down one exec channel. Session.Close is internally
// bounded by tsshd (doWithTimeout, ~500ms) and requests an "exit" on
// the bus, so the follow-up wait on ec.done is best-effort: it lets a
// promptly-exiting process land its real exit code, but never hangs on
// one that ignores the request.
func (ec *execChannel) close() error {
	_ = ec.stdin.Close()
	err := ec.session.Close()
	select {
	case <-ec.done:
	case <-time.After(2 * time.Second):
	}
	return err
}

// closeAllExec is called from Transport.Close to tear down every active
// exec channel. Mirrors closeAllStreamLocal: snapshot under the lock,
// close outside it, since session teardown can block briefly on the
// network.
func (t *Transport) closeAllExec() {
	t.mu.Lock()
	channels := make([]*execChannel, 0, len(t.execChannels))
	for _, ec := range t.execChannels {
		channels = append(channels, ec)
	}
	t.execChannels = nil
	t.mu.Unlock()

	for _, ec := range channels {
		_ = ec.close()
	}
}
