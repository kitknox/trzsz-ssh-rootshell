//go:build rootshell_tailscale

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

package tsengine

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"time"
	"unsafe"

	"github.com/tailscale/wireguard-go/device"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/magicsock"
)

// ErrResetStuck means a socket reset didn't finish; the engine may be wedged.
var ErrResetStuck = errors.New("tailscale socket reset is stuck")

const (
	stuckTimeout   = 10 * time.Second
	unstickEvery   = 250 * time.Millisecond
	maxStackDumpSz = 256 << 10
)

// ResetSockets replaces the UDP sockets under WireGuard and restarts its
// receive loops. iOS reclaims a suspended app's sockets; the loops exit on
// the read error and Tailscale never restarts them, leaving peers on DERP.
// Only the bind restarts: Down/Up would also stop every peer and drop its
// session, staging all traffic behind fresh handshakes.
func (e *Engine) ResetSockets() error {
	if !e.resetMu.TryLock() {
		e.logf("socket reset already running")
		return nil
	}
	defer e.resetMu.Unlock()
	if e.ctx.Err() != nil {
		return nil
	}
	dev, err := wireguardDevice(e.wg)
	if err != nil {
		return err
	}
	start := time.Now()
	// Rebind opens fresh sockets between the close and the update, which
	// starts receive loops on them (an update alone would read the old ones).
	if !e.await("bind close", true, func() {
		if err := dev.BindClose(); err != nil {
			e.logf("bind close: %v", err)
		}
	}) {
		return ErrResetStuck
	}
	e.magic.Rebind()
	var openErr error
	if !e.await("bind open", false, func() { openErr = dev.BindUpdate() }) {
		return ErrResetStuck
	}
	if openErr != nil {
		return fmt.Errorf("bind open: %w", openErr)
	}
	e.magic.ReSTUN("rootshell-foreground")
	e.logf("reset sockets in %v", time.Since(start).Round(time.Millisecond))
	return nil
}

// await runs fn and reports whether it returned in time. With unstick it
// keeps freeing WireGuard's receive loops meanwhile, since its bind close
// waits for them. A magicsock rebind racing it (link change, send error)
// hands them a live socket; packets staged for peers without a session can
// hold the whole buffer pool (64 on iOS) they need to see the close.
func (e *Engine) await(what string, unstick bool, fn func()) bool {
	var peers []device.NoisePublicKey
	if unstick {
		peers = e.peerKeys()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	tick := time.NewTicker(unstickEvery)
	defer tick.Stop()
	deadline := time.After(stuckTimeout)
	unstuck := false
	for {
		select {
		case <-done:
			return true
		case <-tick.C:
			if !unstick {
				continue
			}
			if !unstuck {
				e.logf("%s is waiting on a receive loop; closing sockets, dropping staged packets", what)
				unstuck = true
			}
			e.closeMagicSockets()
			e.flushStaged(peers)
		case <-deadline:
			e.logf("%s stuck after %v", what, stuckTimeout)
			e.dumpGoroutines()
			return false
		}
	}
}

// closeMagicSockets closes magicsock's current UDP sockets without
// replacing them, which ends any receive loop reading them.
func (e *Engine) closeMagicSockets() {
	if e.magic == nil {
		return
	}
	v := reflect.ValueOf(e.magic).Elem()
	for _, name := range []string{"pconn4", "pconn6"} {
		if c := rebindingConn(v, name); c != nil {
			c.Close()
		}
	}
}

// peerKeys lists the netmap's peers, read before a close takes the netmap away.
func (e *Engine) peerKeys() []device.NoisePublicKey {
	if e.LB == nil {
		return nil
	}
	nm := e.LB.NetMap()
	if nm == nil {
		return nil
	}
	keys := make([]device.NoisePublicKey, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		keys = append(keys, device.NoisePublicKey(p.Key().Raw32()))
	}
	return keys
}

// flushStaged drops packets waiting on a handshake, which returns their
// buffers to WireGuard's pool. Peers handshake again when traffic resumes.
func (e *Engine) flushStaged(peers []device.NoisePublicKey) {
	if len(peers) == 0 {
		return
	}
	dev, err := wireguardDevice(e.wg)
	if err != nil {
		return
	}
	for _, k := range peers {
		if p, ok := dev.LookupActivePeer(k); ok {
			p.FlushStagedPackets()
		}
	}
}

// rebindingConn reaches magicsock.Conn's unexported socket field.
// TestWireguardDevice catches a rename.
func rebindingConn(conn reflect.Value, name string) *magicsock.RebindingUDPConn {
	f := conn.FieldByName(name)
	if !f.IsValid() || f.Type() != reflect.TypeFor[magicsock.RebindingUDPConn]() {
		return nil
	}
	return (*magicsock.RebindingUDPConn)(unsafe.Pointer(f.UnsafeAddr()))
}

func (e *Engine) dumpGoroutines() {
	buf := make([]byte, maxStackDumpSz)
	n := runtime.Stack(buf, true)
	e.logf("goroutines:\n%s", buf[:n])
}

// wireguardDevice reaches wgengine's unexported device: Tailscale has no
// public way to restart the bind. TestWireguardDevice catches a rename.
func wireguardDevice(eng wgengine.Engine) (*device.Device, error) {
	v := reflect.ValueOf(eng)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		return nil, fmt.Errorf("unexpected engine type %T", eng)
	}
	f := v.Elem().FieldByName("wgdev")
	if !f.IsValid() || f.Type() != reflect.TypeFor[*device.Device]() {
		return nil, fmt.Errorf("%T has no wgdev field", eng)
	}
	dev := *(**device.Device)(unsafe.Pointer(f.UnsafeAddr()))
	if dev == nil {
		return nil, errors.New("wireguard device not created")
	}
	return dev, nil
}
