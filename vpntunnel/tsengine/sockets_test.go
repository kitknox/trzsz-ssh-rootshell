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
	"context"
	"reflect"
	"testing"
	"time"

	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine"
)

func newFakeEngine(t *testing.T, logf logger.Logf) (*Engine, wgengine.Engine) {
	sys := tsd.NewSystem()
	eng, err := wgengine.NewFakeUserspaceEngine(logf, 0, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get(), sys.Set)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)
	return &Engine{ctx: context.Background(), logf: logf, wg: eng, magic: sys.MagicSock.Get()}, eng
}

// Fails when a Tailscale bump renames or retypes userspaceEngine.wgdev or
// magicsock.Conn's sockets.
func TestWireguardDevice(t *testing.T) {
	e, eng := newFakeEngine(t, t.Logf)
	v := reflect.ValueOf(e.magic).Elem()
	for _, name := range []string{"pconn4", "pconn6"} {
		if rebindingConn(v, name) == nil {
			t.Fatalf("magicsock.Conn has no %s socket", name)
		}
	}
	for range 2 {
		if err := e.ResetSockets(); err != nil {
			t.Fatal(err)
		}
	}
	dev, err := wireguardDevice(eng)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Bind() == nil {
		t.Fatal("device has no bind after reset")
	}
}

// A magicsock rebind racing the reset used to leave WireGuard's Down waiting
// on a receive loop forever.
func TestResetSocketsConcurrentRebind(t *testing.T) {
	e, _ := newFakeEngine(t, func(string, ...any) {})
	for i := range 60 {
		done := make(chan error, 1)
		go func() { done <- e.ResetSockets() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("reset %d: %v", i, err)
			}
		case <-time.After(2 * stuckTimeout):
			t.Fatalf("reset %d never returned", i)
		}
		if i%3 == 0 {
			go e.magic.Rebind()
		}
	}
}

func TestResetSocketsAfterClose(t *testing.T) {
	e, _ := newFakeEngine(t, t.Logf)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.ctx = ctx
	if err := e.ResetSockets(); err != nil {
		t.Fatal(err)
	}
}
