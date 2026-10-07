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
	"testing"

	"tailscale.com/tsd"
	"tailscale.com/wgengine"
)

// Fails when a Tailscale bump renames or retypes userspaceEngine.wgdev.
func TestWireguardDevice(t *testing.T) {
	sys := tsd.NewSystem()
	eng, err := wgengine.NewFakeUserspaceEngine(t.Logf, 0, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get(), sys.Set)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	e := &Engine{ctx: context.Background(), logf: t.Logf, wg: eng, magic: sys.MagicSock.Get()}
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
