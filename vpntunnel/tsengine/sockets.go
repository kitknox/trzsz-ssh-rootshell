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
	"unsafe"

	"github.com/tailscale/wireguard-go/device"
	"tailscale.com/wgengine"
)

// ResetSockets replaces the UDP sockets under WireGuard and restarts its
// receive loops. iOS reclaims a suspended app's sockets; the loops exit on
// the read error and Tailscale never restarts them, leaving peers on DERP.
// Netstack connections survive; peers just handshake again.
func (e *Engine) ResetSockets() error {
	if e.ctx.Err() != nil {
		return nil
	}
	dev, err := wireguardDevice(e.wg)
	if err != nil {
		return err
	}
	// Down closes the bind; Rebind opens fresh sockets before Up starts
	// receive loops on them (Up alone would read the closed ones).
	if err := dev.Down(); err != nil {
		e.logf("wireguard down: %v", err)
	}
	e.magic.Rebind()
	if err := dev.Up(); err != nil {
		return fmt.Errorf("wireguard up: %w", err)
	}
	e.magic.ReSTUN("rootshell-foreground")
	e.logf("reset sockets after returning to the foreground")
	return nil
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
