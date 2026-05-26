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

// One-shot command exec over the TSSHD UDP transport, used by the
// GPG agent forwarding path to discover the remote user's UID and
// home directory at connect time so it can substitute `{UID}` /
// `{HOME}` placeholders into the socket path. The substituted path
// must literally exist on the remote because sshd's bind(2) does no
// expansion — see openssh-portable/readconf.c parse_forward, which
// only expands `$VAR` at config-load time on the client side.
//
// This is intentionally minimal: spawn one auxiliary session,
// `Output(cmd)`, close, return. No PTY, no env vars, no stdin —
// callers should restrict themselves to short read-only probes.

import (
	"fmt"
)

// RunCommand executes `command` on the remote and returns its
// combined stdout bytes. Suitable for short probes like `id -u` /
// `printf '%s' "$HOME"` — for anything that could produce large
// output use the streaming session API instead.
//
// Errors include the command's own stderr where available, which is
// important for diagnostics when the remote shell rejects the
// command itself (e.g. restricted-shell users).
//
// IMPORTANT: parameter must NOT be named `cmd` — gomobile generates
// an ObjC method whose synthesised `_<paramname>` would collide with
// the implicit `_cmd` SEL every Objective-C method already carries,
// breaking the framework build with a "redefinition of '_cmd'" error.
func (t *Transport) RunCommand(command string) ([]byte, error) {
	if t.closed.Load() {
		return nil, fmt.Errorf("transport is closed")
	}
	session, err := t.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session for RunCommand failed: %w", err)
	}
	defer func() { _ = session.Close() }()

	out, err := session.CombinedOutput(command)
	if err != nil {
		return nil, fmt.Errorf("RunCommand[%s]: %w", command, err)
	}
	return out, nil
}
