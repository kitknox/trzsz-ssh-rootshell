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
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// startControl runs a test coordination server on loopback.
func startControl(t *testing.T, authKey string) *testcontrol.Server {
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })
	control := &testcontrol.Server{
		DERPMap:        &tailcfg.DERPMap{}, // none: nothing leaves loopback
		MagicDNSDomain: "tail-scale.ts.net",
		RequireAuthKey: authKey,
		Logf:           logger.Discard,
	}
	control.HTTPTestServer = httptest.NewServer(control)
	t.Cleanup(control.HTTPTestServer.Close)
	return control
}

func startEngine(t *testing.T, controlURL, authKey string, store *memStore) *Engine {
	e, err := Start(Config{Logf: logger.Discard, ControlURL: controlURL, AuthKey: authKey, StateDir: t.TempDir(), Store: store})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func waitStatus(t *testing.T, e *Engine, what string, ok func(Status) bool) Status {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		st := e.Status()
		if ok(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s; last status %+v", what, st)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestAuthKeyRegistersNewNode(t *testing.T) {
	control := startControl(t, "tskey-good")
	store := &memStore{m: map[string][]byte{}}
	e := startEngine(t, control.HTTPTestServer.URL, "tskey-good", store)
	// Without DERP it never reaches Running, but it is registered.
	st := waitStatus(t, e, "registration", func(s Status) bool { return s.Registered })
	registered := e.Registered()
	e.Close()
	if st.State == ipn.Running.String() || st.AuthURL != "" || st.Error != "" || !registered {
		t.Fatalf("status %+v, Registered() = %v", st, registered)
	}

	// testcontrol checks the key on every register, so a signed-in node that
	// leaves the key out is refused.
	control.RequireAuthKey = "tskey-next"
	e = startEngine(t, control.HTTPTestServer.URL, "tskey-next", store)
	defer e.Close()
	waitStatus(t, e, "the key left out", func(s Status) bool { return strings.Contains(s.Error, "invalid authkey") })
}

func TestAuthKeyRefused(t *testing.T) {
	control := startControl(t, "tskey-good")
	e := startEngine(t, control.HTTPTestServer.URL, "tskey-bad", &memStore{m: map[string][]byte{}})
	defer e.Close()
	st := waitStatus(t, e, "the refusal", func(s Status) bool { return s.Error != "" })
	if !strings.Contains(st.Error, "invalid authkey") || st.Registered || st.State == ipn.Running.String() {
		t.Fatalf("status %+v", st)
	}
}

// Tailscale doesn't notify transport errors; they come from health.
func TestLoginErrorFromUnreachableServer(t *testing.T) {
	e := startEngine(t, "http://127.0.0.1:9", "", &memStore{m: map[string][]byte{}})
	defer e.Close()
	st := waitStatus(t, e, "a login error", func(s Status) bool { return s.Error != "" })
	if !strings.Contains(st.Error, "127.0.0.1:9") {
		t.Fatalf("error %q", st.Error)
	}
}
