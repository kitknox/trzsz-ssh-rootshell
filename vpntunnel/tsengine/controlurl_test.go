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
	"bytes"
	"encoding/json"
	"sync"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/persist"
)

func TestSameControlServer(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"", ipn.DefaultControlURL, true},
		{"", "https://login.tailscale.com", true},
		{"https://headscale.example.com/", "https://headscale.example.com", true},
		{"", "https://headscale.example.com", false},
		{"https://a.example.com", "https://b.example.com", false},
	} {
		if got := sameControlServer(tc.a, tc.b); got != tc.same {
			t.Errorf("sameControlServer(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
}

type memStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *memStore) ReadState(k string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[k], nil
}

func (s *memStore) WriteState(k string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = bytes.Clone(v)
	return nil
}

const seededProfile = ipn.ProfileID("a1b2")

// seededStore holds a signed-in profile on controlURL.
func seededStore(t *testing.T, controlURL string) *memStore {
	stateKey := ipn.StateKey("profile-a1b2")
	user := tailcfg.UserProfile{ID: 1, LoginName: "user@example.com", DisplayName: "User"}
	profiles, err := json.Marshal(map[ipn.ProfileID]*ipn.LoginProfile{seededProfile: {
		ID: seededProfile, Key: stateKey, Name: user.LoginName, ControlURL: controlURL, NodeID: "n1", UserProfile: user,
	}})
	if err != nil {
		t.Fatal(err)
	}
	prefs := ipn.NewPrefs()
	prefs.ControlURL = controlURL
	prefs.WantRunning = true
	prefs.Persist = &persist.Persist{NodeID: "n1", UserProfile: user, PrivateNodeKey: key.NewNode()}
	return &memStore{m: map[string][]byte{
		string(ipn.KnownProfilesStateKey):  profiles,
		string(ipn.CurrentProfileStateKey): []byte(stateKey),
		string(stateKey):                   prefs.ToBytes(),
	}}
}

// A different coordination server starts a fresh node; the same one keeps
// the login. Both servers refuse connections, so nothing leaves the host.
func TestStartDropsLoginFromAnotherServer(t *testing.T) {
	const saved = "http://127.0.0.1:9"
	for _, tc := range []struct {
		name, controlURL string
		keep             bool
	}{
		{"same server", saved + "/", true},
		{"other server", "http://localhost:9", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := seededStore(t, saved)
			e, err := Start(Config{Logf: func(string, ...any) {}, ControlURL: tc.controlURL, StateDir: t.TempDir(), Store: store})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if kept := e.LB.CurrentProfile().ID() == seededProfile; kept != tc.keep {
				t.Fatalf("profile kept = %v, want %v", kept, tc.keep)
			}
			if got := e.LB.Prefs().ControlURL(); got != tc.controlURL {
				t.Fatalf("ControlURL = %q, want %q", got, tc.controlURL)
			}
			profiles, _ := store.ReadState(string(ipn.KnownProfilesStateKey))
			if stored := bytes.Contains(profiles, []byte(seededProfile)); stored != tc.keep {
				t.Fatalf("profile stored = %v, want %v", stored, tc.keep)
			}
		})
	}
}
