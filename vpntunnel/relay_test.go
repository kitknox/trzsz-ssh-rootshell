package vpntunnel

import "testing"

func TestRelayCloseReleasesParents(t *testing.T) {
	first := &Relay{}
	second := &Relay{parent: first}
	tail := &Relay{parent: second}

	tail.Close()
	for i, r := range []*Relay{tail, second, first} {
		if !r.closed.Load() {
			t.Fatalf("relay %d still open after closing the tail", i)
		}
	}
}

func TestRelayCloseLeavesChildren(t *testing.T) {
	first := &Relay{}
	tail := &Relay{parent: first}

	first.Close()
	if tail.closed.Load() {
		t.Fatal("closing a parent must not close its child")
	}
	if _, err := tail.parent.connectedClient(); err == nil {
		t.Fatal("closed parent must refuse new hops")
	}
}

func TestPrepareRelayViaNeedsParent(t *testing.T) {
	if _, err := PrepareRelayVia(`{}`, nil); err == nil {
		t.Fatal("expected an error without a parent relay")
	}
}
