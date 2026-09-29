package iosbridge

import "testing"

// The guards must answer before the nil tsshd session is touched.

func TestRedrawScreen_ClosedSession(t *testing.T) {
	s := &TransportSession{}
	s.started.Store(true)
	s.closed.Store(true)
	if err := s.RedrawScreen(true); err == nil {
		t.Fatal("expected an error for a closed session")
	}
}

func TestRedrawScreen_SessionNotStarted(t *testing.T) {
	s := &TransportSession{}
	if err := s.RedrawScreen(true); err == nil {
		t.Fatal("expected an error for a session that was not started")
	}
}
