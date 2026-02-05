package iosbridge

import (
	"bytes"
	"testing"
)

func TestDiscardMarkerFilter_NoMarker(t *testing.T) {
	f := &discardMarkerFilter{}
	input := []byte("hello world")
	result := f.filter(input)
	if !bytes.Equal(result, input) {
		t.Errorf("expected %q, got %q", input, result)
	}
}

func TestDiscardMarkerFilter_FullMarker(t *testing.T) {
	f := &discardMarkerFilter{}
	marker := []byte{0xFF, 0xC0, 0xC1, 0xFF, 0x00, 0x00, 0x00, 0x01}
	input := append([]byte("before"), marker...)
	input = append(input, []byte("after")...)
	result := f.filter(input)
	expected := []byte("beforeafter")
	if !bytes.Equal(result, expected) {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestDiscardMarkerFilter_MultipleMarkers(t *testing.T) {
	f := &discardMarkerFilter{}
	marker1 := []byte{0xFF, 0xC0, 0xC1, 0xFF, 0x00, 0x00, 0x00, 0x01}
	marker2 := []byte{0xFF, 0xC0, 0xC1, 0xFF, 0x00, 0x00, 0x00, 0x02}
	input := append([]byte("a"), marker1...)
	input = append(input, []byte("b")...)
	input = append(input, marker2...)
	input = append(input, []byte("c")...)
	result := f.filter(input)
	expected := []byte("abc")
	if !bytes.Equal(result, expected) {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestDiscardMarkerFilter_SplitAcrossReads(t *testing.T) {
	f := &discardMarkerFilter{}

	// First read: text + partial marker (magic prefix only)
	part1 := append([]byte("hello"), 0xFF, 0xC0, 0xC1, 0xFF)
	result1 := f.filter(part1)
	if !bytes.Equal(result1, []byte("hello")) {
		t.Errorf("part1: expected %q, got %q", "hello", result1)
	}

	// Second read: rest of marker + more text
	part2 := append([]byte{0x00, 0x00, 0x00, 0x05}, []byte("world")...)
	result2 := f.filter(part2)
	if !bytes.Equal(result2, []byte("world")) {
		t.Errorf("part2: expected %q, got %q", "world", result2)
	}
}

func TestDiscardMarkerFilter_SplitMidMagic(t *testing.T) {
	f := &discardMarkerFilter{}

	// First read: text + first 2 bytes of magic
	part1 := append([]byte("data"), 0xFF, 0xC0)
	result1 := f.filter(part1)
	if !bytes.Equal(result1, []byte("data")) {
		t.Errorf("part1: expected %q, got %q", "data", result1)
	}

	// Second read: rest of marker
	part2 := []byte{0xC1, 0xFF, 0x00, 0x00, 0x00, 0x03}
	result2 := f.filter(part2)
	if len(result2) != 0 {
		t.Errorf("part2: expected empty, got %q", result2)
	}
}

func TestDiscardMarkerFilter_FalsePositiveFF(t *testing.T) {
	f := &discardMarkerFilter{}
	// 0xFF followed by non-magic bytes should pass through
	input := []byte{0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	result := f.filter(input)
	if !bytes.Equal(result, input) {
		t.Errorf("expected %X, got %X", input, result)
	}
}

func TestDiscardMarkerFilter_MarkerOnly(t *testing.T) {
	f := &discardMarkerFilter{}
	marker := []byte{0xFF, 0xC0, 0xC1, 0xFF, 0x00, 0x00, 0x00, 0x01}
	result := f.filter(marker)
	if len(result) != 0 {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestDiscardMarkerFilter_EmptyInput(t *testing.T) {
	f := &discardMarkerFilter{}
	result := f.filter(nil)
	if len(result) != 0 {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestDiscardMarkerFilter_PartialThenNoMarker(t *testing.T) {
	f := &discardMarkerFilter{}

	// First read ends with single 0xFF
	part1 := append([]byte("test"), 0xFF)
	result1 := f.filter(part1)
	if !bytes.Equal(result1, []byte("test")) {
		t.Errorf("part1: expected %q, got %q", "test", result1)
	}

	// Second read doesn't continue the magic - held byte should flush
	part2 := []byte("next")
	result2 := f.filter(part2)
	expected2 := append([]byte{0xFF}, []byte("next")...)
	if !bytes.Equal(result2, expected2) {
		t.Errorf("part2: expected %X, got %X", expected2, result2)
	}
}

func TestDiscardMarkerFilter_BackToBackMarkers(t *testing.T) {
	f := &discardMarkerFilter{}
	marker1 := []byte{0xFF, 0xC0, 0xC1, 0xFF, 0x00, 0x00, 0x00, 0x01}
	marker2 := []byte{0xFF, 0xC0, 0xC1, 0xFF, 0x00, 0x00, 0x00, 0x02}
	input := append(marker1, marker2...)
	result := f.filter(input)
	if len(result) != 0 {
		t.Errorf("expected empty, got %X", result)
	}
}
