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

// ECHOCTL expansion tests: PTY echoes control chars as 2-byte ^X sequences
func TestDiscardMarkerFilter_ECHOCTLExpanded(t *testing.T) {
	f := &discardMarkerFilter{}
	// Marker index bytes 0x00,0x00,0x00,0x0C echoed as ^@^@^@^L
	// Magic prefix: FF C0 C1 FF (echoed as-is, bytes >= 0x80)
	// Index echo: 5E 40, 5E 40, 5E 40, 5E 4C (ECHOCTL expansion)
	input := []byte("before")
	input = append(input, 0xFF, 0xC0, 0xC1, 0xFF) // magic
	input = append(input, 0x5E, 0x40)               // ^@ (ECHOCTL of 0x00)
	input = append(input, 0x5E, 0x40)               // ^@ (ECHOCTL of 0x00)
	input = append(input, 0x5E, 0x40)               // ^@ (ECHOCTL of 0x00)
	input = append(input, 0x5E, 0x4C)               // ^L (ECHOCTL of 0x0C)
	input = append(input, []byte("after")...)
	result := f.filter(input)
	expected := []byte("beforeafter")
	if !bytes.Equal(result, expected) {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestDiscardMarkerFilter_MixedECHOCTL(t *testing.T) {
	f := &discardMarkerFilter{}
	// Index bytes: 0x00 (ECHOCTL), 0x00 (ECHOCTL), 0x00 (ECHOCTL), 0x42 (raw 'B')
	// Magic: FF C0 C1 FF
	// Index echo: 5E 40, 5E 40, 5E 40, 42
	input := []byte{0xFF, 0xC0, 0xC1, 0xFF}
	input = append(input, 0x5E, 0x40) // ^@
	input = append(input, 0x5E, 0x40) // ^@
	input = append(input, 0x5E, 0x40) // ^@
	input = append(input, 0x42)        // raw 'B'
	input = append(input, []byte("tail")...)
	result := f.filter(input)
	if !bytes.Equal(result, []byte("tail")) {
		t.Errorf("expected %q, got %q", "tail", result)
	}
}

func TestDiscardMarkerFilter_NonControlIndex(t *testing.T) {
	f := &discardMarkerFilter{}
	// New-style marker with all index bytes >= 0x20 (no ECHOCTL expansion)
	// Index: 0x20 0x20 0x20 0x20
	input := []byte{0xFF, 0xC0, 0xC1, 0xFF, 0x20, 0x20, 0x20, 0x20}
	input = append(input, []byte("data")...)
	result := f.filter(input)
	if !bytes.Equal(result, []byte("data")) {
		t.Errorf("expected %q, got %q", "data", result)
	}
}

func TestDiscardMarkerFilter_HighByteIndex(t *testing.T) {
	f := &discardMarkerFilter{}
	// Index bytes >= 0x80 (echoed as-is, 1 byte each)
	input := []byte{0xFF, 0xC0, 0xC1, 0xFF, 0x80, 0x90, 0xA0, 0xB0}
	result := f.filter(input)
	if len(result) != 0 {
		t.Errorf("expected empty, got %X", result)
	}
}

func TestDiscardMarkerFilter_ECHOCTLSplitAcrossReads(t *testing.T) {
	f := &discardMarkerFilter{}

	// First read: magic prefix + partial ECHOCTL index
	part1 := []byte{0xFF, 0xC0, 0xC1, 0xFF, 0x5E, 0x40, 0x5E}
	result1 := f.filter(part1)
	if len(result1) != 0 {
		t.Errorf("part1: expected empty, got %X", result1)
	}

	// Second read: rest of ECHOCTL index + text
	part2 := []byte{0x40, 0x5E, 0x40, 0x5E, 0x4C}
	part2 = append(part2, []byte("hello")...)
	result2 := f.filter(part2)
	if !bytes.Equal(result2, []byte("hello")) {
		t.Errorf("part2: expected %q, got %q", "hello", result2)
	}
}

func TestDiscardMarkerFilter_DELEchoctl(t *testing.T) {
	f := &discardMarkerFilter{}
	// DEL (0x7F) is echoed as ^? (0x5E 0x3F)
	// Index: 0x7F, 0x00, 0x00, 0x00
	// Echo: 5E 3F, 5E 40, 5E 40, 5E 40
	input := []byte{0xFF, 0xC0, 0xC1, 0xFF}
	input = append(input, 0x5E, 0x3F) // ^?
	input = append(input, 0x5E, 0x40) // ^@
	input = append(input, 0x5E, 0x40) // ^@
	input = append(input, 0x5E, 0x40) // ^@
	input = append(input, []byte("ok")...)
	result := f.filter(input)
	if !bytes.Equal(result, []byte("ok")) {
		t.Errorf("expected %q, got %q", "ok", result)
	}
}

func TestConsumeMarkerIndex_RawBytes(t *testing.T) {
	// 4 raw bytes >= 0x20
	data := []byte{0x20, 0x30, 0x40, 0x50, 0x60}
	n := consumeMarkerIndex(data, 0)
	if n != 4 {
		t.Errorf("expected 4, got %d", n)
	}
}

func TestConsumeMarkerIndex_AllECHOCTL(t *testing.T) {
	// 4 ECHOCTL pairs
	data := []byte{0x5E, 0x40, 0x5E, 0x41, 0x5E, 0x42, 0x5E, 0x43}
	n := consumeMarkerIndex(data, 0)
	if n != 8 {
		t.Errorf("expected 8, got %d", n)
	}
}

func TestConsumeMarkerIndex_NotEnoughData(t *testing.T) {
	// Only 2 bytes, need 4 logical
	data := []byte{0x20, 0x30}
	n := consumeMarkerIndex(data, 0)
	if n != -1 {
		t.Errorf("expected -1, got %d", n)
	}
}
