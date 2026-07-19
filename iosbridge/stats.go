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

// TransportStats is a gomobile-safe snapshot of live transport statistics.
// All counters are int64 (gomobile has no uint64) and durations are in
// milliseconds. Field meanings mirror tsshd.TransportStats:
//
//   - QUIC byte/packet counters are protocol-level (incl. retransmissions);
//     KCP counters are UDP wire-level from the client proxy.
//   - BytesLost/PacketsLost are QUIC-only (HasLoss) and not monotonic.
//   - RetransSegs is KCP-only and process-global across every KCP session
//     (RetransIsGlobal).
type TransportStats struct {
	Mode string // "KCP" or "QUIC"

	SrttMs      int64
	RttVarMs    int64
	MinRttMs    int64 // QUIC only (HasMinRtt)
	LatestRttMs int64 // QUIC only (HasMinRtt)
	RtoMs       int64 // KCP only (HasRto)

	BytesSent       int64
	BytesReceived   int64
	PacketsSent     int64
	PacketsReceived int64

	BytesLost   int64
	PacketsLost int64
	RetransSegs int64

	HasMinRtt       bool
	HasRto          bool
	HasLoss         bool
	RetransIsGlobal bool
}

// GetTransportStats returns a snapshot of live transport statistics, or nil
// when the transport is closed/abandoned or has no underlying client. Cheap:
// atomic reads only, safe to poll while a stats UI is visible.
func (t *Transport) GetTransportStats() *TransportStats {
	if t.closed.Load() || t.client == nil {
		return nil
	}
	s := t.client.GetTransportStats()
	if s == nil {
		return nil
	}
	return &TransportStats{
		Mode:            s.Mode,
		SrttMs:          s.SRTTMs,
		RttVarMs:        s.RTTVarMs,
		MinRttMs:        s.MinRTTMs,
		LatestRttMs:     s.LatestRTTMs,
		RtoMs:           s.RTOMs,
		BytesSent:       s.BytesSent,
		BytesReceived:   s.BytesReceived,
		PacketsSent:     s.PacketsSent,
		PacketsReceived: s.PacketsReceived,
		BytesLost:       s.BytesLost,
		PacketsLost:     s.PacketsLost,
		RetransSegs:     s.RetransSegs,
		HasMinRtt:       s.HasMinRTT,
		HasRto:          s.HasRTO,
		HasLoss:         s.HasLoss,
		RetransIsGlobal: s.RetransIsGlobal,
	}
}
