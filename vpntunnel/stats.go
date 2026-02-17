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

package vpntunnel

import (
	"encoding/json"
	"sync/atomic"
)

// tunnelStats tracks byte counters and active connections.
type tunnelStats struct {
	bytesIn    atomic.Int64
	bytesOut   atomic.Int64
	activeConns atomic.Int32
	totalConns  atomic.Int64
}

// TunnelStatus is the JSON-serializable status returned by GetStatus.
type TunnelStatus struct {
	Connected       bool   `json:"connected"`
	BytesIn         int64  `json:"bytesIn"`
	BytesOut        int64  `json:"bytesOut"`
	ActiveConns     int    `json:"activeConns"`
	TotalConns      int64  `json:"totalConns"`
	TransportType   string `json:"transportType"`
}

func (s *tunnelStats) addBytesIn(n int) {
	s.bytesIn.Add(int64(n))
}

func (s *tunnelStats) addBytesOut(n int) {
	s.bytesOut.Add(int64(n))
}

func (s *tunnelStats) connOpened() {
	s.activeConns.Add(1)
	s.totalConns.Add(1)
}

func (s *tunnelStats) connClosed() {
	s.activeConns.Add(-1)
}

func (s *tunnelStats) toStatus(connected bool, transportType string) string {
	status := TunnelStatus{
		Connected:     connected,
		BytesIn:       s.bytesIn.Load(),
		BytesOut:      s.bytesOut.Load(),
		ActiveConns:   int(s.activeConns.Load()),
		TotalConns:    s.totalConns.Load(),
		TransportType: transportType,
	}
	b, _ := json.Marshal(status)
	return string(b)
}
