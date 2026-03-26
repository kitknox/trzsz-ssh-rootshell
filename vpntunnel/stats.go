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
	"runtime"
	"sync/atomic"
)

// tunnelStats tracks byte counters and active connections.
type tunnelStats struct {
	bytesIn          atomic.Int64
	bytesOut         atomic.Int64
	activeConns      atomic.Int32
	totalConns       atomic.Int64
	activeTCPConns   atomic.Int32
	activeUDPConns   atomic.Int32
	tcpCapacityDrops atomic.Int64
	udpCapacityDrops atomic.Int64
}

// TunnelStatus is the JSON-serializable status returned by GetStatus.
type TunnelStatus struct {
	Connected         bool   `json:"connected"`
	BytesIn           int64  `json:"bytesIn"`
	BytesOut          int64  `json:"bytesOut"`
	ActiveConns       int    `json:"activeConns"`
	ActiveTCPConns    int    `json:"activeTCPConns"`
	ActiveUDPConns    int    `json:"activeUDPConns"`
	TotalConns        int64  `json:"totalConns"`
	TCPCapacityDrops  int64  `json:"tcpCapacityDrops"`
	UDPCapacityDrops  int64  `json:"udpCapacityDrops"`
	TransportType     string `json:"transportType"`
	GoHeapAllocBytes  int64  `json:"goHeapAllocBytes"`
	GoHeapInuseBytes  int64  `json:"goHeapInuseBytes"`
	GoStackInuseBytes int64  `json:"goStackInuseBytes"`
	GoSysBytes        int64  `json:"goSysBytes"`
	GoNumGC           uint32 `json:"goNumGC"`
	GoGoroutines      int    `json:"goGoroutines"`
	GoLiveObjects     int64  `json:"goLiveObjects"`
}

func (s *tunnelStats) addBytesIn(n int) {
	s.bytesIn.Add(int64(n))
}

func (s *tunnelStats) addBytesOut(n int) {
	s.bytesOut.Add(int64(n))
}

func (s *tunnelStats) connOpenedTCP() {
	s.activeConns.Add(1)
	s.activeTCPConns.Add(1)
	s.totalConns.Add(1)
}

func (s *tunnelStats) connClosedTCP() {
	s.activeConns.Add(-1)
	s.activeTCPConns.Add(-1)
}

func (s *tunnelStats) connOpenedUDP() {
	s.activeConns.Add(1)
	s.activeUDPConns.Add(1)
	s.totalConns.Add(1)
}

func (s *tunnelStats) connClosedUDP() {
	s.activeConns.Add(-1)
	s.activeUDPConns.Add(-1)
}

func (s *tunnelStats) tcpCapacityDrop() {
	s.tcpCapacityDrops.Add(1)
}

func (s *tunnelStats) udpCapacityDrop() {
	s.udpCapacityDrops.Add(1)
}

func (s *tunnelStats) toStatus(connected bool, transportType string) string {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	liveObjects := int64(0)
	if mem.Mallocs >= mem.Frees {
		liveObjects = int64(mem.Mallocs - mem.Frees)
	}

	status := TunnelStatus{
		Connected:         connected,
		BytesIn:           s.bytesIn.Load(),
		BytesOut:          s.bytesOut.Load(),
		ActiveConns:       int(s.activeConns.Load()),
		ActiveTCPConns:    int(s.activeTCPConns.Load()),
		ActiveUDPConns:    int(s.activeUDPConns.Load()),
		TotalConns:        s.totalConns.Load(),
		TCPCapacityDrops:  s.tcpCapacityDrops.Load(),
		UDPCapacityDrops:  s.udpCapacityDrops.Load(),
		TransportType:     transportType,
		GoHeapAllocBytes:  int64(mem.HeapAlloc),
		GoHeapInuseBytes:  int64(mem.HeapInuse),
		GoStackInuseBytes: int64(mem.StackInuse),
		GoSysBytes:        int64(mem.Sys),
		GoNumGC:           mem.NumGC,
		GoGoroutines:      runtime.NumGoroutine(),
		GoLiveObjects:     liveObjects,
	}
	b, _ := json.Marshal(status)
	return string(b)
}
