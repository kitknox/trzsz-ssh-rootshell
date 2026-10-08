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

package vpntunnel

import (
	"os"
	"sync"
	"sync/atomic"

	"github.com/tailscale/wireguard-go/tun"
)

const chanTUNQueue = 256

// chanTUN is the tun.Device WireGuard reads from and writes to. Packets from
// the provider arrive through deliver; packets from the tailnet leave through
// the shared tailnetPath queue.
type chanTUN struct {
	in        chan []byte
	path      *tailnetPath
	events    chan tun.Event
	closed    chan struct{}
	closeOnce sync.Once
	drops     atomic.Int64
}

func newChanTUN(path *tailnetPath) *chanTUN {
	t := &chanTUN{
		in:     make(chan []byte, chanTUNQueue),
		path:   path,
		events: make(chan tun.Event, 1),
		closed: make(chan struct{}),
	}
	t.events <- tun.EventUp
	return t
}

// deliver never blocks the provider's read loop; a full queue drops, which
// TCP treats as loss.
func (t *chanTUN) deliver(pkt []byte) {
	select {
	case t.in <- pkt:
	case <-t.closed:
	default:
		t.drops.Add(1)
	}
}

func (t *chanTUN) File() *os.File { return nil }

func (t *chanTUN) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	select {
	case pkt := <-t.in:
		packets[0].Offset = tun.ReadPacketSpacing
		packets[0].Size = copy(slab[tun.ReadPacketSpacing:len(slab)-tun.ReadPacketSpacing], pkt)
		return 1, nil
	case <-t.closed:
		return 0, os.ErrClosed
	}
}

func (t *chanTUN) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	default:
	}
	for _, b := range bufs {
		if len(b) > offset {
			t.path.emit(append([]byte(nil), b[offset:]...))
		}
	}
	return len(bufs), nil
}

func (t *chanTUN) MTU() (int, error)        { return tailnetMTU, nil }
func (t *chanTUN) Name() (string, error)    { return "rootshell-tailnet", nil }
func (t *chanTUN) Events() <-chan tun.Event { return t.events }
func (t *chanTUN) BatchSize() int           { return 1 }

func (t *chanTUN) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}
