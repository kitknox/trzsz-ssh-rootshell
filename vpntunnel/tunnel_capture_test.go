package vpntunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// lanIPv4 returns a non-loopback address the Direct dialer can reach.
func lanIPv4(t *testing.T) net.IP {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLinkLocalUnicast() {
				return ipn.IP.To4()
			}
		}
	}
	t.Skip("no LAN IPv4 address")
	return nil
}

// appStack is a second gVisor stack playing the device's apps, wired to the
// tunnel through InjectPacket / ReadPacket like the Swift packet loops.
type appStack struct {
	s      *stack.Stack
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newAppStack(t *testing.T) *appStack {
	t.Helper()
	ep := channel.New(1024, 1500, "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 0, 0, 2}).WithPrefix(),
	}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	ctx, cancel := context.WithCancel(context.Background())
	a := &appStack{s: s, cancel: cancel}
	a.wg.Add(2)
	go func() { // apps → tunnel
		defer a.wg.Done()
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			data := append([]byte(nil), pkt.ToView().AsSlice()...)
			pkt.DecRef()
			InjectPacket(data, 2)
		}
	}()
	go func() { // tunnel → apps
		defer a.wg.Done()
		for {
			p := ReadPacket()
			if p == nil {
				return
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p.Data)})
			ep.InjectInbound(ipv4.ProtocolNumber, pkt)
			pkt.DecRef()
		}
	}()
	return a
}

func (a *appStack) close() {
	a.cancel()
	a.s.Close()
}

func (a *appStack) httpsGet(t *testing.T, ip net.IP, port int, pool *x509.CertPool, path string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, a.s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ip), Port: uint16(port)}, ipv4.ProtocolNumber)
	if err != nil {
		return "", err
	}
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c := tls.Client(conn, &tls.Config{ServerName: "api.example.com", RootCAs: pool, NextProtos: []string{"h2", "http/1.1"}})
			return c, c.HandshakeContext(ctx)
		},
		ForceAttemptHTTP2: true,
	}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get("https://api.example.com" + path)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// within fails the test if f doesn't return in d (a hung extension).
func within(t *testing.T, name string, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v", name, d)
	}
}

func TestDirectTunnelCaptureLifecycle(t *testing.T) {
	ip := lanIPv4(t)
	certPEM, keyPEM, pool := newTestCA(t)
	ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Skip("cannot listen on LAN address:", err)
	}
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello " + r.URL.Path))
	}))
	up.Listener = ln
	up.EnableHTTP2 = true
	up.StartTLS()
	defer up.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	spool := t.TempDir()
	capture := func(session string) captureConfig {
		return captureConfig{
			Enabled: session != "", SessionID: session, SegmentNonce: "seg-" + session, SpoolDir: spool + "/" + session,
			MITMHosts: []string{fmt.Sprintf("*:%d", port)}, CACertPEM: certPEM, CAKeyPEM: keyPEM,
			EnableH2: true, SkipUpstreamVerify: true, AutoBypassPinned: true, Pcap: true,
		}
	}
	tunnelConfig := func(c *captureConfig) string {
		m := map[string]any{"transportType": "direct", "mtu": 1500}
		if c != nil {
			m["capture"] = c
		}
		b, _ := json.Marshal(m)
		return string(b)
	}
	configure := func(c captureConfig) {
		b, _ := json.Marshal(c)
		within(t, "CaptureConfigure", 3*time.Second, func() {
			if err := CaptureConfigure(string(b)); err != nil {
				t.Errorf("CaptureConfigure: %v", err)
			}
		})
	}
	status := func() map[string]any {
		var out map[string]any
		within(t, "GetStatus", 2*time.Second, func() { _ = json.Unmarshal([]byte(GetStatus()), &out) })
		return out
	}

	for round, initial := range []bool{false, true} {
		t.Run(fmt.Sprintf("round%d", round), func(t *testing.T) {
			session := fmt.Sprintf("s%d", round)
			// Like the app: start with CA-only config, then enable; or (after a restart) start enabled.
			var cfg string
			if initial {
				c := capture(session)
				cfg = tunnelConfig(&c)
			} else {
				c := capture("")
				cfg = tunnelConfig(&c)
			}
			within(t, "StartTunnel", 5*time.Second, func() {
				if err := StartTunnel(cfg, nil); err != nil {
					t.Fatalf("StartTunnel: %v", err)
				}
			})
			app := newAppStack(t)

			if !initial {
				configure(capture(session))
			}
			within(t, "CaptureResetFlows", 3*time.Second, func() { CaptureResetFlows() })
			status()

			// Concurrent traffic plus control-plane calls, like the app's polling.
			var wg sync.WaitGroup
			for i := 0; i < 6; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					body, err := app.httpsGet(t, ip, port, pool, fmt.Sprintf("/r%d", i))
					if err != nil || !strings.HasPrefix(body, "hello ") {
						t.Errorf("request %d: %q %v", i, body, err)
					}
				}(i)
			}
			for i := 0; i < 5; i++ {
				status()
				configure(capture(session))
				time.Sleep(50 * time.Millisecond)
			}
			wg.Wait()

			st := status()
			c, _ := st["capture"].(map[string]any)
			if c == nil || c["transactions"].(float64) < 6 {
				t.Errorf("capture status = %v", st["capture"])
			}
			within(t, "CaptureResetFlows", 3*time.Second, func() { CaptureResetFlows() })
			within(t, "CaptureStop", 5*time.Second, func() { CaptureStop() })
			within(t, "StopTunnel", 5*time.Second, func() { _ = StopTunnel() })
			app.close()
			within(t, "packet pumps", 3*time.Second, app.wg.Wait)
		})
	}
}
