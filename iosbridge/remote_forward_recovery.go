package iosbridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/trzsz/tsshd/tsshd"
)

type remoteForwardClient interface {
	Listen(network, address string) (net.Listener, error)
	DialTimeout(network, address string, timeout time.Duration) (tsshd.Stream, error)
}

// Existing servers can leave handleListenEvent blocked in Accept after the
// client's listen stream closes. Wake that accept through the authenticated
// target transport; no direct TCP route to the server or new protocol is needed.
// Only the subsequent Listen success ACK proves that the old port was released
// and that this forward owns the replacement listener.
func listenRemoteForward(ctx context.Context, client remoteForwardClient, address string, recover bool) (net.Listener, error) {
	if recover {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return nil, fmt.Errorf("remote listener was not released: %v: %w", lastErr, err)
			}
			return nil, err
		}
		listener, err := client.Listen("tcp", address)
		if err == nil {
			return listener, nil
		}
		// Server errors arrive as text, without the remote OS's syscall errno.
		if !recover || !strings.Contains(strings.ToLower(err.Error()), "address already in use") {
			return nil, err
		}
		lastErr = err
		if err = wakeRemoteListener(ctx, client, address); err != nil {
			return nil, fmt.Errorf("could not release previous remote listener: %w", err)
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

func remoteListenerWakeAddress(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	// A wildcard is a bind address, not a portable connect destination.
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return net.JoinHostPort(host, port), nil
}

func wakeRemoteListener(ctx context.Context, client remoteForwardClient, address string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	wakeAddress, err := remoteListenerWakeAddress(address)
	if err != nil {
		return err
	}
	conn, err := client.DialTimeout("tcp", wakeAddress, time.Second)
	if err != nil {
		// The old listener may have closed between the failed bind and dial.
		// Retry Listen to acquire it; permission/transport errors are final.
		if strings.Contains(strings.ToLower(err.Error()), "connection refused") {
			return nil
		}
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline := time.Now().Add(250 * time.Millisecond)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err = conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	// No payload: a stale listener closes the accepted socket when sending to
	// its closed listen stream fails. FIN may still be in flight, so bounded
	// timeouts retry. EOF alone is not sufficient; the next bind must succeed.
	var b [1]byte
	n, err := conn.Read(b[:])
	if n != 0 {
		return fmt.Errorf("remote port responded with data instead of closing")
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return nil
	}
	return err
}
