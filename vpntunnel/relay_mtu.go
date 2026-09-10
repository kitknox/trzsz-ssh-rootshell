package vpntunnel

import "fmt"

// resolveRelayMTU bounds an inner transport packet by the outer transport's
// datagram payload. Use the result for BOTH the target server and client.
func resolveRelayMTU(requested, budget int, mode string) (int, error) {
	if requested <= 0 {
		requested = 1400
	}
	mtu := min(requested, budget)
	minimum := 100
	switch mode {
	case "QUIC":
		minimum = 1200
	case "KCP":
	default:
		return 0, fmt.Errorf("unsupported relay transport %q", mode)
	}
	if mtu < minimum || mtu > 65535 {
		return 0, fmt.Errorf("jump host datagram budget %d cannot carry %s packets (minimum %d); increase the jump transport MTU", mtu, mode, minimum)
	}
	return mtu, nil
}
