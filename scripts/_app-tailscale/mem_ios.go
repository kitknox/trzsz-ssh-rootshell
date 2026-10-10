// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Replaces tailscale.com/wgengine/wgcfg/mem_ios.go in the app's framework; see
// tssh_use_app_tailscale. The in-app engine isn't held to a network
// extension's memory limit, so its WireGuard pool has no ceiling, as on every
// other platform. With the extension's 64, packets staged behind handshakes
// after a suspend can take every buffer the handshakes need to finish.

package wgcfg

import (
	"github.com/tailscale/wireguard-go/device"
)

func getMemoryOptions() []device.Option {
	return []device.Option{
		device.WithQueueStagedSize(64),
		device.WithQueueOutboundSize(64),
		device.WithQueueInboundSize(64),
		device.WithQueueHandshakeSize(64),
	}
}
