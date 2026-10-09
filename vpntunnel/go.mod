module github.com/trzsz/trzsz-ssh/vpntunnel

go 1.27.2

require (
	github.com/tailscale/wireguard-go v0.0.0-20260928213032-417aef361226
	github.com/trzsz/tsshd v0.1.7-0.20260125135324-348ee5b4ec22
	golang.org/x/mobile v0.0.0-20260204172633-1dceadbbeea3
	golang.org/x/net v0.60.0
	gvisor.dev/gvisor v0.0.0-20260915211658-a6f909f08a72
	tailscale.com v1.104.1
)

replace github.com/trzsz/tsshd => github.com/kitknox/tsshd-rootshell v0.0.0-20260719233000-1995533cdb5a

replace github.com/trzsz/kcp-go/v5 => github.com/kitknox/kcp-go-rootshell/v5 v5.0.0-20260718202214-2a3b09b878fb

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/UserExistsError/conpty v0.1.4 // indirect
	github.com/akutz/memconn v0.1.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/coder/websocket v1.8.15 // indirect
	github.com/creachadair/msync v0.10.1 // indirect
	github.com/creack/pty v1.1.24 // indirect
	github.com/dblohm7/wingoes v0.0.0-20260526185140-fb298caac7ca // indirect
	github.com/fxamacker/cbor/v2 v2.9.3 // indirect
	github.com/gaissmai/bart v0.29.0 // indirect
	github.com/go-json-experiment/json v0.0.0-20260820222146-c27c302e5fc3 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/hdevalence/ed25519consensus v0.2.0 // indirect
	github.com/jsimonetti/rtnetlink v1.4.2 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.14.1 // indirect
	github.com/mattn/go-runewidth v0.0.24 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.7.0 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/pires/go-proxyproto v0.15.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rcarmo/go-te v0.1.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/safchain/ethtool v0.7.0 // indirect
	github.com/tailscale/certstore v0.1.1-0.20260409135935-3638fb84b77d // indirect
	github.com/tailscale/go-winio v0.0.0-20231025203758-c4f33415bf55 // indirect
	github.com/tailscale/hujson v0.0.0-20260727124030-b80ff77dac4f // indirect
	github.com/tailscale/peercred v0.0.0-20250107143737-35a0c7bd7edc // indirect
	github.com/tailscale/web-client-prebuilt v0.0.0-20260917222731-e0ed2d0d0fea // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/trzsz/kcp-go/v5 v5.6.72 // indirect
	github.com/trzsz/quic-go v0.60.1 // indirect
	github.com/trzsz/shellescape v1.6.0 // indirect
	github.com/trzsz/smux v1.6.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	go4.org/netipx v0.0.0-20260823151212-3075585bcbeb // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/exp v0.0.0-20260908205506-85c1c2202aba // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/term v0.46.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard/windows v1.0.1 // indirect
)
