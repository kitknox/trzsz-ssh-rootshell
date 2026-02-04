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

import (
	"github.com/trzsz/trzsz-ssh/tssh"
)

// TSSHArgs holds the connection parameters for an SSH connection.
// Create with NewTSSHArgs() and configure before calling Connect().
//
// This struct is gomobile-compatible and uses simple types that can be
// marshaled across the Go/ObjC boundary.
type TSSHArgs struct {
	// Destination is the remote server to connect to.
	// Can be a hostname, IP address, or SSH config alias.
	// Examples: "host.example.com", "192.168.1.1", "myserver"
	Destination string

	// LoginName is the username to log in as on the remote host.
	// If empty, uses the SSH config value or current system user.
	LoginName string

	// Port is the SSH port to connect to.
	// Default is 22 if not specified.
	Port int

	// TsshdPath is the path to the tsshd binary on the remote server.
	// Required for UDP/KCP/QUIC modes. Default is "tsshd" (in PATH).
	TsshdPath string

	// TsshdPort is the port or port range for tsshd to listen on.
	// Examples: "8000", "8000-9000"
	TsshdPort string

	// UDP enables UDP-based transport (mosh-like behavior).
	// Provides better latency over high-latency/lossy networks.
	UDP bool

	// KCP enables KCP protocol over UDP for reliable transport.
	// Recommended for most use cases over raw UDP.
	KCP bool

	// Debug enables verbose debug logging.
	Debug bool

	// IPv4Only forces IPv4 addresses only.
	IPv4Only bool

	// IPv6Only forces IPv6 addresses only.
	IPv6Only bool

	// ProxyJump specifies jump hosts, comma-separated.
	// Example: "jump1.example.com,jump2.example.com"
	ProxyJump string

	// ConfigFile specifies a custom SSH config file path.
	// If empty, uses ~/.ssh/config
	ConfigFile string

	// CipherSpec specifies the cipher for encryption.
	// If empty, uses the default cipher suite.
	CipherSpec string

	// Internal: identity file paths (set via AddIdentity)
	identities []string

	// Internal: SSH options (set via SetOption)
	options map[string][]string
}

// NewTSSHArgs creates a new TSSHArgs with default values.
// This is the gomobile-friendly constructor.
func NewTSSHArgs() *TSSHArgs {
	return &TSSHArgs{
		Port:    22,
		options: make(map[string][]string),
	}
}

// AddIdentity adds a private key file path for authentication.
// Can be called multiple times to add multiple keys.
// The path should be absolute.
func (a *TSSHArgs) AddIdentity(path string) {
	if path != "" {
		a.identities = append(a.identities, path)
	}
}

// ClearIdentities removes all previously added identity files.
func (a *TSSHArgs) ClearIdentities() {
	a.identities = nil
}

// SetOption sets an SSH config option.
// name is the option name (case-insensitive).
// value is the option value.
// Can be called multiple times with the same name to add multiple values.
func (a *TSSHArgs) SetOption(name, value string) {
	if a.options == nil {
		a.options = make(map[string][]string)
	}
	a.options[name] = append(a.options[name], value)
}

// ClearOptions removes all previously set options.
func (a *TSSHArgs) ClearOptions() {
	a.options = make(map[string][]string)
}

// toSshArgs converts TSSHArgs to the internal tssh.SshArgs format.
func (a *TSSHArgs) toSshArgs() *tssh.SshArgs {
	return &tssh.SshArgs{
		Destination: a.Destination,
		LoginName:   a.LoginName,
		Port:        a.Port,
		TsshdPath:   a.TsshdPath,
		TsshdPort:   a.TsshdPort,
		UDP:         a.UDP,
		KCP:         a.KCP,
		Debug:       a.Debug,
		IPv4Only:    a.IPv4Only,
		IPv6Only:    a.IPv6Only,
		ProxyJump:   a.ProxyJump,
		ConfigFile:  a.ConfigFile,
		CipherSpec:  a.CipherSpec,
		Identity:    a.identities,
		Option:      a.options,
	}
}

// Validate checks if the TSSHArgs are valid for connection.
// Returns an error string if invalid, or empty string if valid.
func (a *TSSHArgs) Validate() string {
	if a.Destination == "" {
		return "destination is required"
	}
	if a.Port < 1 || a.Port > 65535 {
		return "port must be between 1 and 65535"
	}
	if a.UDP && a.KCP {
		// KCP implies UDP, so this is allowed but KCP takes precedence
	}
	return ""
}
