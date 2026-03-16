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
	"encoding/base64"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// AgentCallback is the interface for handling SSH agent operations.
// Implement this interface in Swift to provide SSH agent forwarding.
//
// All methods are called from background goroutines and must be thread-safe.
// The Swift implementation should dispatch to the main actor for key operations.
type AgentCallback interface {
	// ListIdentities returns a JSON-encoded array of SSH agent identities.
	// Each element has "blob" (base64-encoded public key) and "comment" (key name).
	// Example: [{"blob":"AAAA...","comment":"my-key"}]
	// Returns "[]" for no keys.
	ListIdentities() (string, error)

	// SignData signs data with the key identified by publicKeyBlob.
	// publicKeyBlob is the raw SSH wire-format public key blob.
	// data is the data to sign.
	// flags contains SSH agent signature flags (e.g., SSH_AGENT_RSA_SHA2_256).
	// Returns the signature in SSH wire format (string algorithm + string blob).
	// Note: flags is int32 (not uint32) due to gomobile limitations on unsigned types.
	SignData(publicKeyBlob []byte, data []byte, flags int32) ([]byte, error)
}

// agentIdentityJSON is the JSON structure for an SSH agent identity.
type agentIdentityJSON struct {
	Blob    string `json:"blob"`
	Comment string `json:"comment"`
}

// swiftBackedAgent implements agent.ExtendedAgent by delegating to a Swift callback.
type swiftBackedAgent struct {
	callback AgentCallback
}

func (a *swiftBackedAgent) List() ([]*agent.Key, error) {
	jsonStr, err := a.callback.ListIdentities()
	if err != nil {
		return nil, fmt.Errorf("ListIdentities callback failed: %w", err)
	}

	var identities []agentIdentityJSON
	if err := json.Unmarshal([]byte(jsonStr), &identities); err != nil {
		return nil, fmt.Errorf("failed to parse identities JSON: %w", err)
	}

	keys := make([]*agent.Key, 0, len(identities))
	for _, id := range identities {
		blob, err := base64.StdEncoding.DecodeString(id.Blob)
		if err != nil {
			continue
		}
		pubKey, err := ssh.ParsePublicKey(blob)
		if err != nil {
			continue
		}
		keys = append(keys, &agent.Key{
			Format:  pubKey.Type(),
			Blob:    blob,
			Comment: id.Comment,
		})
	}
	return keys, nil
}

func (a *swiftBackedAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *swiftBackedAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	sigBytes, err := a.callback.SignData(key.Marshal(), data, int32(flags))
	if err != nil {
		return nil, fmt.Errorf("SignData callback failed: %w", err)
	}

	// Parse SSH wire format signature
	sig := new(ssh.Signature)
	if err := ssh.Unmarshal(sigBytes, sig); err != nil {
		return nil, fmt.Errorf("failed to parse signature from Swift: %w", err)
	}
	return sig, nil
}

// Unsupported operations — agent forwarding only needs List and Sign.

func (a *swiftBackedAgent) Add(key agent.AddedKey) error {
	return fmt.Errorf("adding keys is not supported")
}

func (a *swiftBackedAgent) Remove(key ssh.PublicKey) error {
	return fmt.Errorf("removing keys is not supported")
}

func (a *swiftBackedAgent) RemoveAll() error {
	return fmt.Errorf("removing keys is not supported")
}

func (a *swiftBackedAgent) Lock(passphrase []byte) error {
	return fmt.Errorf("locking is not supported")
}

func (a *swiftBackedAgent) Unlock(passphrase []byte) error {
	return fmt.Errorf("unlocking is not supported")
}

func (a *swiftBackedAgent) Signers() ([]ssh.Signer, error) {
	return nil, fmt.Errorf("signers is not supported")
}

func (a *swiftBackedAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

// EnableAgentForwarding registers a handler for SSH agent channel requests
// and serves agent protocol on each channel using the provided callback.
//
// This must be called BEFORE RequestAgentForwarding() on any session.
// Only one agent handler can be registered per transport.
func (t *Transport) EnableAgentForwarding(callback AgentCallback) error {
	agentChan := t.client.HandleChannelOpen("auth-agent@openssh.com")
	if agentChan == nil {
		return fmt.Errorf("agent channel handler already registered")
	}

	stopChan := make(chan struct{})
	t.mu.Lock()
	t.agentStopChan = stopChan
	t.mu.Unlock()

	agentImpl := &swiftBackedAgent{callback: callback}

	go func() {
		for {
			select {
			case <-stopChan:
				return
			case newChannel, ok := <-agentChan:
				if !ok {
					return
				}
				channel, _, err := newChannel.Accept()
				if err != nil {
					if dl := getDebugLogger(); dl != nil {
						dl.OnDebug(fmt.Sprintf("[agent] failed to accept channel: %v", err))
					}
					continue
				}
				go agent.ServeAgent(agentImpl, channel)
			}
		}
	}()

	return nil
}

// RequestAgentForwarding requests SSH agent forwarding on this session.
// Must be called BEFORE Shell() or StartCommand() — the agent flag is
// included in the session start message sent to the server.
func (s *TransportSession) RequestAgentForwarding() error {
	if s.closed.Load() {
		return fmt.Errorf("session is closed")
	}
	if s.started.Load() {
		return fmt.Errorf("session already started")
	}
	_, err := s.session.SendRequest("auth-agent-req@openssh.com", true, nil)
	return err
}
