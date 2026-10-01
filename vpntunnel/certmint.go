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
	"container/list"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

const leafCacheSize = 64

// certMinter issues per-host leaf certificates signed by the user's capture CA.
// One P-256 leaf key is shared by every leaf for the life of the tunnel.
type certMinter struct {
	caCert  *x509.Certificate
	caKey   crypto.Signer
	caPEM   string
	leafKey *ecdsa.PrivateKey

	mu       sync.Mutex
	items    map[string]*list.Element
	lru      *list.List
	inflight map[string]*mintCall
}

type leafEntry struct {
	name string
	cert *tls.Certificate
}

type mintCall struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

func newCertMinter(certPEM, keyPEM string) (*certMinter, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("capture CA: no certificate PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("capture CA: %w", err)
	}
	caKey, err := parseSignerPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &certMinter{
		caCert:   caCert,
		caKey:    caKey,
		caPEM:    certPEM,
		leafKey:  leafKey,
		items:    make(map[string]*list.Element),
		lru:      list.New(),
		inflight: make(map[string]*mintCall),
	}, nil
}

func parseSignerPEM(keyPEM string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("capture CA: no key PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, errors.New("capture CA: key is not a signer")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("capture CA: unsupported key format")
}

// certFor returns a cached or freshly minted leaf for name (DNS name or IP).
func (m *certMinter) certFor(name string) (*tls.Certificate, error) {
	m.mu.Lock()
	if el, ok := m.items[name]; ok {
		m.lru.MoveToFront(el)
		c := el.Value.(*leafEntry).cert
		m.mu.Unlock()
		return c, nil
	}
	if call, ok := m.inflight[name]; ok {
		m.mu.Unlock()
		<-call.done
		return call.cert, call.err
	}
	call := &mintCall{done: make(chan struct{})}
	m.inflight[name] = call
	m.mu.Unlock()

	call.cert, call.err = m.mint(name)

	m.mu.Lock()
	delete(m.inflight, name)
	if call.err == nil {
		m.items[name] = m.lru.PushFront(&leafEntry{name: name, cert: call.cert})
		for m.lru.Len() > leafCacheSize {
			old := m.lru.Back()
			m.lru.Remove(old)
			delete(m.items, old.Value.(*leafEntry).name)
		}
	}
	m.mu.Unlock()
	close(call.done)
	return call.cert, call.err
}

func (m *certMinter) mint(name string) (*tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	// Apple rejects leaves valid for more than 825 days; a year also stays
	// clear of the 398-day public limit some clients apply regardless.
	notAfter := now.Add(365 * 24 * time.Hour)
	if notAfter.After(m.caCert.NotAfter) {
		notAfter = m.caCert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, &m.leafKey.PublicKey, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("mint leaf for %s: %w", name, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: m.leafKey, Leaf: leaf}, nil
}

// caDER returns the CA certificate in DER form (for the download endpoint).
func (m *certMinter) caDER() []byte { return m.caCert.Raw }
