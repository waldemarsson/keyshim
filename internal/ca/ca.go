// Package ca manages the local certificate authority used to intercept TLS
// for hosts that receive secrets.
package ca

import (
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
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	certFile = "ca.crt"
	keyFile  = "ca.key"

	caValidity      = 2 * 365 * 24 * time.Hour
	leafValidity    = 7 * 24 * time.Hour
	leafRenewBefore = 24 * time.Hour
	clockSkew       = time.Hour
)

// Authority signs short-lived leaf certificates. The CA key stays on disk in
// a directory only the owner can access; leaf keys exist only in memory.
type Authority struct {
	cert     *x509.Certificate
	key      crypto.Signer
	certPEM  []byte
	certPath string
	leafKey  *ecdsa.PrivateKey
	now      func() time.Time

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// LoadOrCreate loads the CA from dir, creating it on first use.
func LoadOrCreate(dir string) (*Authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := checkPrivate(dir); err != nil {
		return nil, err
	}
	certPath, keyPath := filepath.Join(dir, certFile), filepath.Join(dir, keyFile)

	certPEM, err := os.ReadFile(certPath)
	if errors.Is(err, fs.ErrNotExist) {
		if err := create(certPath, keyPath); err != nil {
			return nil, fmt.Errorf("create CA: %w", err)
		}
		certPEM, err = os.ReadFile(certPath)
	}
	if err != nil {
		return nil, err
	}
	if err := checkPrivate(keyPath); err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	cert, err := parseCert(certPEM)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", certPath, err)
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", keyPath, err)
	}
	if pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("%s does not match %s", keyPath, certPath)
	}
	if time.Now().After(cert.NotAfter) {
		return nil, fmt.Errorf("%s expired on %s; remove %s to create a new CA", certPath, cert.NotAfter.Format(time.DateOnly), dir)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Authority{
		cert:     cert,
		key:      key,
		certPEM:  certPEM,
		certPath: certPath,
		leafKey:  leafKey,
		now:      time.Now,
		leaves:   map[string]*tls.Certificate{},
	}, nil
}

// CertPEM returns the public CA certificate for client trust stores.
func (a *Authority) CertPEM() []byte {
	return a.certPEM
}

// CertPath returns the path of the CA certificate file.
func (a *Authority) CertPath() string {
	return a.certPath
}

// Leaf returns a certificate for host, issuing a new one when the cached
// certificate is close to expiry.
func (a *Authority) Leaf(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now()
	if c, ok := a.leaves[host]; ok && now.Add(leafRenewBefore).Before(c.Leaf.NotAfter) {
		return c, nil
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(leafValidity)
	if notAfter.After(a.cert.NotAfter) {
		notAfter = a.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &a.leafKey.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{
		Certificate: [][]byte{der, a.cert.Raw},
		PrivateKey:  a.leafKey,
		Leaf:        leaf,
	}
	a.leaves[host] = c
	return c, nil
}

func create(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Fullmakt"},
			CommonName:   fmt.Sprintf("Fullmakt Local CA %08x", serial.Uint64()&0xffffffff),
		},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	// Write the key first and exclusively, so an existing key is never replaced.
	if err := writeExclusive(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return writeExclusive(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func writeExclusive(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func checkPrivate(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s: permissions %#o allow access by group or others", path, perm)
	}
	return nil
}

func parseCert(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM certificate found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, errors.New("certificate is not a CA")
	}
	return cert, nil
}

func parseKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("no PEM private key found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key cannot sign")
	}
	return signer, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
