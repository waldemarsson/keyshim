package ca

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/waldemarsson/keyshim/internal/keystore/keystoretest"
)

func TestLoadOrCreate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	key := keystoretest.NewKey(t)
	a, err := LoadOrCreate(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key permissions = %#o", perm)
	}

	again, err := LoadOrCreate(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.CertPEM(), again.CertPEM()) {
		t.Error("second load created a new CA")
	}
}

func TestLoadOrCreateRejectsOpenDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	key := keystoretest.NewKey(t)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir, key); err == nil {
		t.Error("want error for group/other-readable directory")
	}
}

func TestLeafVerifies(t *testing.T) {
	a, err := LoadOrCreate(filepath.Join(t.TempDir(), "ca"), keystoretest.NewKey(t))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(a.CertPEM())

	for _, host := range []string{"api.github.com", "127.0.0.1"} {
		c, err := a.Leaf(host)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots}); err != nil {
			t.Errorf("%s: %v", host, err)
		}
		cached, _ := a.Leaf(host)
		if cached != c {
			t.Errorf("%s: leaf not cached", host)
		}
	}

	c, _ := a.Leaf("api.github.com")
	a.now = func() time.Time { return c.Leaf.NotAfter.Add(-time.Hour) }
	renewed, err := a.Leaf("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	if renewed == c {
		t.Error("leaf near expiry was not renewed")
	}
}

func TestCAKeyIsEncrypted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	key := keystoretest.NewKey(t)
	if _, err := LoadOrCreate(dir, key); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "PRIVATE KEY") {
		t.Fatal("CA key is stored in plaintext")
	}
	if _, err := LoadOrCreate(dir, keystoretest.NewKey(t)); err == nil {
		t.Error("CA key opened with another master key")
	}
}

func TestPlaintextCAKeyIsMigrated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	key := keystoretest.NewKey(t)
	first, err := LoadOrCreate(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the pre-encryption layout: a plaintext PEM key.
	keyPEM, err := key.Open(keyPurpose, mustRead(t, filepath.Join(dir, keyFile)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyFile), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	migrated, err := LoadOrCreate(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if !migrated.Migrated || !bytes.Equal(migrated.CertPEM(), first.CertPEM()) {
		t.Errorf("Migrated = %v, same CA = %v", migrated.Migrated, bytes.Equal(migrated.CertPEM(), first.CertPEM()))
	}
	if strings.Contains(string(mustRead(t, filepath.Join(dir, keyFile))), "PRIVATE KEY") {
		t.Error("key still in plaintext after migration")
	}
	again, err := LoadOrCreate(dir, key)
	if err != nil || again.Migrated {
		t.Errorf("second load: migrated = %v, err = %v", again != nil && again.Migrated, err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestLeafCacheIsBounded(t *testing.T) {
	a, err := LoadOrCreate(filepath.Join(t.TempDir(), "ca"), keystoretest.NewKey(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := range maxLeaves + 10 {
		if _, err := a.Leaf(fmt.Sprintf("h%d.example.com", i)); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(a.leaves); n > maxLeaves {
		t.Errorf("leaf cache holds %d entries, limit %d", n, maxLeaves)
	}
}
