package ca

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOrCreate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	a, err := LoadOrCreate(dir)
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

	again, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.CertPEM(), again.CertPEM()) {
		t.Error("second load created a new CA")
	}
}

func TestLoadOrCreateRejectsOpenDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); err == nil {
		t.Error("want error for group/other-readable directory")
	}
}

func TestLeafVerifies(t *testing.T) {
	a, err := LoadOrCreate(filepath.Join(t.TempDir(), "ca"))
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
