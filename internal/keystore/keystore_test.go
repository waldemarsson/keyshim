package keystore_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/waldemarsson/keyshim/internal/keystore"
	"github.com/waldemarsson/keyshim/internal/keystore/keystoretest"
)

func keychainOptions(dir string, kr keystore.Keyring) keystore.Options {
	return keystore.Options{Dir: dir, Source: keystore.SourceKeychain, Keyring: kr}
}

func passphraseOptions(dir, passphrase string) keystore.Options {
	return keystore.Options{
		Dir:        dir,
		Source:     keystore.SourcePassphrase,
		Passphrase: func(bool) (string, error) { return passphrase, nil },
	}
}

func TestKeychainKeySurvivesRestart(t *testing.T) {
	dir, kr := t.TempDir(), keystoretest.NewKeyring()
	first, err := keystore.LoadOrCreate(keychainOptions(dir, kr))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := first.Seal("test", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	again, err := keystore.LoadOrCreate(keychainOptions(dir, kr))
	if err != nil {
		t.Fatal(err)
	}
	if again.ID() != first.ID() {
		t.Fatal("restart created a new key")
	}
	plain, err := again.Open("test", sealed)
	if err != nil || string(plain) != "hello" {
		t.Fatalf("Open = %q, %v", plain, err)
	}

	meta, _ := os.ReadFile(filepath.Join(dir, "key.json"))
	stored, _ := kr.Get("keyshim", first.ID())
	if stored == "" || bytes.Contains(meta, []byte(stored)) {
		t.Error("key.json contains the key, or the keychain is empty")
	}
}

func TestMissingKeychainItem(t *testing.T) {
	dir, kr := t.TempDir(), keystoretest.NewKeyring()
	key, err := keystore.LoadOrCreate(keychainOptions(dir, kr))
	if err != nil {
		t.Fatal(err)
	}
	code := key.RecoveryCode()

	kr.Delete("keyshim", key.ID())
	_, err = keystore.LoadOrCreate(keychainOptions(dir, kr))
	if err == nil || !strings.Contains(err.Error(), "keyshim key import") {
		t.Fatalf("err = %v, want hint to import", err)
	}

	if err := keystore.Import(keychainOptions(dir, kr), "keyshim-recovery-v1:AAAA"); err == nil {
		t.Error("malformed code accepted")
	}
	other := keystoretest.NewKey(t).RecoveryCode()
	if err := keystore.Import(keychainOptions(dir, kr), other); err == nil {
		t.Error("code from another key accepted")
	}
	if err := keystore.Import(keychainOptions(dir, kr), code); err != nil {
		t.Fatal(err)
	}
	if _, err := keystore.LoadOrCreate(keychainOptions(dir, kr)); err != nil {
		t.Fatalf("after import: %v", err)
	}
}

func TestPassphraseKey(t *testing.T) {
	dir := t.TempDir()
	if _, err := keystore.LoadOrCreate(passphraseOptions(dir, "short")); err == nil {
		t.Error("short passphrase accepted")
	}
	key, err := keystore.LoadOrCreate(passphraseOptions(dir, "correct horse battery"))
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := key.Seal("test", []byte("hello"))

	if _, err := keystore.LoadOrCreate(passphraseOptions(dir, "wrong passphrase here")); err == nil || err.Error() != "wrong passphrase" {
		t.Errorf("wrong passphrase: err = %v", err)
	}
	again, err := keystore.LoadOrCreate(passphraseOptions(dir, "correct horse battery"))
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := again.Open("test", sealed); err != nil || string(plain) != "hello" {
		t.Errorf("Open = %q, %v", plain, err)
	}
	if _, err := keystore.LoadOrCreate(keychainOptions(dir, keystoretest.NewKeyring())); err == nil {
		t.Error("switching key source accepted")
	}
}

func TestKeychainUnavailable(t *testing.T) {
	_, err := keystore.LoadOrCreate(keychainOptions(t.TempDir(), failingKeyring{}))
	if err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("err = %v, want hint to use a passphrase", err)
	}
}

type failingKeyring struct{}

func (failingKeyring) Get(string, string) (string, error) { return "", errors.New("no secret service") }
func (failingKeyring) Set(string, string, string) error   { return errors.New("no secret service") }

func TestSealBindsPurposeAndKey(t *testing.T) {
	key := keystoretest.NewKey(t)
	sealed, err := key.Seal("secrets", []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("value")) {
		t.Error("sealed data contains the plaintext")
	}
	if _, err := key.Open("ca-key", sealed); err == nil {
		t.Error("opened with another purpose")
	}
	if _, err := keystoretest.NewKey(t).Open("secrets", sealed); err == nil {
		t.Error("opened with another key")
	}
	tampered := bytes.Replace(sealed, []byte(`"data": "`), []byte(`"data": "AAAA`), 1)
	if _, err := key.Open("secrets", tampered); err == nil {
		t.Error("tampered data accepted")
	}
	if _, err := key.Open("secrets", []byte("plain: text\n")); !errors.Is(err, keystore.ErrNotSealed) {
		t.Errorf("plaintext: err = %v, want ErrNotSealed", err)
	}
	again, _ := key.Seal("secrets", []byte("value"))
	if bytes.Equal(sealed, again) {
		t.Error("two seals produced identical output; nonce reused")
	}
}

func TestRefusesKeyMetadataWritableByOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not reflect ACLs on Windows; the check is skipped there")
	}
	dir, kr := t.TempDir(), keystoretest.NewKeyring()
	if _, err := keystore.LoadOrCreate(keychainOptions(dir, kr)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "key.json"), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := keystore.LoadOrCreate(keychainOptions(dir, kr)); err == nil {
		t.Error("world-writable key.json accepted")
	}
}
