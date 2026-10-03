// Package keystoretest provides an in-memory keychain and ready keys for tests.
package keystoretest

import (
	"sync"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/waldemarsson/fullmakt/internal/keystore"
)

// Keyring is an in-memory keystore.Keyring.
type Keyring struct {
	mu     sync.Mutex
	values map[string]string
}

// NewKeyring returns an empty in-memory keyring.
func NewKeyring() *Keyring {
	return &Keyring{values: map[string]string{}}
}

func (k *Keyring) Get(service, user string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.values[service+"/"+user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (k *Keyring) Set(service, user, secret string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.values[service+"/"+user] = secret
	return nil
}

// Delete removes an entry, simulating a lost keychain item.
func (k *Keyring) Delete(service, user string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.values, service+"/"+user)
}

// NewKey creates a keychain-backed key in a temporary directory.
func NewKey(t testing.TB) *keystore.Key {
	t.Helper()
	key, err := keystore.LoadOrCreate(keystore.Options{
		Dir:     t.TempDir(),
		Source:  keystore.SourceKeychain,
		Keyring: NewKeyring(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return key
}
