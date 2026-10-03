package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/waldemarsson/fullmakt/internal/config"
	"github.com/waldemarsson/fullmakt/internal/keystore"
)

// localPurpose binds the encrypted file to its use, so it cannot be swapped
// with another sealed file such as the CA key.
const localPurpose = "local-secrets"

// ErrExists is returned when adding a key that is already stored. Values are
// never replaced in place; delete the key first.
var ErrExists = errors.New("key already exists; delete it first to store a new value")

// Local stores secrets in a file encrypted with the master key. Values can be
// added and deleted but never read back except by the proxy.
type Local struct {
	path string
	key  *keystore.Key
	now  func() time.Time
	mu   sync.Mutex
}

// Entry describes a stored value without revealing it.
type Entry struct {
	Name    string    `json:"name"`
	AddedAt time.Time `json:"addedAt"`
}

// localFile is the decrypted content of the file.
type localFile struct {
	Entries map[string]localEntry `json:"entries"`
}

type localEntry struct {
	Value   string    `json:"value"`
	AddedAt time.Time `json:"addedAt"`
}

// NewLocal returns a provider for the encrypted file at path.
func NewLocal(path string, key *keystore.Key) *Local {
	return &Local{path: path, key: key, now: time.Now}
}

// Fetch returns the value stored under name.
func (l *Local) Fetch(_ context.Context, name, version string) (string, error) {
	if version != "" {
		return "", errors.New("local provider does not support versions")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := l.read()
	if err != nil {
		return "", err
	}
	e, ok := f.Entries[name]
	if !ok {
		return "", fmt.Errorf("%s: key %q not found", l.path, name)
	}
	return e.Value, nil
}

// Entries lists stored keys by name, without values.
func (l *Local) Entries() ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := l.read()
	if errors.Is(err, fs.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(f.Entries))
	for _, name := range slices.Sorted(maps.Keys(f.Entries)) {
		out = append(out, Entry{Name: name, AddedAt: f.Entries[name].AddedAt})
	}
	return out, nil
}

// Add stores a new key. It fails with ErrExists if the key is already stored.
func (l *Local) Add(name, value string) error {
	if name == "" {
		return errors.New("name is required")
	}
	if value == "" {
		return errors.New("value is required")
	}
	return l.update(func(f *localFile) error {
		if _, ok := f.Entries[name]; ok {
			return fmt.Errorf("%q: %w", name, ErrExists)
		}
		f.Entries[name] = localEntry{Value: value, AddedAt: l.now().UTC().Truncate(time.Second)}
		return nil
	})
}

// Import adds every pair from values, skipping keys that already exist. It
// returns the names added and skipped.
func (l *Local) Import(values map[string]string) (added, skipped []string, err error) {
	err = l.update(func(f *localFile) error {
		now := l.now().UTC().Truncate(time.Second)
		for _, name := range slices.Sorted(maps.Keys(values)) {
			if _, ok := f.Entries[name]; ok || values[name] == "" {
				skipped = append(skipped, name)
				continue
			}
			f.Entries[name] = localEntry{Value: values[name], AddedAt: now}
			added = append(added, name)
		}
		return nil
	})
	return added, skipped, err
}

// Delete removes a key.
func (l *Local) Delete(name string) error {
	return l.update(func(f *localFile) error {
		if _, ok := f.Entries[name]; !ok {
			return fmt.Errorf("key %q not found", name)
		}
		delete(f.Entries, name)
		return nil
	})
}

func (l *Local) update(change func(*localFile) error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := l.read()
	if errors.Is(err, fs.ErrNotExist) {
		f, err = &localFile{Entries: map[string]localEntry{}}, nil
	}
	if err != nil {
		return err
	}
	if err := change(f); err != nil {
		return err
	}
	plain, err := json.Marshal(f)
	if err != nil {
		return err
	}
	sealed, err := l.key.Seal(localPurpose, plain)
	if err != nil {
		return err
	}
	return config.WriteFileAtomic(l.path, sealed, 0o600)
}

// read decrypts the file after checking its permissions. Callers hold l.mu.
func (l *Local) read() (*localFile, error) {
	fh, err := os.Open(l.path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	// Check the opened file, not the path, so the file cannot be swapped
	// between the check and the read.
	info, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s: permissions %#o allow access by group or others; run chmod 600", l.path, perm)
	}
	data, err := io.ReadAll(fh)
	if err != nil {
		return nil, err
	}
	plain, err := l.key.Open(localPurpose, data)
	if errors.Is(err, keystore.ErrNotSealed) {
		return nil, fmt.Errorf("%s is not encrypted; move it aside and load it with `fullmakt secrets import`", l.path)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", l.path, err)
	}
	var f localFile
	if err := json.Unmarshal(plain, &f); err != nil {
		return nil, fmt.Errorf("%s: invalid content", l.path)
	}
	if f.Entries == nil {
		f.Entries = map[string]localEntry{}
	}
	return &f, nil
}
