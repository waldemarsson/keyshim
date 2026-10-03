package secrets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"slices"
	"sync"

	"go.yaml.in/yaml/v3"

	"github.com/waldemarsson/fullmakt/internal/config"
)

// Local reads secrets from a YAML file of key: value pairs. The file must not
// be readable or writable by group or others.
type Local struct {
	path string
	mu   sync.Mutex
}

// NewLocal returns a provider for the file at path.
func NewLocal(path string) *Local {
	return &Local{path: path}
}

// Fetch returns the value stored under name.
func (l *Local) Fetch(_ context.Context, name, version string) (string, error) {
	if version != "" {
		return "", errors.New("local provider does not support versions")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	values, err := l.read()
	if err != nil {
		return "", err
	}
	v, ok := values[name]
	if !ok {
		return "", fmt.Errorf("%s: key %q not found", l.path, name)
	}
	return v, nil
}

// Keys returns the stored key names, never the values.
func (l *Local) Keys() ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	values, err := l.read()
	if errors.Is(err, fs.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	return slices.Sorted(maps.Keys(values)), nil
}

// Set stores value under key, creating the file if needed.
func (l *Local) Set(key, value string) error {
	if key == "" {
		return errors.New("key is required")
	}
	if value == "" {
		return errors.New("value is required")
	}
	return l.update(func(values map[string]string) { values[key] = value })
}

// Delete removes key.
func (l *Local) Delete(key string) error {
	return l.update(func(values map[string]string) { delete(values, key) })
}

func (l *Local) update(change func(map[string]string)) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	values, err := l.read()
	if errors.Is(err, fs.ErrNotExist) {
		values, err = map[string]string{}, nil
	}
	if err != nil {
		return err
	}
	change(values)
	data, err := yaml.Marshal(values)
	if err != nil {
		return err
	}
	return config.WriteFileAtomic(l.path, data, 0o600)
}

// read loads the file after checking its permissions. Callers hold l.mu.
func (l *Local) read() (map[string]string, error) {
	f, err := os.Open(l.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Check the opened file, not the path, so the file cannot be swapped
	// between the check and the read.
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s: permissions %#o allow access by group or others; run chmod 600", l.path, perm)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	if err := yaml.Unmarshal(data, &values); err != nil {
		return nil, fmt.Errorf("%s: invalid YAML", l.path)
	}
	return values, nil
}
