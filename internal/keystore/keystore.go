// Package keystore manages the master key that encrypts keyshim's data at
// rest, and seals and opens data with keys derived from it.
//
// The master key lives in the OS keychain (macOS Keychain, Windows Credential
// Manager, Linux Secret Service) or is derived from a passphrase. key.json,
// stored next to the configuration, holds only the key ID, KDF parameters and
// a check value; it reveals nothing about the key.
package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/argon2"

	"github.com/waldemarsson/keyshim/internal/config"
)

const (
	SourceKeychain   = "keychain"
	SourcePassphrase = "passphrase"

	// MinPassphraseLength is the shortest passphrase accepted for a new key.
	MinPassphraseLength = 12

	metaFile        = "key.json"
	keyringService  = "keyshim"
	keySize         = 32
	sealedFormat    = "keyshim-sealed-v1"
	recoveryPrefix  = "keyshim-recovery-v1:"
	verifierPurpose = "key-check"
	verifierText    = "keyshim"
)

// Argon2id parameters for new passphrase keys; stored in key.json so they can
// be raised later without breaking existing keys.
var defaultKDF = kdfParams{Algorithm: "argon2id", Time: 3, MemoryKiB: 64 * 1024, Threads: 4}

// Keyring stores the master key. The default is the OS keychain.
type Keyring interface {
	Get(service, user string) (string, error)
	Set(service, user, secret string) error
}

type osKeyring struct{}

func (osKeyring) Get(service, user string) (string, error) { return keyring.Get(service, user) }
func (osKeyring) Set(service, user, secret string) error   { return keyring.Set(service, user, secret) }

// Options locates and unlocks a key.
type Options struct {
	// Dir holds key.json, normally the configuration directory.
	Dir string
	// Source is SourceKeychain or SourcePassphrase.
	Source string
	// Keyring overrides the OS keychain. Tests use it.
	Keyring Keyring
	// Passphrase asks for the passphrase; confirm is true when creating a key.
	Passphrase func(confirm bool) (string, error)
}

func (o Options) keyring() Keyring {
	if o.Keyring != nil {
		return o.Keyring
	}
	return osKeyring{}
}

type kdfParams struct {
	Algorithm string `json:"algorithm"`
	Salt      string `json:"salt"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memoryKiB"`
	Threads   uint8  `json:"threads"`
}

// meta is the content of key.json.
type meta struct {
	Version  int        `json:"version"`
	ID       string     `json:"id"`
	Source   string     `json:"source"`
	KDF      *kdfParams `json:"kdf,omitempty"`
	Verifier string     `json:"verifier"`
}

// Key is an unlocked master key.
type Key struct {
	id     string
	master []byte
}

// ID identifies the key; sealed data records the ID it was sealed with.
func (k *Key) ID() string { return k.id }

// LoadOrCreate unlocks the key described by key.json in o.Dir, creating a new
// key on first use.
func LoadOrCreate(o Options) (*Key, error) {
	m, err := readMeta(o.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return create(o)
	}
	if err != nil {
		return nil, err
	}
	if m.Source != o.Source {
		return nil, fmt.Errorf("%s uses key source %q but the configuration says %q; changing the key source is not supported",
			filepath.Join(o.Dir, metaFile), m.Source, o.Source)
	}

	var master []byte
	switch m.Source {
	case SourceKeychain:
		encoded, err := o.keyring().Get(keyringService, m.ID)
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, fmt.Errorf("key %s is not in the OS keychain; restore it with `keyshim key import`", m.ID)
		}
		if err != nil {
			return nil, keychainError(err)
		}
		if master, err = base64.StdEncoding.DecodeString(encoded); err != nil || len(master) != keySize {
			return nil, fmt.Errorf("key %s in the OS keychain is malformed", m.ID)
		}
	case SourcePassphrase:
		if m.KDF == nil {
			return nil, errors.New("key.json has no KDF parameters")
		}
		passphrase, err := o.Passphrase(false)
		if err != nil {
			return nil, err
		}
		if master, err = deriveKey(passphrase, m.KDF); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("key.json: unknown key source %q", m.Source)
	}

	k := &Key{id: m.ID, master: master}
	if err := k.verify(m); err != nil {
		if m.Source == SourcePassphrase {
			return nil, errors.New("wrong passphrase")
		}
		return nil, fmt.Errorf("key %s in the OS keychain does not match key.json", m.ID)
	}
	return k, nil
}

func create(o Options) (*Key, error) {
	m := meta{Version: 1, ID: randomHex(8), Source: o.Source}
	var master []byte
	switch o.Source {
	case SourceKeychain:
		master = randomBytes(keySize)
		if err := o.keyring().Set(keyringService, m.ID, base64.StdEncoding.EncodeToString(master)); err != nil {
			return nil, keychainError(err)
		}
	case SourcePassphrase:
		passphrase, err := o.Passphrase(true)
		if err != nil {
			return nil, err
		}
		if len(passphrase) < MinPassphraseLength {
			return nil, fmt.Errorf("passphrase must be at least %d characters", MinPassphraseLength)
		}
		kdf := defaultKDF
		kdf.Salt = base64.StdEncoding.EncodeToString(randomBytes(16))
		m.KDF = &kdf
		if master, err = deriveKey(passphrase, m.KDF); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown key source %q", o.Source)
	}

	k := &Key{id: m.ID, master: master}
	verifier, err := k.Seal(verifierPurpose, []byte(verifierText))
	if err != nil {
		return nil, err
	}
	m.Verifier = string(verifier)
	if err := writeMeta(o.Dir, m); err != nil {
		return nil, err
	}
	return k, nil
}

// RecoveryCode encodes the master key so it can be restored with Import.
// Anyone holding the code can decrypt keyshim's data.
func (k *Key) RecoveryCode() string {
	return recoveryPrefix + base64.RawURLEncoding.EncodeToString(k.master)
}

// Import stores a key from a recovery code in the OS keychain, after checking
// it against key.json. Used to restore a backup on another machine.
func Import(o Options, code string) error {
	m, err := readMeta(o.Dir)
	if err != nil {
		return err
	}
	if m.Source != SourceKeychain {
		return errors.New("import is only needed for keychain keys; passphrase keys are unlocked with the passphrase")
	}
	encoded, ok := strings.CutPrefix(strings.TrimSpace(code), recoveryPrefix)
	if !ok {
		return errors.New("not a keyshim recovery code")
	}
	master, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(master) != keySize {
		return errors.New("recovery code is malformed")
	}
	if err := (&Key{id: m.ID, master: master}).verify(m); err != nil {
		return errors.New("recovery code does not belong to this key.json")
	}
	if err := o.keyring().Set(keyringService, m.ID, base64.StdEncoding.EncodeToString(master)); err != nil {
		return keychainError(err)
	}
	return nil
}

func (k *Key) verify(m *meta) error {
	plain, err := k.Open(verifierPurpose, []byte(m.Verifier))
	if err != nil || string(plain) != verifierText {
		return errors.New("verification failed")
	}
	return nil
}

// sealed is the on-disk format of encrypted data. It is JSON so backups and
// diffs stay readable; everything except the ciphertext is public.
type sealed struct {
	Format  string `json:"format"`
	KeyID   string `json:"keyId"`
	Purpose string `json:"purpose"`
	Nonce   string `json:"nonce"`
	Data    string `json:"data"`
}

// Seal encrypts plaintext with AES-256-GCM under a key derived for purpose.
// The key ID and purpose are authenticated, so sealed data cannot be moved to
// another purpose or opened with another key.
func (k *Key) Seal(purpose string, plaintext []byte) ([]byte, error) {
	aead, err := k.aead(purpose)
	if err != nil {
		return nil, err
	}
	nonce := randomBytes(aead.NonceSize())
	out := sealed{
		Format:  sealedFormat,
		KeyID:   k.id,
		Purpose: purpose,
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
		Data:    base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, k.associatedData(purpose))),
	}
	return json.MarshalIndent(out, "", "  ")
}

// Open decrypts data produced by Seal for the same purpose.
func (k *Key) Open(purpose string, data []byte) ([]byte, error) {
	var s sealed
	if err := json.Unmarshal(data, &s); err != nil || s.Format != sealedFormat {
		return nil, ErrNotSealed
	}
	if s.KeyID != k.id {
		return nil, fmt.Errorf("data was encrypted with key %s, not the current key %s", s.KeyID, k.id)
	}
	if s.Purpose != purpose {
		return nil, fmt.Errorf("data was encrypted for %q, not %q", s.Purpose, purpose)
	}
	nonce, err1 := base64.StdEncoding.DecodeString(s.Nonce)
	ciphertext, err2 := base64.StdEncoding.DecodeString(s.Data)
	if err1 != nil || err2 != nil {
		return nil, errors.New("sealed data is malformed")
	}
	aead, err := k.aead(purpose)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("sealed data is malformed")
	}
	plain, err := aead.Open(nil, nonce, ciphertext, k.associatedData(purpose))
	if err != nil {
		return nil, errors.New("sealed data failed authentication; it was modified or belongs to another key")
	}
	return plain, nil
}

// ErrNotSealed means data is not in the sealed format, for example a
// plaintext file from before encryption.
var ErrNotSealed = errors.New("data is not encrypted by keyshim")

func (k *Key) aead(purpose string) (cipher.AEAD, error) {
	sub, err := hkdf.Key(sha256.New, k.master, nil, "keyshim/v1/"+purpose, keySize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sub)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (k *Key) associatedData(purpose string) []byte {
	return []byte(sealedFormat + "|" + k.id + "|" + purpose)
}

func deriveKey(passphrase string, p *kdfParams) ([]byte, error) {
	if p.Algorithm != "argon2id" {
		return nil, fmt.Errorf("unsupported KDF %q", p.Algorithm)
	}
	salt, err := base64.StdEncoding.DecodeString(p.Salt)
	if err != nil || len(salt) < 16 {
		return nil, errors.New("key.json: invalid KDF salt")
	}
	return argon2.IDKey([]byte(passphrase), salt, p.Time, p.MemoryKiB, p.Threads, keySize), nil
}

func readMeta(dir string) (*meta, error) {
	if err := config.CheckWritableOnlyByOwner(filepath.Join(dir, metaFile)); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, metaFile))
	if err != nil {
		return nil, err
	}
	var m meta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, metaFile), err)
	}
	if m.Version != 1 || m.ID == "" {
		return nil, fmt.Errorf("%s: unsupported or incomplete key metadata", filepath.Join(dir, metaFile))
	}
	return &m, nil
}

func writeMeta(dir string, m meta) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	// Exclusive create: never replace the metadata of an existing key.
	f, err := os.OpenFile(filepath.Join(dir, metaFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func keychainError(err error) error {
	return fmt.Errorf("OS keychain unavailable (%v); on a machine without a keychain, such as headless Linux, set `encryption: {key: passphrase}` in the configuration", err)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return b
}

func randomHex(n int) string {
	return hex.EncodeToString(randomBytes(n))
}
