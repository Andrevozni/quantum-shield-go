// Package castore persists a QuantumShield CA hierarchy to an encrypted file.
//
// # File format
//
// The on-disk file is:
//
//	[ 4 bytes  ] magic "QSC1" (QuantumShield CA v1)
//	[ 32 bytes ] Argon2id salt
//	[ 12 bytes ] AES-256-GCM nonce
//	[ N bytes  ] AES-256-GCM ciphertext + 16-byte tag
//
// The plaintext is a JSON-encoded Store value.  AES-256-GCM authenticates
// every byte of ciphertext and the nonce; any tampering is detected.
//
// # Key derivation
//
// masterKey = Argon2id(password, salt, time=3, mem=64 MiB, threads=4, keyLen=32)
//
// # Usage
//
//	store := castore.New()
//	store.SetRoot(rootCA)
//	store.SetIntermediate(serial, subCA)
//	if err := store.Save(path, password); err != nil { ... }
//
//	store, err := castore.Load(path, password)
//	rootCA := store.Root()
//	subCA  := store.Intermediate(serial)
package castore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/crypto/argon2"

	"github.com/quantum-shield/quantum-shield-go/internal/ca"
)

// ── Constants ─────────────────────────────────────────────────────────────────

var magic = [4]byte{'Q', 'S', 'C', '1'}

const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 32
	nonceLen     = 12
)

// ── Wire types ────────────────────────────────────────────────────────────────

// persistedStore is the JSON payload stored inside the encrypted file.
type persistedStore struct {
	Version       int                       `json:"version"`
	Root          *ca.Snapshot              `json:"root,omitempty"`
	Intermediates map[string]*ca.Snapshot   `json:"intermediates"` // serial → snapshot
}

// ── Store ─────────────────────────────────────────────────────────────────────

// Store is an in-memory CA hierarchy that can be saved to / loaded from an
// encrypted file.  Safe for concurrent use.
type Store struct {
	mu            sync.RWMutex
	root          *ca.CA
	intermediates map[string]*ca.CA // serial → sub-CA
}

// New returns an empty Store.
func New() *Store {
	return &Store{intermediates: make(map[string]*ca.CA)}
}

// SetRoot replaces (or sets) the root CA.
func (s *Store) SetRoot(c *ca.CA) {
	s.mu.Lock()
	s.root = c
	s.mu.Unlock()
}

// Root returns the root CA, or nil if not set.
func (s *Store) Root() *ca.CA {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.root
}

// SetIntermediate registers (or replaces) an intermediate CA keyed by its
// certificate serial number.
func (s *Store) SetIntermediate(serial string, c *ca.CA) {
	s.mu.Lock()
	s.intermediates[serial] = c
	s.mu.Unlock()
}

// Intermediate returns the intermediate CA for the given serial, or nil.
func (s *Store) Intermediate(serial string) *ca.CA {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.intermediates[serial]
}

// Intermediates returns a copy of the intermediate CA map.
func (s *Store) Intermediates() map[string]*ca.CA {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]*ca.CA, len(s.intermediates))
	for k, v := range s.intermediates {
		out[k] = v
	}
	return out
}

// ── Save ──────────────────────────────────────────────────────────────────────

// Save encrypts the full CA hierarchy and writes it to path.
// If path already exists it is atomically replaced (write to a temp file,
// then rename) so a crash during Save never corrupts the existing file.
func (s *Store) Save(path, password string) error {
	if password == "" {
		return errors.New("castore.Save: password must not be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	ps := &persistedStore{
		Version:       1,
		Intermediates: make(map[string]*ca.Snapshot, len(s.intermediates)),
	}

	if s.root != nil {
		snap, err := s.root.Export()
		if err != nil {
			return fmt.Errorf("castore.Save: export root: %w", err)
		}
		ps.Root = &snap
	}
	for serial, sub := range s.intermediates {
		snap, err := sub.Export()
		if err != nil {
			return fmt.Errorf("castore.Save: export intermediate %s: %w", serial, err)
		}
		snapCopy := snap
		ps.Intermediates[serial] = &snapCopy
	}

	plaintext, err := json.Marshal(ps)
	if err != nil {
		return fmt.Errorf("castore.Save: marshal: %w", err)
	}

	ciphertext, err := encrypt(plaintext, password)
	if err != nil {
		return fmt.Errorf("castore.Save: encrypt: %w", err)
	}

	return atomicWrite(path, ciphertext)
}

// ── Load ──────────────────────────────────────────────────────────────────────

// Load decrypts and parses an encrypted CA store file.
// Returns a ready-to-use Store and a nil error on success.
// Returns a descriptive error if the file is absent, corrupted, or the
// password is wrong.
func Load(path, password string) (*Store, error) {
	if password == "" {
		return nil, errors.New("castore.Load: password must not be empty")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("castore.Load: read file: %w", err)
	}

	plaintext, err := decrypt(raw, password)
	if err != nil {
		return nil, fmt.Errorf("castore.Load: decrypt: %w", err)
	}

	var ps persistedStore
	if err := json.Unmarshal(plaintext, &ps); err != nil {
		return nil, fmt.Errorf("castore.Load: unmarshal: %w", err)
	}

	store := New()
	if ps.Root != nil {
		root, err := ca.Restore(*ps.Root)
		if err != nil {
			return nil, fmt.Errorf("castore.Load: restore root CA: %w", err)
		}
		store.root = root
	}
	for serial, snap := range ps.Intermediates {
		sub, err := ca.Restore(*snap)
		if err != nil {
			return nil, fmt.Errorf("castore.Load: restore intermediate %s: %w", serial, err)
		}
		store.intermediates[serial] = sub
	}
	return store, nil
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

// encrypt produces: magic(4) | salt(32) | nonce(12) | AES-GCM-ciphertext
func encrypt(plaintext []byte, password string) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	key := deriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	// Assemble: magic | salt | nonce | ciphertext
	out := make([]byte, 4+saltLen+nonceLen+len(ct))
	copy(out[0:4], magic[:])
	copy(out[4:4+saltLen], salt)
	copy(out[4+saltLen:4+saltLen+nonceLen], nonce)
	copy(out[4+saltLen+nonceLen:], ct)
	return out, nil
}

// decrypt validates magic, derives the key, and decrypts.
func decrypt(data []byte, password string) ([]byte, error) {
	const minLen = 4 + saltLen + nonceLen + 16 // at least GCM tag
	if len(data) < minLen {
		return nil, errors.New("file too short")
	}
	var m [4]byte
	copy(m[:], data[0:4])
	if m != magic {
		return nil, errors.New("invalid magic — not a QuantumShield CA store file")
	}
	salt  := data[4 : 4+saltLen]
	nonce := data[4+saltLen : 4+saltLen+nonceLen]
	ct    := data[4+saltLen+nonceLen:]

	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		// Don't leak whether it was bad password or corrupt data.
		return nil, errors.New("decryption failed — wrong password or corrupted file")
	}
	return pt, nil
}

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

// ── Atomic write ──────────────────────────────────────────────────────────────

// atomicWrite writes data to a temp file beside path, then renames it.
// On POSIX this is atomic; on Windows it is best-effort.
func atomicWrite(path string, data []byte) error {
	// Use binary.AppendUvarint as a compile-time import check; value unused.
	_ = binary.AppendUvarint

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp) //nolint:errcheck
		return fmt.Errorf("rename temp → final: %w", err)
	}
	return nil
}
