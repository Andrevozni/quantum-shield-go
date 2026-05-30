// Package keystore implements an encrypted, persistent key store for QuantumShield.
//
// Keys are stored in a JSON file on disk, but all sensitive fields (dk bytes)
// are encrypted with AES-256-GCM using a master key derived via Argon2id from
// a password/passphrase. Encapsulation keys (ek bytes) are stored in plaintext
// since they are public.
//
// # Key lifecycle
//
//	Store → active key, used for all new operations
//	Rotate → generates a new version; old version kept for decryption
//	Expire → marks a key version as expired; no new operations allowed
//	Delete → removes all versions from store (irreversible)
//
// # File format
//
//	{
//	  "version": 1,
//	  "entries": {
//	    "<keyID>": {
//	      "versions": [
//	        { "version": 1, "ek": "base64", "dk_enc": "base64",
//	          "nonce": "base64", "created_at": "RFC3339",
//	          "expires_at": "RFC3339", "active": true }
//	      ]
//	    }
//	  }
//	}
package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/quantum-shield/quantum-shield-go/internal/kdf"
	"github.com/quantum-shield/quantum-shield-go/internal/kem"
)

const (
	fileVersion    = 1
	defaultTTL     = 90 * 24 * time.Hour // 90 days
	masterKeySalt  = "qs-keystore-master-key-v1"
)

// ── Wire types (JSON on disk) ─────────────────────────────────────────────────

type diskFile struct {
	Version int                    `json:"version"`
	Entries map[string]*diskEntry  `json:"entries"`
}

type diskEntry struct {
	Versions []*diskVersion `json:"versions"`
}

type diskVersion struct {
	Version   int    `json:"version"`
	Level     int    `json:"level"` // 768 or 1024
	EKBytes   string `json:"ek"`    // base64, public
	DKEnc     string `json:"dk_enc"` // base64, AES-256-GCM encrypted dk
	Nonce     string `json:"nonce"`  // base64, GCM nonce for DKEnc

	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Active     bool      `json:"active"`
}

// ── Public types ──────────────────────────────────────────────────────────────

// KeyVersion is a decrypted key version returned to callers.
type KeyVersion struct {
	Version   int
	Level     kem.Level
	EKBytes   []byte
	DKBytes   []byte
	CreatedAt time.Time
	ExpiresAt time.Time
	Active    bool
}

// MasterKeyProvider supplies the 32-byte AES-256 key used to encrypt and
// decrypt private key material.  The hsm.EnvProvider and hsm.PKCS11Provider
// types satisfy this interface.
type MasterKeyProvider interface {
	MasterKey() ([]byte, error)
	Close() error
}

// Store is a thread-safe encrypted key store.
type Store struct {
	path      string
	masterKey []byte // 32-byte AES-256 key
	gcm       cipher.AEAD
	mu        sync.RWMutex
	data      *diskFile
}

// Close zeroes the in-memory master key and AES-GCM cipher, preventing future
// use of the store.  Safe to call multiple times.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.masterKey {
		s.masterKey[i] = 0
	}
	s.masterKey = nil
	s.gcm = nil
	return nil
}

// ── Open / Create ─────────────────────────────────────────────────────────────

// Open opens an existing key store or creates a new one at path.
// password is used to derive the master encryption key via Argon2id.
// If the file does not exist, it is created with an empty store.
func Open(path, password string) (*Store, error) {
	if password == "" {
		return nil, errors.New("keystore: password must not be empty")
	}

	// Derive master key: fixed domain salt (not random — so we can re-derive on open)
	masterKey, err := kdf.DeriveArgon2id([]byte(password), kdf.DomainSalt(masterKeySalt))
	if err != nil {
		return nil, fmt.Errorf("keystore: derive master key: %w", err)
	}

	return openWithKey(path, masterKey)
}

// OpenWithProvider opens or creates a keystore at path using the given
// MasterKeyProvider to obtain the AES-256 encryption key.
//
// This function is the preferred entry-point when an HSM or cloud KMS backend
// supplies the master key.  The provider's MasterKey method is called once
// during Open; the 32-byte key is stored in memory for the lifetime of the
// Store.  Call provider.Close() independently when the Store is no longer
// needed.
//
// Returns an error if provider.MasterKey returns an error, if the key is not
// exactly 32 bytes, or if the underlying file cannot be opened or created.
func OpenWithProvider(path string, provider MasterKeyProvider) (*Store, error) {
	if provider == nil {
		return nil, errors.New("keystore: provider must not be nil")
	}
	masterKey, err := provider.MasterKey()
	if err != nil {
		return nil, fmt.Errorf("keystore: get master key from provider: %w", err)
	}
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("keystore: provider returned %d-byte key, want 32", len(masterKey))
	}
	return openWithKey(path, masterKey)
}

// openWithKey is the shared implementation for Open and OpenWithProvider.
func openWithKey(path string, masterKey []byte) (*Store, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, masterKey: masterKey, gcm: gcm}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		s.data = &diskFile{Version: fileVersion, Entries: make(map[string]*diskEntry)}
		if err := s.flush(); err != nil {
			return nil, err
		}
	} else {
		if err := s.load(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// ── Store / Load ──────────────────────────────────────────────────────────────

// Put stores a new key under keyID. If keyID already exists a new version is added.
// ttl controls how long this version is valid; 0 uses the default (90 days).
func (s *Store) Put(keyID string, level kem.Level, ekBytes, dkBytes []byte, ttl time.Duration) error {
	if keyID == "" {
		return errors.New("keystore: keyID must not be empty")
	}
	if len(ekBytes) == 0 || len(dkBytes) == 0 {
		return errors.New("keystore: key material must not be empty")
	}
	if ttl <= 0 {
		ttl = defaultTTL
	}

	dkEnc, nonce, err := s.encrypt(dkBytes)
	if err != nil {
		return fmt.Errorf("keystore: encrypt dk: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.data.Entries[keyID]
	if !ok {
		entry = &diskEntry{}
		s.data.Entries[keyID] = entry
	}

	// Deactivate previous versions
	for _, v := range entry.Versions {
		v.Active = false
	}

	ver := len(entry.Versions) + 1
	now := time.Now().UTC()
	entry.Versions = append(entry.Versions, &diskVersion{
		Version:   ver,
		Level:     int(level),
		EKBytes:   base64.StdEncoding.EncodeToString(ekBytes),
		DKEnc:     base64.StdEncoding.EncodeToString(dkEnc),
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		Active:    true,
	})
	return s.flush()
}

// GetActive returns the active (most recent, non-expired) version of keyID.
func (s *Store) GetActive(keyID string) (*KeyVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.data.Entries[keyID]
	if !ok {
		return nil, fmt.Errorf("keystore: key %q not found", keyID)
	}
	for i := len(entry.Versions) - 1; i >= 0; i-- {
		v := entry.Versions[i]
		if v.Active && time.Now().Before(v.ExpiresAt) {
			return s.decode(keyID, v)
		}
	}
	return nil, fmt.Errorf("keystore: no active non-expired version for key %q", keyID)
}

// GetVersion returns a specific version of a key (for decryption with old keys).
func (s *Store) GetVersion(keyID string, version int) (*KeyVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.data.Entries[keyID]
	if !ok {
		return nil, fmt.Errorf("keystore: key %q not found", keyID)
	}
	for _, v := range entry.Versions {
		if v.Version == version {
			return s.decode(keyID, v)
		}
	}
	return nil, fmt.Errorf("keystore: version %d of key %q not found", version, keyID)
}

// ── Rotation ──────────────────────────────────────────────────────────────────

// Rotate generates a new ML-KEM keypair for keyID and adds it as the new active version.
// The old version remains in the store for decryption.
// Returns the new encapsulation key bytes.
func (s *Store) Rotate(keyID string) ([]byte, error) {
	s.mu.RLock()
	entry, ok := s.data.Entries[keyID]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("keystore: key %q not found", keyID)
	}

	// Determine level from latest version
	var level kem.Level = kem.Level768
	if len(entry.Versions) > 0 {
		level = kem.Level(entry.Versions[len(entry.Versions)-1].Level)
	}

	dk, err := kem.GenerateKey(level)
	if err != nil {
		return nil, fmt.Errorf("keystore: rotate keygen: %w", err)
	}
	ekBytes := dk.EncapsulationKey().Bytes()
	dkBytes := dk.Bytes()

	if err := s.Put(keyID, level, ekBytes, dkBytes, defaultTTL); err != nil {
		return nil, err
	}
	return ekBytes, nil
}

// ── Expiry ────────────────────────────────────────────────────────────────────

// Expire deactivates the active version of keyID without deleting it.
func (s *Store) Expire(keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.data.Entries[keyID]
	if !ok {
		return fmt.Errorf("keystore: key %q not found", keyID)
	}
	for _, v := range entry.Versions {
		v.Active = false
	}
	return s.flush()
}

// Delete removes all versions of keyID permanently.
func (s *Store) Delete(keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data.Entries[keyID]; !ok {
		return fmt.Errorf("keystore: key %q not found", keyID)
	}
	delete(s.data.Entries, keyID)
	return s.flush()
}

// List returns all stored key IDs.
func (s *Store) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.data.Entries))
	for id := range s.data.Entries {
		ids = append(ids, id)
	}
	return ids
}

// VersionCount returns the number of stored versions for keyID.
func (s *Store) VersionCount(keyID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if entry, ok := s.data.Entries[keyID]; ok {
		return len(entry.Versions)
	}
	return 0
}

// ── Internal ──────────────────────────────────────────────────────────────────

func (s *Store) decode(keyID string, v *diskVersion) (*KeyVersion, error) {
	ekBytes, err := base64.StdEncoding.DecodeString(v.EKBytes)
	if err != nil {
		return nil, fmt.Errorf("keystore: decode ek for %q: %w", keyID, err)
	}
	dkEnc, err := base64.StdEncoding.DecodeString(v.DKEnc)
	if err != nil {
		return nil, fmt.Errorf("keystore: decode dk_enc for %q: %w", keyID, err)
	}
	nonce, err := base64.StdEncoding.DecodeString(v.Nonce)
	if err != nil {
		return nil, fmt.Errorf("keystore: decode nonce for %q: %w", keyID, err)
	}
	dkBytes, err := s.decrypt(dkEnc, nonce)
	if err != nil {
		return nil, fmt.Errorf("keystore: decrypt dk for %q: %w", keyID, err)
	}
	return &KeyVersion{
		Version:   v.Version,
		Level:     kem.Level(v.Level),
		EKBytes:   ekBytes,
		DKBytes:   dkBytes,
		CreatedAt: v.CreatedAt,
		ExpiresAt: v.ExpiresAt,
		Active:    v.Active,
	}, nil
}

func (s *Store) encrypt(plain []byte) (ciphertext, nonce []byte, err error) {
	nonce = make([]byte, s.gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ct := s.gcm.Seal(nil, nonce, plain, nil)
	return ct, nonce, nil
}

func (s *Store) decrypt(ct, nonce []byte) ([]byte, error) {
	return s.gcm.Open(nil, nonce, ct, nil)
}

func (s *Store) flush() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	// Write to temp file first, then rename (atomic on most OS)
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var data diskFile
	if err := json.Unmarshal(b, &data); err != nil {
		return fmt.Errorf("keystore: parse file: %w", err)
	}
	if data.Entries == nil {
		data.Entries = make(map[string]*diskEntry)
	}
	s.data = &data
	return nil
}
