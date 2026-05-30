package keystore_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quantum-shield/quantum-shield-go/internal/kem"
	"github.com/quantum-shield/quantum-shield-go/internal/keystore"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func tempStore(t *testing.T) *keystore.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keystore.json")
	s, err := keystore.Open(path, "test-master-password-2025")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func genKEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	dk, err := kem.GenerateKey(kem.Level768)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return dk.EncapsulationKey().Bytes(), dk.Bytes()
}

// ── Open / Create ─────────────────────────────────────────────────────────────

func TestOpen_CreatesNewFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.json")
	s, err := keystore.Open(path, "password")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if s == nil {
		t.Fatal("store must not be nil")
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("file must be created")
	}
}

func TestOpen_LoadsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	ek, dk := genKEM(t)

	s1, _ := keystore.Open(path, "password")
	s1.Put("my-key", kem.Level768, ek, dk, 0)

	// Reopen
	s2, err := keystore.Open(path, "password")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	kv, err := s2.GetActive("my-key")
	if err != nil {
		t.Fatalf("GetActive after reopen: %v", err)
	}
	if len(kv.DKBytes) == 0 {
		t.Error("dk must not be empty after reload")
	}
}

func TestOpen_EmptyPassword(t *testing.T) {
	_, err := keystore.Open(filepath.Join(t.TempDir(), "s.json"), "")
	if err == nil {
		t.Error("empty password must be rejected")
	}
}

// ── Put / GetActive ───────────────────────────────────────────────────────────

func TestPut_GetActive(t *testing.T) {
	s := tempStore(t)
	ek, dk := genKEM(t)
	if err := s.Put("k1", kem.Level768, ek, dk, 0); err != nil {
		t.Fatalf("Put: %v", err)
	}
	kv, err := s.GetActive("k1")
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if string(kv.EKBytes) != string(ek) {
		t.Error("ek mismatch")
	}
	if string(kv.DKBytes) != string(dk) {
		t.Error("dk mismatch — decryption failed")
	}
	if !kv.Active {
		t.Error("version must be active")
	}
}

func TestPut_NotFound(t *testing.T) {
	s := tempStore(t)
	_, err := s.GetActive("nonexistent")
	if err == nil {
		t.Error("expected error for missing key")
	}
}

func TestPut_EmptyKeyID(t *testing.T) {
	s := tempStore(t)
	_, dk := genKEM(t)
	err := s.Put("", kem.Level768, []byte{1}, dk, 0)
	if err == nil {
		t.Error("empty keyID must be rejected")
	}
}

func TestPut_EmptyKeyMaterial(t *testing.T) {
	s := tempStore(t)
	err := s.Put("k", kem.Level768, []byte{}, []byte{}, 0)
	if err == nil {
		t.Error("empty key material must be rejected")
	}
}

// ── Version management ────────────────────────────────────────────────────────

func TestVersionCount_AfterMultiplePuts(t *testing.T) {
	s := tempStore(t)
	for range 3 {
		ek, dk := genKEM(t)
		s.Put("k", kem.Level768, ek, dk, 0)
	}
	if c := s.VersionCount("k"); c != 3 {
		t.Errorf("expected 3 versions, got %d", c)
	}
}

func TestGetVersion_PreviousVersionAccessible(t *testing.T) {
	s := tempStore(t)
	ek1, dk1 := genKEM(t)
	s.Put("k", kem.Level768, ek1, dk1, 0)

	ek2, dk2 := genKEM(t)
	s.Put("k", kem.Level768, ek2, dk2, 0)

	// Version 1 must still be accessible for decryption
	v1, err := s.GetVersion("k", 1)
	if err != nil {
		t.Fatalf("GetVersion(1): %v", err)
	}
	if string(v1.DKBytes) != string(dk1) {
		t.Error("version 1 dk mismatch")
	}
	if v1.Active {
		t.Error("version 1 must not be active after rotation")
	}

	// Version 2 must be the active one
	v2, err := s.GetActive("k")
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if string(v2.DKBytes) != string(dk2) {
		t.Error("version 2 dk mismatch")
	}
}

func TestGetVersion_NotFound(t *testing.T) {
	s := tempStore(t)
	ek, dk := genKEM(t)
	s.Put("k", kem.Level768, ek, dk, 0)
	_, err := s.GetVersion("k", 99)
	if err == nil {
		t.Error("expected error for non-existent version")
	}
}

// ── Rotation ──────────────────────────────────────────────────────────────────

func TestRotate(t *testing.T) {
	s := tempStore(t)
	ek1, dk1 := genKEM(t)
	s.Put("k", kem.Level768, ek1, dk1, 0)

	newEK, err := s.Rotate("k")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if len(newEK) == 0 {
		t.Error("Rotate must return new ek bytes")
	}
	if string(newEK) == string(ek1) {
		t.Error("rotated key must differ from original")
	}
	if s.VersionCount("k") != 2 {
		t.Errorf("expected 2 versions after rotation, got %d", s.VersionCount("k"))
	}
}

func TestRotate_NotFound(t *testing.T) {
	s := tempStore(t)
	_, err := s.Rotate("nonexistent")
	if err == nil {
		t.Error("Rotate nonexistent key must fail")
	}
}

// ── Expiry ────────────────────────────────────────────────────────────────────

func TestExpire(t *testing.T) {
	s := tempStore(t)
	ek, dk := genKEM(t)
	s.Put("k", kem.Level768, ek, dk, 0)
	s.Expire("k")
	_, err := s.GetActive("k")
	if err == nil {
		t.Error("expired key must not be returned as active")
	}
}

func TestGetActive_ExpiredTTL(t *testing.T) {
	s := tempStore(t)
	ek, dk := genKEM(t)
	s.Put("k", kem.Level768, ek, dk, 1*time.Millisecond) // expires immediately
	time.Sleep(5 * time.Millisecond)
	_, err := s.GetActive("k")
	if err == nil {
		t.Error("TTL-expired key must not be returned as active")
	}
}

// ── Delete / List ─────────────────────────────────────────────────────────────

func TestDelete(t *testing.T) {
	s := tempStore(t)
	ek, dk := genKEM(t)
	s.Put("k", kem.Level768, ek, dk, 0)
	s.Delete("k")
	if ids := s.List(); len(ids) != 0 {
		t.Errorf("expected empty list after delete, got %v", ids)
	}
}

func TestList(t *testing.T) {
	s := tempStore(t)
	for _, id := range []string{"alpha", "beta", "gamma"} {
		ek, dk := genKEM(t)
		s.Put(id, kem.Level768, ek, dk, 0)
	}
	ids := s.List()
	if len(ids) != 3 {
		t.Errorf("expected 3 keys, got %d", len(ids))
	}
}
