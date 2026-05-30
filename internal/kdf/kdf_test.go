package kdf_test

import (
	"bytes"
	"testing"

	"github.com/quantum-shield/quantum-shield-go/internal/kdf"
)

// ── HKDF ─────────────────────────────────────────────────────────────────────

func TestDeriveHKDF_Deterministic(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, 32)
	salt := bytes.Repeat([]byte{0x01}, 32)
	info := []byte("test-context-v1")

	k1, err := kdf.DeriveHKDF(secret, salt, info, 32)
	if err != nil {
		t.Fatalf("DeriveHKDF: %v", err)
	}
	k2, err := kdf.DeriveHKDF(secret, salt, info, 32)
	if err != nil {
		t.Fatalf("DeriveHKDF: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("same inputs must produce same key")
	}
}

func TestDeriveHKDF_DifferentInfoProducesDifferentKey(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, 32)
	salt := bytes.Repeat([]byte{0x01}, 32)

	k1, _ := kdf.DeriveHKDF(secret, salt, []byte("send-key"), 32)
	k2, _ := kdf.DeriveHKDF(secret, salt, []byte("recv-key"), 32)

	if bytes.Equal(k1, k2) {
		t.Error("different info must produce different keys")
	}
}

func TestDeriveHKDF_DifferentSecretProducesDifferentKey(t *testing.T) {
	salt := bytes.Repeat([]byte{0x01}, 32)
	info := []byte("ctx")

	k1, _ := kdf.DeriveHKDF(bytes.Repeat([]byte{0xAA}, 32), salt, info, 32)
	k2, _ := kdf.DeriveHKDF(bytes.Repeat([]byte{0xBB}, 32), salt, info, 32)

	if bytes.Equal(k1, k2) {
		t.Error("different secret must produce different keys")
	}
}

func TestDeriveHKDF_OutputLength(t *testing.T) {
	secret := bytes.Repeat([]byte{0x55}, 32)
	for _, l := range []int{16, 32, 48, 64} {
		k, err := kdf.DeriveHKDF(secret, nil, []byte("ctx"), l)
		if err != nil {
			t.Fatalf("length %d: %v", l, err)
		}
		if len(k) != l {
			t.Errorf("length %d: got %d bytes", l, len(k))
		}
	}
}

func TestDeriveHKDF_InvalidLen(t *testing.T) {
	_, err := kdf.DeriveHKDF([]byte("secret"), nil, nil, 0)
	if err == nil {
		t.Error("expected error for keyLen=0")
	}
	_, err = kdf.DeriveHKDF([]byte("secret"), nil, nil, -1)
	if err == nil {
		t.Error("expected error for keyLen=-1")
	}
}

func TestDeriveHKDF_NilSaltOK(t *testing.T) {
	_, err := kdf.DeriveHKDF([]byte("secret"), nil, []byte("ctx"), 32)
	if err != nil {
		t.Errorf("nil salt should be OK: %v", err)
	}
}

func TestDeriveHKDFMulti_LengthMismatch(t *testing.T) {
	_, err := kdf.DeriveHKDFMulti([]byte("s"), nil,
		[][]byte{[]byte("a"), []byte("b")}, []int{32})
	if err == nil {
		t.Error("expected error for mismatched lengths")
	}
}

func TestDeriveHKDFMulti_IndependentKeys(t *testing.T) {
	secret := bytes.Repeat([]byte{0xCC}, 32)
	infos := [][]byte{[]byte("send"), []byte("recv"), []byte("auth")}
	lens := []int{32, 32, 32}

	keys, err := kdf.DeriveHKDFMulti(secret, nil, infos, lens)
	if err != nil {
		t.Fatalf("DeriveHKDFMulti: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}
	// All three must be distinct
	if bytes.Equal(keys[0], keys[1]) || bytes.Equal(keys[1], keys[2]) || bytes.Equal(keys[0], keys[2]) {
		t.Error("multi-derived keys must all be distinct")
	}
}

// ── Argon2id ──────────────────────────────────────────────────────────────────

func TestDeriveArgon2id_Deterministic(t *testing.T) {
	pass := []byte("correct-horse-battery-staple")
	salt := bytes.Repeat([]byte{0x99}, 32)

	k1, err := kdf.DeriveArgon2id(pass, salt)
	if err != nil {
		t.Fatalf("DeriveArgon2id: %v", err)
	}
	k2, _ := kdf.DeriveArgon2id(pass, salt)
	if !bytes.Equal(k1, k2) {
		t.Error("same password+salt must produce same key")
	}
}

func TestDeriveArgon2id_DifferentSalt(t *testing.T) {
	pass := []byte("same-password")
	s1 := bytes.Repeat([]byte{0x11}, 32)
	s2 := bytes.Repeat([]byte{0x22}, 32)

	k1, _ := kdf.DeriveArgon2id(pass, s1)
	k2, _ := kdf.DeriveArgon2id(pass, s2)
	if bytes.Equal(k1, k2) {
		t.Error("different salts must produce different keys")
	}
}

func TestDeriveArgon2id_EmptyPassword(t *testing.T) {
	salt := bytes.Repeat([]byte{0x01}, 32)
	_, err := kdf.DeriveArgon2id([]byte{}, salt)
	if err == nil {
		t.Error("expected error for empty password")
	}
}

func TestDeriveArgon2id_ShortSalt(t *testing.T) {
	_, err := kdf.DeriveArgon2id([]byte("pass"), []byte("short"))
	if err == nil {
		t.Error("expected error for salt shorter than 16 bytes")
	}
}

func TestDeriveArgon2id_OutputIs32Bytes(t *testing.T) {
	salt, _ := kdf.NewSalt()
	k, err := kdf.DeriveArgon2id([]byte("password"), salt)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(k) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(k))
	}
}

// ── Utilities ─────────────────────────────────────────────────────────────────

func TestNewSalt_Length(t *testing.T) {
	s, err := kdf.NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	if len(s) != kdf.SaltLen {
		t.Errorf("expected %d bytes, got %d", kdf.SaltLen, len(s))
	}
}

func TestNewSalt_Unique(t *testing.T) {
	s1, _ := kdf.NewSalt()
	s2, _ := kdf.NewSalt()
	if bytes.Equal(s1, s2) {
		t.Error("two salts must be distinct")
	}
}

func TestDomainSalt_Deterministic(t *testing.T) {
	s1 := kdf.DomainSalt("myapp-v1")
	s2 := kdf.DomainSalt("myapp-v1")
	if !bytes.Equal(s1, s2) {
		t.Error("same label must produce same salt")
	}
}

func TestDomainSalt_DifferentLabel(t *testing.T) {
	s1 := kdf.DomainSalt("app-v1")
	s2 := kdf.DomainSalt("app-v2")
	if bytes.Equal(s1, s2) {
		t.Error("different labels must produce different salts")
	}
}

// ── Benchmark ─────────────────────────────────────────────────────────────────

func BenchmarkDeriveHKDF(b *testing.B) {
	secret := bytes.Repeat([]byte{0xAB}, 32)
	salt := bytes.Repeat([]byte{0x01}, 32)
	info := []byte("bench-ctx")
	b.ResetTimer()
	for b.Loop() {
		kdf.DeriveHKDF(secret, salt, info, 32)
	}
}

func BenchmarkDeriveArgon2id(b *testing.B) {
	pass := []byte("bench-password-123")
	salt := bytes.Repeat([]byte{0x55}, 32)
	b.ResetTimer()
	for b.Loop() {
		kdf.DeriveArgon2id(pass, salt)
	}
}
