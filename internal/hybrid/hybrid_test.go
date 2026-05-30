package hybrid_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/quantum-shield/quantum-shield-go/internal/hybrid"
	"github.com/quantum-shield/quantum-shield-go/internal/kem"
)

func setup(t *testing.T, level kem.Level) (ekBytes, dkBytes []byte, enc *hybrid.Encrypter, dec *hybrid.Decrypter) {
	t.Helper()
	dk, err := kem.GenerateKey(level)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return dk.EncapsulationKey().Bytes(), dk.Bytes(), hybrid.NewEncrypter(level), hybrid.NewDecrypter(level)
}

func TestRoundtrip(t *testing.T) {
	msg := []byte("Transfer EUR 1,000,000 — confidential")
	ekBytes, dkBytes, enc, dec := setup(t, kem.Level768)

	encrypted, err := enc.Encrypt(ekBytes, msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	plaintext, err := dec.Decrypt(dkBytes, encrypted)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(msg, plaintext) {
		t.Fatalf("plaintext mismatch: got %q", plaintext)
	}
}

func TestAllLevels(t *testing.T) {
	for _, level := range []kem.Level{kem.Level768, kem.Level1024} {
		t.Run(string(rune('0'+int(level/512))), func(t *testing.T) {
			ekBytes, dkBytes, enc, dec := setup(t, level)
			encrypted, err := enc.Encrypt(ekBytes, []byte("secret"))
			if err != nil {
				t.Fatal(err)
			}
			plain, err := dec.Decrypt(dkBytes, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plain, []byte("secret")) {
				t.Fatal("mismatch")
			}
		})
	}
}

func TestReplayRejected(t *testing.T) {
	ekBytes, dkBytes, enc, dec := setup(t, kem.Level768)
	encrypted, _ := enc.Encrypt(ekBytes, []byte("payload"))

	if _, err := dec.Decrypt(dkBytes, encrypted); err != nil {
		t.Fatalf("first decrypt failed: %v", err)
	}
	if _, err := dec.Decrypt(dkBytes, encrypted); err == nil {
		t.Fatal("replay should have been rejected")
	}
}

func TestWrongKey(t *testing.T) {
	ekBytes, _, enc, _ := setup(t, kem.Level768)
	_, dkBytes2, _, dec2 := setup(t, kem.Level768)

	encrypted, _ := enc.Encrypt(ekBytes, []byte("secret"))
	if _, err := dec2.Decrypt(dkBytes2, encrypted); err == nil {
		t.Fatal("wrong key should fail")
	}
}

func TestTamperedCiphertext(t *testing.T) {
	ekBytes, dkBytes, enc, dec := setup(t, kem.Level768)
	encrypted, _ := enc.Encrypt(ekBytes, []byte("secret"))

	// Flip a byte in the data
	encrypted.Data[0] ^= 0xFF
	if _, err := dec.Decrypt(dkBytes, encrypted); err == nil {
		t.Fatal("tampered ciphertext should fail authentication")
	}
}

func TestNilEncrypted(t *testing.T) {
	_, dkBytes, _, dec := setup(t, kem.Level768)
	if _, err := dec.Decrypt(dkBytes, nil); err == nil {
		t.Fatal("nil input should fail")
	}
}

func TestLargeMessage(t *testing.T) {
	msg := bytes.Repeat([]byte("A"), 100*1024) // 100 KB
	ekBytes, dkBytes, enc, dec := setup(t, kem.Level768)
	encrypted, err := enc.Encrypt(ekBytes, msg)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := dec.Decrypt(dkBytes, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, plain) {
		t.Fatal("large message mismatch")
	}
}

// ── Cross-restart replay protection tests ────────────────────────────────────

// TestTimestampBoundToAEAD verifies that modifying CreatedAt after encryption
// causes AES-GCM authentication failure.  This proves an attacker cannot change
// the timestamp (to bypass the freshness check) without breaking the ciphertext.
func TestTimestampBoundToAEAD(t *testing.T) {
	ekBytes, dkBytes, enc, dec := setup(t, kem.Level768)
	encrypted, err := enc.Encrypt(ekBytes, []byte("secret payload"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Tamper with the timestamp — GCM additional data changes → authentication fails.
	encrypted.CreatedAt += 999
	if _, err := dec.Decrypt(dkBytes, encrypted); err == nil {
		t.Fatal("modified CreatedAt must cause AEAD authentication failure")
	}
}

// TestCrossRestartReplayProtected verifies that a fresh Decrypter (simulating a
// server restart with an empty in-process cache) still accepts an authentic fresh
// ciphertext on the first attempt, but rejects it on the second (in-process cache).
func TestCrossRestartReplayProtected(t *testing.T) {
	ekBytes, dkBytes, enc, _ := setup(t, kem.Level768)
	encrypted, err := enc.Encrypt(ekBytes, []byte("payload"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Simulate server restart: new Decrypter, empty cache, same ciphertext.
	freshDec := hybrid.NewDecrypter(kem.Level768)
	if _, err := freshDec.Decrypt(dkBytes, encrypted); err != nil {
		t.Fatalf("first decrypt on fresh decrypter must succeed: %v", err)
	}
	// Same ciphertext a second time — in-process cache must reject it.
	if _, err := freshDec.Decrypt(dkBytes, encrypted); err == nil {
		t.Fatal("replay on fresh decrypter must be rejected by in-process cache")
	}
}

// TestStaleCreatedAtRejected verifies that a ciphertext whose age exceeds maxAge
// is rejected even though it is cryptographically valid. This is the core
// cross-restart replay protection: after a restart the freshness window keeps old
// ciphertexts from being accepted regardless of the empty in-process cache.
//
// Uses WithNowFunc to simulate 10 minutes passing without real sleeps.
func TestStaleCreatedAtRejected(t *testing.T) {
	ekBytes, dkBytes, enc, _ := setup(t, kem.Level768)
	encrypted, err := enc.Encrypt(ekBytes, []byte("stale payload"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Simulate 10 minutes passing; maxAge is 5 minutes → must reject.
	future := time.Now().Add(10 * time.Minute)
	staleDec := hybrid.NewDecrypterWithMaxAge(kem.Level768, 5*time.Minute).
		WithNowFunc(func() time.Time { return future })

	if _, err := staleDec.Decrypt(dkBytes, encrypted); err == nil {
		t.Fatal("expired ciphertext must be rejected by freshness check")
	}
}

// TestFreshCiphertextWithinWindow verifies that a just-created ciphertext is
// accepted when the decrypter's clock is only slightly ahead (within maxAge).
func TestFreshCiphertextWithinWindow(t *testing.T) {
	ekBytes, dkBytes, enc, _ := setup(t, kem.Level768)
	encrypted, err := enc.Encrypt(ekBytes, []byte("fresh payload"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Simulate 2 minutes passing; maxAge is 5 minutes → must accept.
	nearFuture := time.Now().Add(2 * time.Minute)
	freshDec := hybrid.NewDecrypterWithMaxAge(kem.Level768, 5*time.Minute).
		WithNowFunc(func() time.Time { return nearFuture })

	if _, err := freshDec.Decrypt(dkBytes, encrypted); err != nil {
		t.Fatalf("ciphertext within maxAge window must be accepted: %v", err)
	}
}

func BenchmarkEncrypt768(b *testing.B) {
	dk, _ := kem.GenerateKey(kem.Level768)
	enc := hybrid.NewEncrypter(kem.Level768)
	ekBytes := dk.EncapsulationKey().Bytes()
	msg := []byte("benchmark payload — 32 bytes exactly!!")
	b.ResetTimer()
	for b.Loop() {
		enc.Encrypt(ekBytes, msg)
	}
}

func BenchmarkDecrypt768(b *testing.B) {
	dk, _ := kem.GenerateKey(kem.Level768)
	ek := dk.EncapsulationKey()
	enc := hybrid.NewEncrypter(kem.Level768)
	msg := []byte("benchmark payload")

	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		encrypted, _ := enc.Encrypt(ek.Bytes(), msg)
		dec := hybrid.NewDecrypter(kem.Level768)
		b.StartTimer()
		dec.Decrypt(dk.Bytes(), encrypted)
	}
}

