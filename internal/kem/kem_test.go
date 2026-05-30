package kem_test

import (
	"bytes"
	"testing"

	"github.com/quantum-shield/quantum-shield-go/internal/kem"
)

func TestRoundtrip(t *testing.T) {
	for _, level := range []kem.Level{kem.Level768, kem.Level1024} {
		level := level
		t.Run(string(rune('0'+int(level/768))), func(t *testing.T) {
			dk, err := kem.GenerateKey(level)
			if err != nil {
				t.Fatalf("GenerateKey(%d): %v", level, err)
			}
			ek := dk.EncapsulationKey()

			ss1, ct, err := kem.Encapsulate(ek)
			if err != nil {
				t.Fatalf("Encapsulate: %v", err)
			}
			if len(ss1) != 32 {
				t.Fatalf("expected 32-byte shared secret, got %d", len(ss1))
			}

			ss2, err := kem.Decapsulate(dk, ct)
			if err != nil {
				t.Fatalf("Decapsulate: %v", err)
			}
			if !bytes.Equal(ss1, ss2) {
				t.Fatal("shared secrets do not match")
			}
		})
	}
}

func TestSerialisation(t *testing.T) {
	dk, err := kem.GenerateKey(kem.Level768)
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	// Roundtrip public key
	ek2, err := kem.ParseEncapsulationKey(kem.Level768, ek.Bytes())
	if err != nil {
		t.Fatalf("ParseEncapsulationKey: %v", err)
	}
	// Roundtrip private key (seed)
	dk2, err := kem.ParseDecapsulationKey(kem.Level768, dk.Bytes())
	if err != nil {
		t.Fatalf("ParseDecapsulationKey: %v", err)
	}

	ss1, ct, _ := kem.Encapsulate(ek2)
	ss2, err := kem.Decapsulate(dk2, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("serialised keys: shared secrets do not match")
	}
}

func TestWrongKey(t *testing.T) {
	dk, _ := kem.GenerateKey(kem.Level768)
	dk2, _ := kem.GenerateKey(kem.Level768)
	ek2 := dk2.EncapsulationKey()

	// Encapsulate under dk2's public key, decapsulate with dk
	// Per FIPS 203 implicit rejection: no panic, no oracle.
	_, ct, _ := kem.Encapsulate(ek2)
	_, _ = kem.Decapsulate(dk, ct) // must not panic
}

func TestNilKey(t *testing.T) {
	if _, _, err := kem.Encapsulate(nil); err == nil {
		t.Fatal("nil encapsulation key should return error")
	}
	if _, err := kem.Decapsulate(nil, []byte("ct")); err == nil {
		t.Fatal("nil decapsulation key should return error")
	}
}

func BenchmarkKeygen768(b *testing.B) {
	for b.Loop() {
		if _, err := kem.GenerateKey(kem.Level768); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncapsulate768(b *testing.B) {
	dk, _ := kem.GenerateKey(kem.Level768)
	ek := dk.EncapsulationKey()
	b.ResetTimer()
	for b.Loop() {
		kem.Encapsulate(ek)
	}
}

func BenchmarkDecapsulate768(b *testing.B) {
	dk, _ := kem.GenerateKey(kem.Level768)
	ek := dk.EncapsulationKey()
	_, ct, _ := kem.Encapsulate(ek)
	b.ResetTimer()
	for b.Loop() {
		kem.Decapsulate(dk, ct)
	}
}
