package dsa_test

import (
	"testing"

	"github.com/quantum-shield/quantum-shield-go/internal/dsa"
)

func TestSignVerify(t *testing.T) {
	for _, level := range []dsa.Level{dsa.Level44, dsa.Level65, dsa.Level87} {
		t.Run(string(rune('0'+int(level/44))), func(t *testing.T) {
			pk, sk, err := dsa.GenerateKey(level)
			if err != nil {
				t.Fatalf("GenerateKey(%d): %v", level, err)
			}

			msg := []byte("Transfer EUR 500,000 — signed document")
			sig, err := dsa.Sign(sk, msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			if !dsa.Verify(pk, msg, sig) {
				t.Fatal("valid signature rejected")
			}
		})
	}
}

func TestTamperedMessage(t *testing.T) {
	pk, sk, _ := dsa.GenerateKey(dsa.Level65)
	msg := []byte("original document")
	sig, _ := dsa.Sign(sk, msg)

	tampered := []byte("modified document")
	if dsa.Verify(pk, tampered, sig) {
		t.Fatal("tampered message accepted")
	}
}

func TestTamperedSignature(t *testing.T) {
	pk, sk, _ := dsa.GenerateKey(dsa.Level65)
	msg := []byte("document")
	sig, _ := dsa.Sign(sk, msg)

	sig[0] ^= 0xFF
	if dsa.Verify(pk, msg, sig) {
		t.Fatal("tampered signature accepted")
	}
}

func TestWrongKey(t *testing.T) {
	_, sk, _ := dsa.GenerateKey(dsa.Level65)
	pk2, _, _ := dsa.GenerateKey(dsa.Level65)

	msg := []byte("document")
	sig, _ := dsa.Sign(sk, msg)
	if dsa.Verify(pk2, msg, sig) {
		t.Fatal("wrong key accepted")
	}
}

func TestSerialisation(t *testing.T) {
	pk, sk, _ := dsa.GenerateKey(dsa.Level65)
	msg := []byte("serialisation test")
	sig, _ := dsa.Sign(sk, msg)

	pkBytes, err := pk.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pk2, err := dsa.ParsePublicKey(dsa.Level65, pkBytes)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !dsa.Verify(pk2, msg, sig) {
		t.Fatal("serialised public key: verify failed")
	}
}

func TestNilInputs(t *testing.T) {
	if dsa.Verify(nil, []byte("msg"), []byte("sig")) {
		t.Fatal("nil public key should return false")
	}
}

func BenchmarkKeygen65(b *testing.B) {
	for b.Loop() {
		dsa.GenerateKey(dsa.Level65)
	}
}

func BenchmarkSign65(b *testing.B) {
	_, sk, _ := dsa.GenerateKey(dsa.Level65)
	msg := []byte("benchmark message for signing")
	b.ResetTimer()
	for b.Loop() {
		dsa.Sign(sk, msg)
	}
}

func BenchmarkVerify65(b *testing.B) {
	pk, sk, _ := dsa.GenerateKey(dsa.Level65)
	msg := []byte("benchmark message for signing")
	sig, _ := dsa.Sign(sk, msg)
	b.ResetTimer()
	for b.Loop() {
		dsa.Verify(pk, msg, sig)
	}
}
