package slhdsa_test

import (
	"bytes"
	"testing"

	"github.com/quantum-shield/quantum-shield-go/internal/slhdsa"
)

// ── basic correctness ─────────────────────────────────────────────────────────

func TestSignVerify_AllLevels(t *testing.T) {
	levels := []slhdsa.Level{
		slhdsa.Level128f,
		slhdsa.Level128s,
	}
	// 192/256 levels are correct but slow — tested separately via -run or in CI.

	msg := []byte("post-quantum signed document")
	for _, lvl := range levels {
		t.Run(lvl.AlgorithmName(), func(t *testing.T) {
			pk, sk, err := slhdsa.GenerateKey(lvl)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			sig, err := slhdsa.Sign(sk, msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !slhdsa.Verify(pk, msg, sig) {
				t.Fatal("valid signature rejected")
			}
		})
	}
}

// TestSignVerify_HighSecurity tests the 192-bit and 256-bit parameter sets.
// These are slower; run with -run TestSignVerify_HighSecurity when needed.
func TestSignVerify_HighSecurity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping high-security levels in short mode")
	}
	levels := []slhdsa.Level{
		slhdsa.Level192f,
		slhdsa.Level192s,
		slhdsa.Level256f,
		slhdsa.Level256s,
	}
	msg := []byte("high-security signed document")
	for _, lvl := range levels {
		t.Run(lvl.AlgorithmName(), func(t *testing.T) {
			pk, sk, err := slhdsa.GenerateKey(lvl)
			if err != nil {
				t.Fatalf("GenerateKey(%s): %v", lvl.AlgorithmName(), err)
			}
			sig, err := slhdsa.Sign(sk, msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !slhdsa.Verify(pk, msg, sig) {
				t.Fatal("valid signature rejected")
			}
		})
	}
}

// ── tamper detection ──────────────────────────────────────────────────────────

func TestTamperedMessage(t *testing.T) {
	pk, sk, _ := slhdsa.GenerateKey(slhdsa.Level128f)
	msg := []byte("original document")
	sig, _ := slhdsa.Sign(sk, msg)

	if slhdsa.Verify(pk, []byte("modified document"), sig) {
		t.Fatal("tampered message accepted")
	}
}

func TestTamperedSignature(t *testing.T) {
	pk, sk, _ := slhdsa.GenerateKey(slhdsa.Level128f)
	msg := []byte("document")
	sig, _ := slhdsa.Sign(sk, msg)

	// Flip bits in the middle of the signature.
	mid := len(sig) / 2
	sig[mid] ^= 0xFF
	sig[mid+1] ^= 0xAA

	if slhdsa.Verify(pk, msg, sig) {
		t.Fatal("tampered signature accepted")
	}
}

func TestWrongKey(t *testing.T) {
	_, sk, _ := slhdsa.GenerateKey(slhdsa.Level128f)
	pk2, _, _ := slhdsa.GenerateKey(slhdsa.Level128f)

	msg := []byte("document")
	sig, _ := slhdsa.Sign(sk, msg)
	if slhdsa.Verify(pk2, msg, sig) {
		t.Fatal("signature verified under wrong key")
	}
}

func TestNilInputs(t *testing.T) {
	pk, sk, _ := slhdsa.GenerateKey(slhdsa.Level128f)
	msg := []byte("document")
	sig, _ := slhdsa.Sign(sk, msg)

	// nil public key
	if slhdsa.Verify(nil, msg, sig) {
		t.Fatal("nil public key should return false")
	}
	// empty signature
	if slhdsa.Verify(pk, msg, []byte{}) {
		t.Fatal("empty signature should return false")
	}
	// nil private key
	if _, err := slhdsa.Sign(nil, msg); err == nil {
		t.Fatal("Sign with nil key should error")
	}
}

// ── serialisation round-trips ─────────────────────────────────────────────────

func TestSerialisation_PublicKey(t *testing.T) {
	pk, sk, _ := slhdsa.GenerateKey(slhdsa.Level128f)
	msg := []byte("serialisation test")
	sig, _ := slhdsa.Sign(sk, msg)

	pkBytes := pk.Bytes()
	if len(pkBytes) == 0 {
		t.Fatal("public key bytes are empty")
	}

	pk2, err := slhdsa.ParsePublicKey(slhdsa.Level128f, pkBytes)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !slhdsa.Verify(pk2, msg, sig) {
		t.Fatal("deserialised public key: verify failed")
	}
}

func TestSerialisation_PrivateKey(t *testing.T) {
	pk, sk, _ := slhdsa.GenerateKey(slhdsa.Level128f)
	skBytes := sk.Bytes()
	if len(skBytes) == 0 {
		t.Fatal("private key bytes are empty")
	}

	sk2, err := slhdsa.ParsePrivateKey(slhdsa.Level128f, skBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	// Sign with the reconstructed key; verify with original public key.
	msg := []byte("round-trip test")
	sig, err := slhdsa.Sign(sk2, msg)
	if err != nil {
		t.Fatalf("Sign after deserialise: %v", err)
	}
	if !slhdsa.Verify(pk, msg, sig) {
		t.Fatal("signature from deserialised private key rejected by original public key")
	}
}

func TestPublicKeyFromPrivate(t *testing.T) {
	pkOrig, sk, _ := slhdsa.GenerateKey(slhdsa.Level128f)

	// Derive public key from private key and verify they match.
	pkDerived := sk.Public()
	if !bytes.Equal(pkOrig.Bytes(), pkDerived.Bytes()) {
		t.Fatal("Public() derived key does not match the keypair's public key")
	}
}

// ── parameter set API ─────────────────────────────────────────────────────────

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want slhdsa.Level
		ok   bool
	}{
		{"", slhdsa.Level128f, true},
		{"128f", slhdsa.Level128f, true},
		{"128s", slhdsa.Level128s, true},
		{"192f", slhdsa.Level192f, true},
		{"192s", slhdsa.Level192s, true},
		{"256f", slhdsa.Level256f, true},
		{"256s", slhdsa.Level256s, true},
		{"bogus", slhdsa.Level128f, false},
		{"256x", slhdsa.Level128f, false},
	}
	for _, tc := range cases {
		lvl, err := slhdsa.ParseLevel(tc.in)
		if tc.ok {
			if err != nil {
				t.Errorf("ParseLevel(%q): unexpected error: %v", tc.in, err)
			} else if lvl != tc.want {
				t.Errorf("ParseLevel(%q): got %v, want %v", tc.in, lvl, tc.want)
			}
		} else {
			if err == nil {
				t.Errorf("ParseLevel(%q): expected error, got nil", tc.in)
			}
		}
	}
}

func TestAlgorithmName(t *testing.T) {
	cases := map[slhdsa.Level]string{
		slhdsa.Level128f: "SLH-DSA-SHA2-128f",
		slhdsa.Level128s: "SLH-DSA-SHA2-128s",
		slhdsa.Level192f: "SLH-DSA-SHA2-192f",
		slhdsa.Level192s: "SLH-DSA-SHA2-192s",
		slhdsa.Level256f: "SLH-DSA-SHA2-256f",
		slhdsa.Level256s: "SLH-DSA-SHA2-256s",
	}
	for lvl, want := range cases {
		if got := lvl.AlgorithmName(); got != want {
			t.Errorf("Level(%d).AlgorithmName() = %q, want %q", lvl, got, want)
		}
	}
}

// ── key level isolation ───────────────────────────────────────────────────────

func TestCrossLevelRejection(t *testing.T) {
	// A public key from 128f cannot verify a signature made with 128s (different
	// parameter sets produce incompatible key / signature sizes).
	_, sk128s, _ := slhdsa.GenerateKey(slhdsa.Level128s)
	pk128f, _, _ := slhdsa.GenerateKey(slhdsa.Level128f)

	msg := []byte("level isolation test")
	sig128s, _ := slhdsa.Sign(sk128s, msg)

	// Trying to verify a 128s signature with a 128f public key should fail —
	// either the LoadSignature call inside Verify rejects the wrong-length bytes,
	// or the verification itself returns false.
	if slhdsa.Verify(pk128f, msg, sig128s) {
		t.Fatal("128s signature accepted under 128f public key")
	}
}

// ── randomised signing uniqueness ─────────────────────────────────────────────

func TestRandomizedSigning_UniqueSignatures(t *testing.T) {
	// Two calls to Sign over the same message should produce different signatures
	// because SLH-DSA signing is hedged (randomized nonce per signature).
	pk, sk, _ := slhdsa.GenerateKey(slhdsa.Level128f)
	msg := []byte("unique signature test")

	sig1, err1 := slhdsa.Sign(sk, msg)
	sig2, err2 := slhdsa.Sign(sk, msg)
	if err1 != nil || err2 != nil {
		t.Fatalf("Sign failed: %v / %v", err1, err2)
	}
	if bytes.Equal(sig1, sig2) {
		t.Fatal("two Sign calls produced identical signatures — randomization may be broken")
	}
	// Both signatures must still be valid.
	if !slhdsa.Verify(pk, msg, sig1) {
		t.Fatal("first signature invalid")
	}
	if !slhdsa.Verify(pk, msg, sig2) {
		t.Fatal("second signature invalid")
	}
}

// ── benchmarks ────────────────────────────────────────────────────────────────

func BenchmarkKeygen128f(b *testing.B) {
	for b.Loop() {
		slhdsa.GenerateKey(slhdsa.Level128f)
	}
}

func BenchmarkSign128f(b *testing.B) {
	_, sk, _ := slhdsa.GenerateKey(slhdsa.Level128f)
	msg := []byte("benchmark message")
	b.ResetTimer()
	for b.Loop() {
		slhdsa.Sign(sk, msg)
	}
}

func BenchmarkVerify128f(b *testing.B) {
	pk, sk, _ := slhdsa.GenerateKey(slhdsa.Level128f)
	msg := []byte("benchmark message")
	sig, _ := slhdsa.Sign(sk, msg)
	b.ResetTimer()
	for b.Loop() {
		slhdsa.Verify(pk, msg, sig)
	}
}

func BenchmarkSign128s(b *testing.B) {
	_, sk, _ := slhdsa.GenerateKey(slhdsa.Level128s)
	msg := []byte("benchmark message")
	b.ResetTimer()
	for b.Loop() {
		slhdsa.Sign(sk, msg)
	}
}
