package vault_test

import (
	"bytes"
	"testing"

	"github.com/quantum-shield/quantum-shield-go/internal/vault"
)

// ── Correctness ───────────────────────────────────────────────────────────────

func TestBasicSplitReconstruct(t *testing.T) {
	secret := []byte("Transfer EUR 1,000,000 — TOP SECRET")
	shards, err := vault.Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(shards) != 5 {
		t.Fatalf("expected 5 shards, got %d", len(shards))
	}

	recovered, err := vault.Reconstruct(shards[:3], 3)
	if err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	if !bytes.Equal(secret, recovered) {
		t.Fatalf("secret mismatch\ngot:  %q\nwant: %q", recovered, secret)
	}
}

func TestAnyKOfNShards(t *testing.T) {
	// Any combination of k shards must reconstruct the secret correctly
	secret := []byte("quantum-safe private key material")
	shards, _ := vault.Split(secret, 5, 3)

	combinations := [][]int{
		{0, 1, 2}, {0, 1, 3}, {0, 1, 4},
		{0, 2, 3}, {0, 2, 4}, {0, 3, 4},
		{1, 2, 3}, {1, 2, 4}, {1, 3, 4},
		{2, 3, 4},
	}
	for _, combo := range combinations {
		selected := []vault.Shard{shards[combo[0]], shards[combo[1]], shards[combo[2]]}
		recovered, err := vault.Reconstruct(selected, 3)
		if err != nil {
			t.Errorf("Reconstruct(%v): %v", combo, err)
			continue
		}
		if !bytes.Equal(secret, recovered) {
			t.Errorf("Reconstruct(%v): secret mismatch", combo)
		}
	}
}

func TestAllNShards(t *testing.T) {
	// Using all 5 shards also works
	secret := []byte("all shards reconstruction test")
	shards, _ := vault.Split(secret, 5, 3)
	recovered, err := vault.Reconstruct(shards, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, recovered) {
		t.Fatal("mismatch with all shards")
	}
}

func TestThreshold2of3(t *testing.T) {
	secret := []byte("minimum threshold test")
	shards, _ := vault.Split(secret, 3, 2)
	recovered, _ := vault.Reconstruct(shards[:2], 2)
	if !bytes.Equal(secret, recovered) {
		t.Fatal("2-of-3 failed")
	}
}

func TestBinarySecret(t *testing.T) {
	// ML-KEM private key seed is 64 bytes of binary data
	secret := make([]byte, 64)
	for i := range secret {
		secret[i] = byte(i * 17)
	}
	shards, _ := vault.Split(secret, 7, 4)
	recovered, err := vault.Reconstruct(shards[:4], 4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, recovered) {
		t.Fatal("binary secret mismatch")
	}
}

// ── Security ──────────────────────────────────────────────────────────────────

func TestInsufficientShards(t *testing.T) {
	secret := []byte("cannot reconstruct with too few shards")
	shards, _ := vault.Split(secret, 5, 3)

	// Only 2 shards — must fail (or return wrong data, but must not panic)
	_, err := vault.Reconstruct(shards[:2], 3)
	if err == nil {
		t.Fatal("reconstruction with insufficient shards should fail")
	}
}

func TestTamperedShardValue(t *testing.T) {
	secret := []byte("tamper detection test")
	shards, _ := vault.Split(secret, 5, 3)

	// Tamper shard value — checksum should catch it
	shards[0].Value[0] ^= 0xFF
	_, err := vault.Reconstruct(shards[:3], 3)
	if err == nil {
		t.Fatal("tampered shard value should be detected by checksum")
	}
}

func TestTamperedShardIndex(t *testing.T) {
	secret := []byte("index tamper test")
	shards, _ := vault.Split(secret, 5, 3)

	// Tamper shard index — checksum covers index too
	shards[0].Index ^= 0x01
	_, err := vault.Reconstruct(shards[:3], 3)
	if err == nil {
		t.Fatal("tampered shard index should be detected by checksum")
	}
}

func TestDuplicateShards(t *testing.T) {
	secret := []byte("duplicate shard test")
	shards, _ := vault.Split(secret, 5, 3)

	// Pass shard 0 twice — must fail
	dup := []vault.Shard{shards[0], shards[0], shards[1]}
	_, err := vault.Reconstruct(dup, 3)
	if err == nil {
		t.Fatal("duplicate shard indices should be rejected")
	}
}

func TestInvalidParameters(t *testing.T) {
	secret := []byte("param test")
	cases := []struct{ n, k int }{
		{1, 1},  // k < 2
		{3, 4},  // k > n
		{256, 3}, // n > 255
		{0, 0},
	}
	for _, c := range cases {
		if _, err := vault.Split(secret, c.n, c.k); err == nil {
			t.Errorf("Split(n=%d, k=%d) should fail", c.n, c.k)
		}
	}
}

func TestEmptySecret(t *testing.T) {
	if _, err := vault.Split(nil, 3, 2); err == nil {
		t.Fatal("empty secret should fail")
	}
}

func TestRandomnessFresh(t *testing.T) {
	// Two splits of the same secret must produce different shards (random coefficients)
	secret := []byte("randomness test")
	s1, _ := vault.Split(secret, 3, 2)
	s2, _ := vault.Split(secret, 3, 2)
	if bytes.Equal(s1[0].Value, s2[0].Value) {
		t.Fatal("shard values should be different across splits (random coefficients)")
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

func BenchmarkSplit5of3(b *testing.B) {
	secret := make([]byte, 32) // 256-bit key
	for b.Loop() {
		vault.Split(secret, 5, 3)
	}
}

func BenchmarkReconstruct5of3(b *testing.B) {
	secret := make([]byte, 32)
	shards, _ := vault.Split(secret, 5, 3)
	b.ResetTimer()
	for b.Loop() {
		vault.Reconstruct(shards[:3], 3)
	}
}
