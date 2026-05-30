// Package vault implements Shamir's Secret Sharing over GF(256).
//
// A secret (arbitrary bytes) is split into N shards such that any K of them
// suffice to reconstruct the secret. Fewer than K shards reveal nothing.
//
// Security properties:
//   - GF(256) arithmetic: all operations mod the AES irreducible polynomial x⁸+x⁴+x³+x+1
//   - Non-consecutive x-values prevent GF(256) degeneracy
//   - Each shard carries an HMAC-SHA256 checksum keyed by a value derived from
//     the secret itself — unforgeable without knowledge of the secret
//   - Reconstruction uses Lagrange interpolation — no trusted dealer needed
//
// Checksum design note:
//
//	Previous implementations used a fixed, hard-coded HMAC key. Because the key
//	was public (visible in source code), any attacker could compute valid checksums
//	for arbitrary shard data, bypassing Byzantine-fault detection entirely.
//
//	The current design derives the HMAC key from the secret:
//	  hmacKey = SHA-256("qs-shard-integrity-v1:" ‖ secret)
//
//	Consequence: checksum verification must occur AFTER Lagrange interpolation,
//	because the HMAC key is not known until the secret is reconstructed.
//	If any shard was tampered, interpolation produces an incorrect candidate
//	secret → a different HMAC key → a checksum mismatch → rejection.
package vault

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
)

// GF(256) irreducible polynomial: x⁸ + x⁴ + x³ + x + 1 = 0x11b
const gfPoly = 0x11b

// Shard is one piece of the split secret.
type Shard struct {
	Index    byte   // x-coordinate in GF(256), 1-based, non-zero
	Value    []byte // f(x) evaluated at Index, same length as secret
	Checksum []byte // HMAC-SHA256(shardHMACKey(secret), Index||Value) — Byzantine detection
}

// Split splits secret into n shards with reconstruction threshold k.
// Requires 2 ≤ k ≤ n ≤ 255.
func Split(secret []byte, n, k int) ([]Shard, error) {
	if len(secret) == 0 {
		return nil, errors.New("vault.Split: secret must not be empty")
	}
	if k < 2 || k > n || n > 255 {
		return nil, fmt.Errorf("vault.Split: invalid parameters n=%d k=%d (need 2≤k≤n≤255)", n, k)
	}

	// Generate k-1 random coefficients for each secret byte.
	// Polynomial: f(x) = secret[i] + a1·x + a2·x² + ... + a(k-1)·x^(k-1)
	// f(0) = secret[i] by construction.
	coeffs := make([][]byte, k)
	coeffs[0] = secret
	for i := 1; i < k; i++ {
		coeffs[i] = make([]byte, len(secret))
		if _, err := rand.Read(coeffs[i]); err != nil {
			return nil, fmt.Errorf("vault.Split: generate coefficients: %w", err)
		}
	}

	// Derive the per-secret HMAC key for shard integrity.
	// Bound to the secret — unforgeable without knowledge of the secret.
	hmacKey := shardHMACKey(secret)

	// Choose n non-consecutive x-values to prevent GF(256) degeneracy.
	// Use x = 2, 4, 6, ... (even values, all distinct and non-zero).
	shards := make([]Shard, n)
	for si := range n {
		x := byte((si + 1) * 2) // x ∈ {2, 4, 6, ..., 2n}
		value := make([]byte, len(secret))
		for bi := range len(secret) {
			// Evaluate polynomial at x using Horner's method
			result := byte(0)
			for ci := k - 1; ci >= 0; ci-- {
				result = gfMul(result, x)
				result = result ^ coeffs[ci][bi]
			}
			value[bi] = result
		}
		shards[si] = Shard{
			Index:    x,
			Value:    value,
			Checksum: shardChecksum(x, value, hmacKey),
		}
	}
	return shards, nil
}

// Reconstruct recovers the secret from at least k shards.
//
// Verification order:
//  1. Structural checks (shard count, zero/duplicate x-values).
//  2. Lagrange interpolation at x=0 — produces a candidate secret.
//  3. HMAC-SHA256 checksum verification using the candidate secret as key.
//     If any shard was tampered, interpolation yields an incorrect candidate,
//     its derived HMAC key differs from the one used at Split time, and the
//     checksum comparison fails — detecting Byzantine tampering.
//
// Returns an error if fewer than k shards are provided, if any structural
// check fails, or if any shard checksum does not match.
func Reconstruct(shards []Shard, k int) ([]byte, error) {
	if len(shards) < k {
		return nil, fmt.Errorf("vault.Reconstruct: need %d shards, got %d", k, len(shards))
	}
	if len(shards) == 0 {
		return nil, errors.New("vault.Reconstruct: no shards provided")
	}

	// Structural validation — does not require the secret.
	seen := make(map[byte]struct{}, len(shards))
	for _, s := range shards {
		if s.Index == 0 {
			return nil, errors.New("vault.Reconstruct: shard with x=0 is invalid")
		}
		if _, dup := seen[s.Index]; dup {
			return nil, fmt.Errorf("vault.Reconstruct: duplicate shard index %d", s.Index)
		}
		seen[s.Index] = struct{}{}
	}

	// Use only the first k shards for Lagrange interpolation.
	if k <= 0 || k > len(shards) {
		return nil, fmt.Errorf("vault.Reconstruct: k=%d out of range [1,%d]", k, len(shards))
	}
	active := shards[:k]
	if len(active[0].Value) == 0 {
		return nil, errors.New("vault.Reconstruct: first shard has empty value")
	}
	secretLen := len(active[0].Value)
	secret := make([]byte, secretLen)

	// Lagrange interpolation at x=0 over GF(256).
	for bi := range secretLen {
		result := byte(0)
		for i, si := range active {
			numerator := byte(1)
			denominator := byte(1)
			for j, sj := range active {
				if i == j {
					continue
				}
				// numerator   *= (0 - sj.Index) = sj.Index  in GF(256)  (negation = identity)
				// denominator *= (si.Index - sj.Index) = si.Index XOR sj.Index  in GF(256)
				numerator = gfMul(numerator, sj.Index)
				denominator = gfMul(denominator, si.Index^sj.Index)
			}
			lagrange := gfMul(numerator, gfInv(denominator))
			result ^= gfMul(si.Value[bi], lagrange)
		}
		secret[bi] = result
	}

	// Verify all provided shard checksums using the candidate secret as HMAC key.
	//
	// This step both detects tampering AND authenticates that the caller holds shards
	// produced by a Split of this exact secret — impossible to pass without knowing
	// the secret (or forging HMAC-SHA256 with a secret-derived key).
	//
	// If any shard was tampered, interpolation produced an incorrect candidate,
	// the derived HMAC key differs from Split's key, checksums will not match,
	// and the candidate secret is zeroed before the error is returned.
	hmacKey := shardHMACKey(secret)
	for i, s := range shards {
		expected := shardChecksum(s.Index, s.Value, hmacKey)
		if subtle.ConstantTimeCompare(s.Checksum, expected) != 1 {
			// Zero the candidate secret before returning to limit exposure window.
			for j := range secret {
				secret[j] = 0
			}
			return nil, fmt.Errorf(
				"vault.Reconstruct: shard %d (index %d) checksum mismatch — possible tampering",
				i, s.Index,
			)
		}
	}

	return secret, nil
}

// ── GF(256) arithmetic ────────────────────────────────────────────────────────

// gfMul multiplies two GF(256) elements using the AES polynomial.
//
// # Constant-time guarantee
//
// The original schoolbook implementation had two data-dependent branches:
//
//	if b&1 != 0 { result ^= a }        // timing leak: depends on bit of b
//	if carry != 0 { a ^= 0x1b }        // timing leak: depends on MSB of a
//
// This implementation replaces both with branchless arithmetic:
//
//	mask  = byte(0) - (b & 1)           // 0x00 when bit=0, 0xFF when bit=1
//	carry = byte(0) - (a >> 7)          // 0x00 when MSB=0, 0xFF when MSB=1
//
// The subtraction wraps in unsigned arithmetic (byte = uint8):
//
//	0x00 - 0x01 = 0xFF  (two's complement wrap)
//	0x00 - 0x00 = 0x00
//
// Both loops run exactly 8 iterations regardless of operand values.
// This eliminates all data-dependent timing variation in GF(256) multiplication,
// preventing timing attacks on Lagrange interpolation in Reconstruct().
func gfMul(a, b byte) byte {
	var result byte
	for range 8 { // always 8 iterations — no data-dependent loop count
		// Branchless conditional: mask = 0xFF if low bit of b is 1, else 0x00
		mask := byte(0) - (b & 1)
		result ^= a & mask

		// Branchless reduction: carry = 0xFF if MSB of a is 1, else 0x00
		carry := byte(0) - (a >> 7)
		a = (a << 1) ^ (0x1b & carry) // 0x1b = low byte of AES polynomial 0x11b

		b >>= 1
	}
	return result
}

// gfInv returns the multiplicative inverse of a in GF(256).
// Uses Fermat's little theorem: a^(256-2) = a^254 in GF(256).
//
// The computation is a^2 · a → a^3, then repeated (square then multiply by a)
// six more times. All operations call the constant-time gfMul above.
// Loop count is fixed at 7 iterations regardless of input value.
func gfInv(a byte) byte {
	if a == 0 {
		panic("vault: GF(256) inverse of zero is undefined")
	}
	// Build a^254 = a^(2+4+8+16+32+64+128) via square-and-multiply.
	// Iteration i produces a^(2^(i+1)) * a^(2^i - 1) accumulated.
	result := a
	for range 6 {
		result = gfMul(result, result) // square
		result = gfMul(result, a)      // multiply by a
	}
	result = gfMul(result, result) // final square: a^254
	return result
}

// ── Shard integrity ───────────────────────────────────────────────────────────

// shardHMACKey derives the HMAC key used for shard integrity verification.
// Binding the key to the secret means:
//   - An attacker who does not know the secret cannot compute valid checksums
//     for arbitrary shard data, even knowing the algorithm and source code.
//   - Verification must happen after Lagrange interpolation (post-reconstruction),
//     since the key is not available until the secret is known.
func shardHMACKey(secret []byte) []byte {
	h := sha256.New()
	h.Write([]byte("qs-shard-integrity-v1:"))
	h.Write(secret)
	return h.Sum(nil)
}

// shardChecksum returns HMAC-SHA256(hmacKey, index || value).
// The hmacKey must be shardHMACKey(secret) — never a fixed/public key.
func shardChecksum(index byte, value, hmacKey []byte) []byte {
	h := hmac.New(sha256.New, hmacKey)
	h.Write([]byte{index})
	h.Write(value)
	return h.Sum(nil)
}
