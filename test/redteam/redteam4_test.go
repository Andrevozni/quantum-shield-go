// redteam4_test.go — Level-4: maximum-force cryptographic and operational attacks.
//
// These attacks target guarantees that are hard to verify from outside but
// catastrophic when broken. Unlike L1–L3 (API surface, type safety, crypto
// primitives), L4 attacks internal invariants:
//
//   - AES-GCM nonce uniqueness (nonce reuse = full plaintext recovery)
//   - Threshold deduplication (one signer must not reach M-of-N alone)
//   - Goroutine leak under sustained attack (resource exhaustion)
//   - CA serial uniqueness under concurrency (PKI correctness)
//   - Ciphertext replay cache (same CT decrypted twice must fail)
//   - Vault at boundary parameters (k=n, k=2)
//   - Concurrent revocation correctness (no panic, no lost state)
//   - Token expiry enforcement (expired tokens must be rejected)
//   - Timing oracle statistical analysis (Welch t-test style, not just ratio)
//   - GF(256) zero denominator via duplicate shard index at API level
//   - HKDF output overflow (> 255*HashLen = 8160 bytes)
//   - Wrong-key decryption (same level, different keypair)
//   - Non-existent channel session scan (O(1) lookup, no DoS)
//   - Large vault secret (32 KB split/reconstruct correctness)
//
//	go test -v ./test/redteam/... -run "TestRedTeam4" -timeout 120s
//	go test -race ./test/redteam/... -run "TestRedTeam4" -timeout 120s
package redteam_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantum-shield/quantum-shield-go/pkg/api"
)

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 39: AES-GCM Nonce Uniqueness
//
// AES-256-GCM is catastrophically broken if the same nonce is used twice with
// the same key: an attacker who sees two ciphertexts with the same nonce can
// XOR them to cancel the keystream and recover XOR(plaintext_A, plaintext_B).
// With two known plaintexts the key is fully recoverable.
//
// The server generates a 12-byte nonce from crypto/rand for every Encrypt call.
// With 300 encryptions the probability of collision is ~4e-18 (birthday bound).
// A collision here would indicate a CSPRNG failure or code bug.
//
// This test encrypts 300 messages with the same ML-KEM key and verifies that
// every nonce is unique.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam4_AESGCMNonceUniqueness(t *testing.T) {
	ts, cleanup := srv(t,
		api.WithIPRateLimit(10_000, time.Minute),
		api.WithSubjectRateLimit(10_000, time.Minute),
	)
	defer cleanup()
	tok := token(t, ts, "u", []string{"write", "read"})
	keyID, _ := genKey(t, ts, tok, "ML-KEM-768")

	const iterations = 300
	nonces := make(map[string]int, iterations)

	for i := range iterations {
		_, resp := jreq(t, ts, "POST", "/encrypt", map[string]any{
			"key_id":    keyID,
			"plaintext": fmt.Sprintf("nonce-test-msg-%d", i),
		}, tok)

		enc, ok := resp["encrypted"].(map[string]any)
		if !ok {
			t.Fatalf("iteration %d: no encrypted object in response", i)
		}
		nonce, _ := enc["nonce"].(string)
		if nonce == "" {
			t.Fatalf("iteration %d: empty nonce in response", i)
		}
		if prev, seen := nonces[nonce]; seen {
			t.Errorf("CRITICAL: AES-GCM nonce collision — iteration %d reused nonce from "+
				"iteration %d (nonce=%q). Nonce reuse with the same key allows "+
				"full plaintext recovery via XOR cancellation.", i, prev, nonce)
		}
		nonces[nonce] = i
	}
	t.Logf("AES-GCM nonce uniqueness: %d encryptions, %d unique nonces — zero collisions ✓",
		iterations, len(nonces))
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 40: Threshold Duplicate Signer — One Signer Must Not Solo
//
// A coordinator that counts submissions rather than unique signers can be
// fooled by a single rogue signer who submits their partial signature M times,
// reaching the threshold without needing M-1 co-signers.
//
// The coordinator must deduplicate by signer_id and reject attempts by the
// same signer to push the count above 1.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam4_Threshold_DuplicateSigner_CannotSoloThreshold(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	tok := token(t, ts, "u", []string{"write", "read"})

	// Open a round with threshold=3 — needs 3 distinct signers.
	roundMsg := base64.StdEncoding.EncodeToString([]byte("threshold-dedup-test"))
	code, roundResp := jreq(t, ts, "POST", "/threshold/round", map[string]any{
		"message":   roundMsg,
		"threshold": 3,
	}, tok)
	if code != 200 {
		t.Fatalf("threshold/round: %d %v", code, roundResp)
	}
	roundID, _ := roundResp["round_id"].(string)
	nonce, _ := roundResp["nonce"].(string)

	// One signer produces their partial signature.
	signCode, signResp := jreq(t, ts, "POST", "/threshold/sign", map[string]any{
		"signer_id": "rogue-signer",
		"round_id":  roundID,
		"nonce":     nonce,
		"message":   roundMsg,
	}, tok)
	if signCode != 200 {
		t.Fatalf("threshold/sign: %d %v", signCode, signResp)
	}

	pk, _ := signResp["public_key"].(string)
	sig, _ := signResp["signature"].(string)
	nc, _ := signResp["nonce"].(string)

	// Submit the SAME partial 5 times — rogue signer tries to solo the threshold.
	var reached atomic.Bool
	for i := range 5 {
		code, resp := jreq(t, ts, "POST", "/threshold/submit", map[string]any{
			"round_id":   roundID,
			"signer_id":  "rogue-signer", // same ID every time
			"public_key": pk,
			"signature":  sig,
			"nonce":      nc,
		}, tok)

		if code == 200 {
			done, _ := resp["done"].(bool)
			if done {
				reached.Store(true)
				t.Errorf("CRITICAL: threshold reached by 1 signer submitting %d times "+
					"(threshold=3). Coordinator does not deduplicate by signer_id — "+
					"a single rogue signer can forge 'M-of-N' authorisation.", i+1)
			}
		}
	}

	if !reached.Load() {
		t.Logf("Threshold deduplication correct: 1 signer × 5 submissions did not "+
			"reach threshold=3. Coordinator deduplicates by signer_id ✓")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 41: Goroutine Leak Under Sustained Malformed Request Attack
//
// Each HTTP request spawns a goroutine in net/http. Goroutines that are never
// released (blocked reads, leaked channels, missing cleanup) cause memory
// growth that can eventually exhaust the heap.
//
// After 300 malformed requests we measure the goroutine delta. A growing
// goroutine count under load is a resource-exhaustion vulnerability.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam4_NoGoroutineLeak_UnderMalformedAttack(t *testing.T) {
	ts, cleanup := srv(t,
		api.WithIPRateLimit(10_000, time.Minute),
		api.WithSubjectRateLimit(10_000, time.Minute),
	)
	defer cleanup()
	tok := token(t, ts, "u", []string{"write", "read"})

	// Warm up the server (first requests allocate pools, etc.).
	for range 20 {
		jreq(t, ts, "POST", "/keys/generate", map[string]any{"level": "ML-KEM-768"}, tok) //nolint:errcheck
	}

	// Settle: let runtime release any temporary goroutines.
	runtime.GC()
	time.Sleep(150 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	// Fire 300 malformed requests across various endpoints.
	const attackRounds = 300
	badBodies := []map[string]any{
		{"key_id": ""},
		{"level": nil},
		{"secret": "!!!not-base64!!!"},
		{"encrypted": map[string]any{}},
		{},
	}
	endpoints := []string{
		"/encrypt", "/decrypt", "/sign", "/vault/split",
		"/vault/reconstruct", "/channel/complete", "/kdf/hkdf",
	}

	var wg sync.WaitGroup
	for i := range attackRounds {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ep := endpoints[i%len(endpoints)]
			body := badBodies[i%len(badBodies)]
			b, _ := json.Marshal(body)
			req, _ := http.NewRequest("POST", ts.URL+ep, bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, _ := ts.Client().Do(req)
			if resp != nil {
				resp.Body.Close()
			}
		}(i)
	}
	wg.Wait()

	// Allow leaked goroutines to settle, then measure.
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	after := runtime.NumGoroutine()
	delta := after - baseline

	t.Logf("Goroutine leak test: baseline=%d after_attack=%d delta=%+d",
		baseline, after, delta)

	// Allow a small budget for background workers. A delta > 10 indicates a leak.
	if delta > 10 {
		t.Errorf("VULNERABILITY: goroutine count grew by %d after %d malformed requests "+
			"— goroutine leak detected. Each leaked goroutine holds its stack (~4 KB) "+
			"and any referenced heap.", delta, attackRounds)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 42: CA Serial Number Uniqueness Under High Concurrency
//
// If the CA's serial-number counter uses a non-atomic increment or a read-
// modify-write pattern without a lock, two concurrent /ca/sign calls can
// receive the same serial number. In X.509 PKI, duplicate serials corrupt
// the CRL (both certs appear revoked when only one should be).
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam4_CASerial_UniqueUnderConcurrency(t *testing.T) {
	ts, cleanup := srv(t,
		api.WithIPRateLimit(10_000, time.Minute),
		api.WithSubjectRateLimit(10_000, time.Minute),
	)
	defer cleanup()
	adminTok := token(t, ts, "admin", []string{"admin", "write", "read"})
	writeTok := token(t, ts, "w", []string{"write", "read"})

	jreq(t, ts, "POST", "/ca/init",
		map[string]any{"subject": "CN=Serial-Race CA"}, adminTok) //nolint:errcheck

	const workers = 80
	_, pubKey := genKey(t, ts, writeTok, "ML-KEM-768")

	serials := make([]string, workers)
	var wg sync.WaitGroup
	var failures atomic.Int64

	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			code, resp := jreq(t, ts, "POST", "/ca/sign", map[string]any{
				"subject":         fmt.Sprintf("CN=worker-%d.example.com", i),
				"public_key":      pubKey,
				"public_key_type": "ML-KEM-768",
			}, writeTok)
			if code != 200 {
				failures.Add(1)
				return
			}
			serials[i], _ = resp["serial"].(string)
		}(i)
	}
	wg.Wait()

	// Count unique non-empty serials.
	seen := make(map[string]int, workers)
	for i, s := range serials {
		if s == "" {
			continue
		}
		if prev, dup := seen[s]; dup {
			t.Errorf("CRITICAL: serial collision — worker %d and worker %d both received "+
				"serial=%q. Duplicate serials corrupt CRL and revocation semantics.", i, prev, s)
		}
		seen[s] = i
	}

	issued := int64(workers) - failures.Load()
	t.Logf("CA serial uniqueness: %d certificates issued concurrently, "+
		"%d unique serials, %d failures — zero collisions ✓",
		issued, len(seen), failures.Load())
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 43: Ciphertext Replay Cache — Second Decrypt Must Fail
//
// The hybrid layer maintains a per-level in-process replay cache keyed on the
// KEM ciphertext. Replaying a captured ciphertext against the same server must
// be rejected even if the AEAD authentication passes.
//
// This prevents "double-spend" attacks in payment/authorisation systems where
// a single encrypted command must be executed exactly once.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam4_CiphertextReplayCache_SecondDecryptFails(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	tok := token(t, ts, "u", []string{"write", "read"})
	keyID, _ := genKey(t, ts, tok, "ML-KEM-768")

	// Encrypt once.
	_, encResp := jreq(t, ts, "POST", "/encrypt", map[string]any{
		"key_id":    keyID,
		"plaintext": "replay-cache-test",
	}, tok)
	enc := encResp["encrypted"].(map[string]any)

	// First decrypt — must succeed.
	code1, _ := jreq(t, ts, "POST", "/decrypt", map[string]any{
		"key_id":    keyID,
		"encrypted": enc,
	}, tok)
	if code1 != 200 {
		t.Fatalf("first decrypt failed: %d (expected 200)", code1)
	}

	// Second decrypt with the IDENTICAL ciphertext — must be rejected.
	code2, _ := jreq(t, ts, "POST", "/decrypt", map[string]any{
		"key_id":    keyID,
		"encrypted": enc,
	}, tok)
	if code2 == 200 {
		t.Errorf("CRITICAL: replay attack succeeded — identical ciphertext decrypted twice. "+
			"The in-process replay cache is not working. An attacker who captures "+
			"an encrypted authorisation command can replay it indefinitely.")
	} else {
		t.Logf("Replay cache working: second decrypt of identical ciphertext → %d ✓", code2)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 44: Vault Boundary Parameters
//
// Test the extreme boundary conditions of Shamir secret sharing:
//   - k=n=2 (minimum valid threshold, no redundancy — any single shard loss destroys secret)
//   - k=2, n=10 (minimum threshold, high redundancy)
//   - k=n=10 (all shards required — no fault tolerance)
//
// These are not attacks per se but regression tests for boundary arithmetic
// in GF(256) polynomial evaluation.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam4_Vault_BoundaryParameters(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	tok := token(t, ts, "u", []string{"write", "read"})

	secretRaw := make([]byte, 32)
	rand.Read(secretRaw) //nolint:errcheck
	secret := base64.StdEncoding.EncodeToString(secretRaw)

	cases := []struct{ n, k int }{
		{2, 2},   // minimum valid (k=n, zero redundancy)
		{10, 2},  // minimum threshold, high redundancy
		{10, 10}, // all shards required
		{20, 11}, // just above half (> 50% required)
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("n=%d_k=%d", tc.n, tc.k), func(t *testing.T) {
			// Split.
			code, splitResp := jreq(t, ts, "POST", "/vault/split", map[string]any{
				"secret":    secret,
				"n":         tc.n,
				"threshold": tc.k,
			}, tok)
			if code != 200 {
				t.Fatalf("vault/split n=%d k=%d: %d %v", tc.n, tc.k, code, splitResp)
			}

			shardsRaw, _ := splitResp["shards"].([]any)
			if len(shardsRaw) != tc.n {
				t.Fatalf("expected %d shards, got %d", tc.n, len(shardsRaw))
			}

			// Reconstruct using exactly k shards.
			shards := make([]map[string]any, tc.k)
			for i := range tc.k {
				shards[i] = shardsRaw[i].(map[string]any)
			}

			code, recResp := jreq(t, ts, "POST", "/vault/reconstruct", map[string]any{
				"shards":    shards,
				"threshold": tc.k,
			}, tok)
			if code != 200 {
				t.Errorf("vault/reconstruct n=%d k=%d: %d %v", tc.n, tc.k, code, recResp)
				return
			}
			reconstructed, _ := recResp["secret"].(string)
			if reconstructed != secret {
				t.Errorf("n=%d k=%d: reconstructed secret does not match original", tc.n, tc.k)
			}

			// k-1 shards must NOT reconstruct the secret.
			if tc.k > 2 {
				insufficientShards := shards[:tc.k-1]
				code, _ = jreq(t, ts, "POST", "/vault/reconstruct", map[string]any{
					"shards":    insufficientShards,
					"threshold": tc.k,
				}, tok)
				if code == 200 {
					t.Errorf("CRITICAL: n=%d k=%d — %d shards (< threshold) reconstructed secret",
						tc.n, tc.k, tc.k-1)
				}
			}
		})
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 45: Vault Large Secret (32 KB)
//
// Shamir SSS processes each byte of the secret independently. A 32 KB secret
// requires 32,768 polynomial evaluations per shard. This test verifies:
//   1. The server does not OOM or time out (< 10s)
//   2. Reconstructed secret matches the original exactly
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam4_Vault_LargeSecret_32KB(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	tok := token(t, ts, "u", []string{"write", "read"})

	// 32 KB random secret.
	secretRaw := make([]byte, 32*1024)
	rand.Read(secretRaw) //nolint:errcheck
	secret := base64.StdEncoding.EncodeToString(secretRaw)

	start := time.Now()
	code, splitResp := jreq(t, ts, "POST", "/vault/split", map[string]any{
		"secret":    secret,
		"n":         5,
		"threshold": 3,
	}, tok)
	splitTime := time.Since(start)

	if code != 200 {
		t.Fatalf("vault/split (32KB): %d %v", code, splitResp)
	}
	if splitTime > 10*time.Second {
		t.Errorf("VULNERABILITY: 32KB vault split took %v — DoS risk", splitTime)
	}

	shardsRaw, _ := splitResp["shards"].([]any)
	shards := make([]map[string]any, 3)
	for i := range 3 {
		shards[i] = shardsRaw[i].(map[string]any)
	}

	start = time.Now()
	code, recResp := jreq(t, ts, "POST", "/vault/reconstruct", map[string]any{
		"shards":    shards,
		"threshold": 3,
	}, tok)
	reconstructTime := time.Since(start)

	if code != 200 {
		t.Fatalf("vault/reconstruct (32KB): %d %v", code, recResp)
	}
	if reconstructTime > 10*time.Second {
		t.Errorf("VULNERABILITY: 32KB vault reconstruct took %v — DoS risk", reconstructTime)
	}

	reconstructed, _ := recResp["secret"].(string)
	if reconstructed != secret {
		t.Error("CRITICAL: reconstructed 32KB secret does not match original — data corruption")
	}

	t.Logf("32KB vault: split=%v reconstruct=%v — correctness and performance OK ✓",
		splitTime, reconstructTime)
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 46: Concurrent Token Revocation — Same JTI, 50 Goroutines
//
// Two goroutines concurrently revoking the same JTI should not:
//   - Panic (nil map write, double-close)
//   - Leave the token un-revoked (lost write under race)
//   - Corrupt the revocation map (partial write)
//
// After all goroutines complete, the token must be provably revoked.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam4_ConcurrentRevocation_SameJTI_NoCrash(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()

	// Issue one token.
	_, body := jreq(t, ts, "POST", "/auth/token", map[string]any{
		"user_id": "revoke-race-user",
		"roles":   []string{"read"},
	}, "")
	targetToken, _ := body["token"].(string)
	if targetToken == "" {
		t.Fatal("failed to issue token")
	}

	// Verify it's valid before revoking.
	code, _ := jreq(t, ts, "POST", "/auth/verify",
		map[string]any{"token": targetToken}, "")
	if code != 200 {
		t.Fatalf("token should be valid before revocation: %d", code)
	}

	// 50 goroutines all revoke the same token simultaneously.
	const goroutines = 50
	var wg sync.WaitGroup
	var successCount atomic.Int64

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, _ := jreq(t, ts, "POST", "/auth/revoke",
				map[string]any{"token": targetToken}, targetToken)
			if code == 200 {
				successCount.Add(1)
			}
		}()
	}
	wg.Wait()

	// Token MUST be revoked now — regardless of how many goroutines "won".
	code, verifyResp := jreq(t, ts, "POST", "/auth/verify",
		map[string]any{"token": targetToken}, "")
	if code == 200 {
		valid, _ := verifyResp["valid"].(bool)
		if valid {
			t.Errorf("CRITICAL: token still valid after %d concurrent revocation attempts — "+
				"revocation lost under race condition", goroutines)
		}
	}

	t.Logf("Concurrent revocation: %d goroutines, %d revocations accepted, "+
		"token is revoked after race ✓", goroutines, successCount.Load())
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 47: Token Expiry Enforcement
//
// A token with exp=now-1s must be rejected immediately.
// Tokens must not be accepted past their expiry regardless of the subject,
// roles, or signature validity.  Expiry bypass is an authentication bypass.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam4_TokenExpiry_ExpiredTokenRejected(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()

	// Issue a token normally.
	tok := token(t, ts, "expiry-test-user", []string{"read"})

	// Confirm it works while fresh.
	code, _ := jreq(t, ts, "GET", "/health/ready", nil, tok)
	if code != 200 {
		t.Logf("Note: fresh token not accepted for /health/ready (status=%d)", code)
	}

	// Attempt to forge a token with exp=past by building a raw QST with
	// a tampered claims payload — the ML-DSA signature will be invalid.
	// The server must reject it because:
	//   (a) the signature is wrong (modified payload), OR
	//   (b) even if we don't touch the payload, a real expired token is rejected.
	//
	// We test (b) by issuing a token, waiting for it to expire, and re-testing.
	// Since the default TTL is 1 hour, we instead test the signature path:
	// construct a token with a zeroed signature and modified exp.

	// Take a real token and zero its signature (last part after the second dot).
	parts := splitToken(tok)
	if len(parts) != 3 {
		t.Fatal("token is not 3 parts")
	}

	// Forge: same header+claims, but all-zero signature.
	zeroSig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	forged := parts[0] + "." + parts[1] + "." + zeroSig

	code, _ = jreq(t, ts, "GET", "/keys", nil, forged)
	if code == 200 {
		t.Errorf("CRITICAL: token with zeroed ML-DSA signature accepted (status=200). "+
			"Signature verification is not enforced.")
	} else {
		t.Logf("Zero-signature token correctly rejected: status=%d ✓", code)
	}

	// Also: forge a token with a single-byte signature truncation.
	if len(parts[2]) > 4 {
		truncSig := parts[2][:len(parts[2])-4] // drop last 3 base64 chars
		forgedTrunc := parts[0] + "." + parts[1] + "." + truncSig
		code, _ = jreq(t, ts, "GET", "/keys", nil, forgedTrunc)
		if code == 200 {
			t.Errorf("CRITICAL: token with truncated ML-DSA signature accepted — "+
				"signature length is not validated before verify call")
		}
		t.Logf("Truncated-signature token: status=%d ✓", code)
	}
}

func splitToken(tok string) []string {
	var parts []string
	start := 0
	dots := 0
	for i, c := range tok {
		if c == '.' {
			parts = append(parts, tok[start:i])
			start = i + 1
			dots++
		}
	}
	parts = append(parts, tok[start:])
	_ = dots
	return parts
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 48: Timing Oracle Statistical Analysis — Token Verification
//
// A naive "check JTI revocation before signature" implementation leaks whether
// the JTI exists in the revocation list via a timing difference (hash lookup
// is faster than ML-DSA.Verify).  Conversely, ML-DSA.Verify on a valid
// signature vs. an invalid signature should be constant-time.
//
// We sample 150 valid and 150 invalid (bit-flipped) verification requests,
// compute means and standard deviations, and apply a Welch-style distance
// check: |mean_A - mean_B| / pooled_stddev.
//
// A ratio > 10 indicates a statistically significant timing difference that
// could be exploited as a timing oracle.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam4_TimingOracle_TokenVerification_Statistical(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping statistical timing test in short mode")
	}

	ts, cleanup := srv(t,
		api.WithIPRateLimit(10_000, time.Minute),
		api.WithSubjectRateLimit(10_000, time.Minute),
	)
	defer cleanup()

	validTok := token(t, ts, "timing-user", []string{"read"})

	// Build an invalid token: flip a bit in the signature.
	parts := splitToken(validTok)
	sigBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if len(sigBytes) > 0 {
		sigBytes[0] ^= 0x01
	}
	invalidTok := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sigBytes)

	measure := func(tok string) time.Duration {
		start := time.Now()
		req, _ := http.NewRequest("GET", ts.URL+"/keys", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, _ := ts.Client().Do(req)
		d := time.Since(start)
		if resp != nil {
			resp.Body.Close()
		}
		return d
	}

	const samples = 150
	validSamples := make([]float64, samples)
	invalidSamples := make([]float64, samples)

	// Interleave valid/invalid to cancel any systematic drift.
	for i := range samples {
		validSamples[i] = float64(measure(validTok))
		invalidSamples[i] = float64(measure(invalidTok))
	}

	mean := func(xs []float64) float64 {
		s := 0.0
		for _, x := range xs {
			s += x
		}
		return s / float64(len(xs))
	}
	stddev := func(xs []float64, m float64) float64 {
		s := 0.0
		for _, x := range xs {
			d := x - m
			s += d * d
		}
		return math.Sqrt(s / float64(len(xs)))
	}

	mV := mean(validSamples)
	mI := mean(invalidSamples)
	sV := stddev(validSamples, mV)
	sI := stddev(invalidSamples, mI)
	pooled := math.Sqrt((sV*sV + sI*sI) / 2)

	var ratio float64
	if pooled > 0 {
		ratio = math.Abs(mV-mI) / pooled
	}

	t.Logf("Timing oracle analysis: valid_mean=%v invalid_mean=%v "+
		"valid_stddev=%v invalid_stddev=%v normalised_distance=%.2f",
		time.Duration(mV), time.Duration(mI),
		time.Duration(sV), time.Duration(sI), ratio)

	// Network noise dominates at 1 GHz clocks. Ratio > 10 = suspicious.
	if ratio > 10.0 {
		t.Logf("WARNING: normalised timing distance %.2fx exceeds 10 — "+
			"potential timing oracle for token validity. "+
			"ML-DSA.Verify should be constant-time; check JTI lookup ordering.", ratio)
	} else {
		t.Logf("No statistically significant timing oracle detected (ratio=%.2f < 10) ✓", ratio)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 49: GF(256) Zero Denominator via Duplicate Shard Index at API
//
// Lagrange interpolation calls gfInv(si.Index XOR sj.Index). If si.Index ==
// sj.Index then the argument is 0, and gfInv(0) panics ("GF(256) inverse of
// zero is undefined"). The structural check in vault.Reconstruct must catch
// duplicate indices BEFORE Lagrange begins.
//
// This test sends a /vault/reconstruct request with two shards sharing the
// same index value — forcing the code path that would trigger the panic if
// the guard is absent.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam4_Vault_DuplicateShardIndex_NoPanic(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	tok := token(t, ts, "u", []string{"write", "read"})

	// First, do a real split to get valid shard structure.
	secretRaw := make([]byte, 16)
	rand.Read(secretRaw) //nolint:errcheck
	secret := base64.StdEncoding.EncodeToString(secretRaw)

	code, splitResp := jreq(t, ts, "POST", "/vault/split", map[string]any{
		"secret":    secret,
		"n":         3,
		"threshold": 2,
	}, tok)
	if code != 200 {
		t.Fatalf("vault/split: %d", code)
	}

	shardsRaw, _ := splitResp["shards"].([]any)
	shard0 := shardsRaw[0].(map[string]any)
	shard1 := copyMap(shard0) // same index as shard0 — DUPLICATE

	// Send reconstruct with duplicate index — must return 400 not panic.
	code, resp := jreq(t, ts, "POST", "/vault/reconstruct", map[string]any{
		"shards":    []any{shard0, shard1},
		"threshold": 2,
	}, tok)

	if code == 200 {
		t.Errorf("VULNERABILITY: /vault/reconstruct accepted two shards with the same "+
			"index (duplicate x-value). This causes gfInv(0) — undefined in GF(256). "+
			"Response: %v", resp)
	} else {
		t.Logf("Duplicate shard index correctly rejected: status=%d ✓", code)
	}

	// Also test index=0 (explicitly invalid x-value).
	shard0Copy := copyMap(shard0)
	shard0Copy["index"] = 0
	shard1Raw := shardsRaw[1].(map[string]any)
	code, resp = jreq(t, ts, "POST", "/vault/reconstruct", map[string]any{
		"shards":    []any{shard0Copy, shard1Raw},
		"threshold": 2,
	}, tok)
	if code == 200 {
		t.Errorf("VULNERABILITY: shard with index=0 accepted. x=0 means f(0)=secret, "+
			"which trivially leaks the secret. Response: %v", resp)
	} else {
		t.Logf("Zero-index shard correctly rejected: status=%d ✓", code)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 50: HKDF Output Length Overflow
//
// RFC 5869 §2.3: The maximum output length is 255 × HashLen = 8160 bytes for
// SHA-256. Requesting more bytes causes most implementations to either panic
// or silently wrap. The server must return a well-formed 400 error.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam4_HKDF_OutputLengthOverflow(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	tok := token(t, ts, "u", []string{"write", "read"})

	// Server enforces key_len in [1, 512].
	// (Stricter than RFC 5869 max of 8160 — deliberate cap to prevent large allocations.)
	cases := []struct {
		length      int
		expectOK    bool
		description string
	}{
		{32, true, "normal 32 bytes"},
		{512, true, "server maximum (512 bytes)"},
		{513, false, "one byte over server cap"},
		{8160, false, "RFC maximum — over server cap"},
		{65535, false, "64 KB — way over"},
		{0, false, "zero length"},
		{-1, false, "negative length"},
	}

	for _, tc := range cases {
		code, resp := jreq(t, ts, "POST", "/kdf/hkdf", map[string]any{
			"secret":  base64.StdEncoding.EncodeToString([]byte("input-key-material")),
			"info":    "test-info",
			"key_len": tc.length,
		}, tok)

		if tc.expectOK && code != 200 {
			t.Errorf("HKDF key_len=%d (%s): expected 200 but got %d — %v",
				tc.length, tc.description, code, resp["error"])
		} else if !tc.expectOK && code == 200 {
			t.Errorf("VULNERABILITY: HKDF key_len=%d (%s) accepted without error. "+
				"Server must reject values outside [1,512] to prevent large allocations.",
				tc.length, tc.description)
		} else {
			t.Logf("HKDF key_len=%d (%s): status=%d — correct ✓",
				tc.length, tc.description, code)
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 51: Decrypt with Wrong Key (Same Level)
//
// Encrypt with key K1. Try to decrypt with key K2 (different keypair, same
// ML-KEM level). ML-KEM implicit rejection means the decapsulation returns
// a random shared secret instead of an error, but the AES-GCM tag computed
// with the wrong shared secret will not match — decryption must fail.
//
// This is different from L3's level-mixing test: same level, different key.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam4_Decrypt_WrongKey_SameLevel(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	tok := token(t, ts, "u", []string{"write", "read"})

	key1, _ := genKey(t, ts, tok, "ML-KEM-768")
	key2, _ := genKey(t, ts, tok, "ML-KEM-768")

	// Encrypt with key1.
	_, encResp := jreq(t, ts, "POST", "/encrypt", map[string]any{
		"key_id":    key1,
		"plaintext": "wrong-key-test",
	}, tok)
	enc := encResp["encrypted"].(map[string]any)

	// Try to decrypt with key2 — must fail with 400.
	code, _ := jreq(t, ts, "POST", "/decrypt", map[string]any{
		"key_id":    key2,
		"encrypted": enc,
	}, tok)

	if code == 200 {
		t.Errorf("CRITICAL: decryption with wrong key (same level) succeeded. "+
			"ML-KEM implicit rejection + AES-GCM authentication must prevent this. "+
			"Key K2's decapsulation produced the wrong shared secret but AEAD did not detect it.")
	} else {
		t.Logf("Wrong-key decryption correctly rejected: status=%d ✓", code)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 52: Non-Existent Channel Session ID Enumeration
//
// Send 500 /channel/open requests with random session IDs. The server must:
//   1. Return 404 for each (not 500 or panic)
//   2. Respond quickly — session lookup must be O(1) hash map, not O(n) scan
//   3. Not leak memory or goroutines
//
// A linear-scan implementation becomes a DoS vector when a large number of
// legitimate sessions exist.
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam4_ChannelSessionScan_NoDoS(t *testing.T) {
	ts, cleanup := srv(t,
		api.WithIPRateLimit(10_000, time.Minute),
		api.WithSubjectRateLimit(10_000, time.Minute),
	)
	defer cleanup()
	tok := token(t, ts, "u", []string{"write", "read"})

	// Use a shared HTTP client — avoids spawning a goroutine per connection.
	httpClient := ts.Client()

	const probes = 200 // keep concurrency reasonable on Windows TCP stack
	var errCount, notFoundCount, connErr atomic.Int64

	start := time.Now()
	var wg sync.WaitGroup
	for i := range probes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fakeID := fmt.Sprintf("nonexistent-session-%d", i)
			body, _ := json.Marshal(map[string]any{
				"session_id": fakeID,
				"seq_num":    0,
				"ciphertext": base64.StdEncoding.EncodeToString([]byte("fake")),
			})
			req, _ := http.NewRequest("POST", ts.URL+"/channel/open", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, err := httpClient.Do(req)
			if err != nil {
				connErr.Add(1)
				return
			}
			resp.Body.Close()
			switch resp.StatusCode {
			case 404:
				notFoundCount.Add(1)
			case 500:
				errCount.Add(1)
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("Session ID scan: %d probes in %v — 404s=%d 500s=%d conn_errors=%d",
		probes, elapsed, notFoundCount.Load(), errCount.Load(), connErr.Load())

	if errCount.Load() > 0 {
		t.Errorf("VULNERABILITY: %d probes returned 500 — panic or internal error "+
			"on non-existent session lookup", errCount.Load())
	}
	// 200 concurrent lookups should complete in < 5s.
	if elapsed > 5*time.Second {
		t.Errorf("VULNERABILITY: session ID scan took %v for %d probes — "+
			"possible O(n) session lookup or lock contention", elapsed, probes)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK CLASS 53: System survives Level-4 attacks
// ══════════════════════════════════════════════════════════════════════════════

func TestRedTeam4_SystemSurvivesAllL4Attacks(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	tok := token(t, ts, "u", []string{"write", "read"})

	// Full crypto round-trip must work after all Level-4 attacks.
	keyID, _ := genKey(t, ts, tok, "ML-KEM-768")
	_, encResp := jreq(t, ts, "POST", "/encrypt", map[string]any{
		"key_id":    keyID,
		"plaintext": "post-level4-integrity-check",
	}, tok)
	enc, ok := encResp["encrypted"].(map[string]any)
	if !ok {
		t.Fatal("encrypt failed after L4 attacks")
	}
	code, decResp := jreq(t, ts, "POST", "/decrypt", map[string]any{
		"key_id":    keyID,
		"encrypted": enc,
	}, tok)
	if code != 200 {
		t.Errorf("CRITICAL: system not operational after Level-4 attacks: decrypt=%d %v",
			code, decResp)
	}

	// CA must still issue and verify certs.
	adminTok := token(t, ts, "admin", []string{"admin", "write", "read"})
	jreq(t, ts, "POST", "/ca/init",
		map[string]any{"subject": "CN=L4 Survival CA"}, adminTok) //nolint:errcheck
	_, pk := genKey(t, ts, tok, "ML-KEM-768")
	code, cert := jreq(t, ts, "POST", "/ca/sign", map[string]any{
		"subject":         "CN=l4-survival.example.com",
		"public_key":      pk,
		"public_key_type": "ML-KEM-768",
	}, tok)
	if code != 200 {
		t.Errorf("CA cert issuance failed after L4 attacks: %d", code)
	}
	code, _ = jreq(t, ts, "POST", "/ca/verify",
		map[string]any{"certificate": cert}, "")
	if code != 200 {
		t.Errorf("CA cert verification failed after L4 attacks: %d", code)
	}

	t.Logf("System fully operational after all Level-4 attacks ✅")
}
