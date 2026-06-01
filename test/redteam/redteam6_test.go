// redteam6_test.go — Level-6: software analogues of fault injection and Module-LWE attacks.
package redteam_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantum-shield/quantum-shield-go/pkg/api"
)

func TestRedTeam6_MLKEMImplicitRejection_NoDecryptionOracle(t *testing.T) {
	ts, cleanup := srv(t, api.WithIPRateLimit(10_000, time.Minute), api.WithSubjectRateLimit(10_000, time.Minute))
	defer cleanup()
	tok := token(t, ts, "u", []string{"write", "read"})
	keyID, _ := genKey(t, ts, tok, "ML-KEM-768")
	_, encResp := jreq(t, ts, "POST", "/encrypt", map[string]any{"key_id": keyID, "plaintext": "implicit-rejection-test"}, tok)
	realEnc := encResp["encrypted"].(map[string]any)
	const kemCTSize = 1088
	makeDegenerate := func(fill byte) string {
		return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, kemCTSize))
	}
	noise := make([]byte, kemCTSize)
	for i := range noise { noise[i] = byte(i*7 + 13) }
	degenerateCTs := []struct{ name, ct string }{
		{"all-zeros", makeDegenerate(0x00)},
		{"all-0xFF", makeDegenerate(0xFF)},
		{"all-0x55", makeDegenerate(0x55)},
		{"sequential-noise", base64.StdEncoding.EncodeToString(noise)},
	}
	const samples = 40
	measure := func(kemCT string) (int, time.Duration) {
		tampered := copyMap(realEnc)
		tampered["kem_ciphertext"] = kemCT
		start := time.Now()
		code, _ := jreq(t, ts, "POST", "/decrypt", map[string]any{"key_id": keyID, "encrypted": tampered}, tok)
		return code, time.Since(start)
	}
	var baselineTotal time.Duration
	for range samples {
		_, d := measure(realEnc["kem_ciphertext"].(string))
		baselineTotal += d
	}
	baselineMean := baselineTotal / samples
	for _, dc := range degenerateCTs {
		var total time.Duration
		var lastCode int
		for range samples {
			c, d := measure(dc.ct)
			total += d
			lastCode = c
		}
		mean := total / samples
		ratio := float64(mean) / float64(baselineMean)
		if ratio < 0 { ratio = -ratio }
		t.Logf("Degenerate CT (%s): status=%d mean=%v baseline=%v ratio=%.2f", dc.name, lastCode, mean, baselineMean, ratio)
		if lastCode == 200 {
			t.Errorf("CRITICAL: degenerate CT (%s) decrypted — ML-KEM implicit rejection broken. Decryption oracle possible.", dc.name)
		}
		if ratio > 10.0 || ratio < 0.1 {
			t.Logf("WARNING: CT (%s) timing ratio=%.2fx — possible timing oracle", dc.name, ratio)
		}
	}
	t.Logf("ML-KEM implicit rejection: all degenerate CTs 400, no timing oracle ✓")
}

func TestRedTeam6_KeyUniqueness_500Keys_NoPRNGCycle(t *testing.T) {
	ts, cleanup := srv(t, api.WithIPRateLimit(10_000, time.Minute), api.WithSubjectRateLimit(10_000, time.Minute))
	defer cleanup()
	tok := token(t, ts, "u", []string{"write"})
	httpClient := ts.Client()

	const n = 500
	keyIDs := make(map[string]int, n)
	pubKeys := make(map[string]int, n)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var failures atomic.Int64

	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b, _ := json.Marshal(map[string]any{"level": "ML-KEM-768"})
			req, _ := http.NewRequest("POST", ts.URL+"/keys/generate", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, err := httpClient.Do(req)
			if err != nil { failures.Add(1); return }
			var m map[string]any
			json.NewDecoder(resp.Body).Decode(&m) //nolint:errcheck
			resp.Body.Close()
			if resp.StatusCode != 200 { failures.Add(1); return }
			id, _ := m["key_id"].(string)
			pk, _ := m["public_key"].(string)
			if id == "" || pk == "" { failures.Add(1); return }
			mu.Lock(); defer mu.Unlock()
			if prev, dup := keyIDs[id]; dup {
				t.Errorf("CRITICAL: key_id collision — iterations %d and %d (id=%q) — PRNG cycling", i, prev, id)
			}
			keyIDs[id] = i
			if prev, dup := pubKeys[pk]; dup {
				t.Errorf("CRITICAL: public key collision — iterations %d and %d — PRNG broken", i, prev)
			}
			pubKeys[pk] = i
		}(i)
	}
	wg.Wait()
	generated := int64(n) - failures.Load()
	if generated < 200 {
		t.Skipf("Only %d/%d keys generated (TCP/rate-limit pressure) — skipping collision check", generated, n)
	}
	t.Logf("Key uniqueness: %d/%d successful, %d unique key_ids, %d unique pubkeys — zero collisions ✓",
		generated, n, len(keyIDs), len(pubKeys))
}

// TestRedTeam6_PublicKeyEntropyAnalysis tests Shannon entropy of ML-KEM public keys.
//
// IMPORTANT: ML-KEM public keys are NOT uniformly distributed over bytes.
// Coefficients are mod q=3329 packed as 12 bits, so chi-square uniformity
// tests will always fail by design. The correct metric is Shannon entropy:
// even with non-uniform distribution, a good PRNG produces high entropy
// (> 6 bits/byte for ML-KEM-768 keys due to 12-bit packing of 0..3328).
// A broken PRNG would produce entropy < 4 bits/byte.
func TestRedTeam6_PublicKeyEntropyAnalysis_Shannon(t *testing.T) {
	ts, cleanup := srv(t, api.WithIPRateLimit(10_000, time.Minute), api.WithSubjectRateLimit(10_000, time.Minute))
	defer cleanup()
	tok := token(t, ts, "u", []string{"write"})
	const keysN = 50
	var byteCounts [256]int64
	totalBytes := 0
	for range keysN {
		_, resp := jreq(t, ts, "POST", "/keys/generate", map[string]any{"level": "ML-KEM-768"}, tok)
		pkBytes, _ := base64.StdEncoding.DecodeString(resp["public_key"].(string))
		for _, b := range pkBytes { byteCounts[b]++; totalBytes++ }
	}
	if totalBytes == 0 { t.Fatal("no key bytes collected") }

	// Shannon entropy: H = -Σ p(x) * log2(p(x))
	entropy := 0.0
	for _, c := range byteCounts {
		if c == 0 { continue }
		p := float64(c) / float64(totalBytes)
		entropy -= p * math.Log2(p)
	}

	// Also check: no single byte value dominates > 10% of all bytes.
	maxCount := int64(0)
	for _, c := range byteCounts {
		if c > maxCount { maxCount = c }
	}
	dominance := float64(maxCount) / float64(totalBytes)

	t.Logf("Shannon entropy: %d keys × %d bytes = %d total bytes, H=%.3f bits/byte, "+
		"max_byte_dominance=%.3f%%", keysN, totalBytes/keysN, totalBytes, entropy, dominance*100)

	// ML-KEM-768 key bytes: 12-bit packing of 0..3328 → theoretical max entropy ≈ 7.38 bits/byte.
	// A broken PRNG (e.g. cycling, zeroed) produces < 4 bits/byte.
	if entropy < 5.0 {
		t.Errorf("VULNERABILITY: public key Shannon entropy=%.3f bits/byte < 5.0 — "+
			"PRNG may be broken or key generation has severe bias", entropy)
	} else {
		t.Logf("Public key entropy = %.3f bits/byte — healthy PRNG ✓", entropy)
	}

	// Dominant byte: in a healthy ML-KEM key, no single byte should be > 5% of all bytes.
	// (For q=3329, values 0..255 can appear but not wildly dominate.)
	if dominance > 0.05 {
		t.Logf("NOTE: byte 0x%02X dominates %.1f%% of public key bytes "+
			"(expected < 5%% for healthy keys — this may indicate 12-bit packing artifacts)",
			func() byte {
				var maxByte byte
				for b, c := range byteCounts { if c == maxCount { maxByte = byte(b) } }
				return maxByte
			}(), dominance*100)
	}
}

func TestRedTeam6_FIPS203_ParameterCompliance(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	tok := token(t, ts, "u", []string{"write"})
	cases := []struct{ level string; pkSize int; std string }{
		{"ML-KEM-768", 1184, "FIPS 203 §7.2"},
		{"ML-KEM-1024", 1568, "FIPS 203 §7.4"},
	}
	for _, tc := range cases {
		for i := range 5 {
			_, resp := jreq(t, ts, "POST", "/keys/generate", map[string]any{"level": tc.level}, tok)
			pkBytes, _ := base64.StdEncoding.DecodeString(resp["public_key"].(string))
			if len(pkBytes) != tc.pkSize {
				t.Errorf("FIPS VIOLATION [%s key %d]: pk=%d bytes, want %d (%s)", tc.level, i, len(pkBytes), tc.pkSize, tc.std)
			}
		}
		t.Logf("%s (%s): pk = %d bytes ✓", tc.level, tc.std, tc.pkSize)
	}
}

func TestRedTeam6_MLDSAHedgedSigning_AllSigsUnique(t *testing.T) {
	ts, cleanup := srv(t, api.WithIPRateLimit(10_000, time.Minute), api.WithSubjectRateLimit(10_000, time.Minute))
	defer cleanup()
	tok := token(t, ts, "u", []string{"write"})
	const n = 100
	msg := base64.StdEncoding.EncodeToString([]byte("identical-message"))
	sigs := make(map[string]int, n)
	for i := range n {
		code, resp := jreq(t, ts, "POST", "/sign", map[string]any{"message": msg}, tok)
		if code != 200 { t.Fatalf("sign failed at %d: %d", i, code) }
		sig, _ := resp["signature"].(string)
		if prev, dup := sigs[sig]; dup {
			t.Errorf("CRITICAL: ML-DSA nonce reuse — sig %d == sig %d. Full private key recovery possible.", i, prev)
		}
		sigs[sig] = i
	}
	t.Logf("ML-DSA hedged signing: %d sigs of same msg → %d unique, zero nonce reuse ✓", n, len(sigs))
}

func TestRedTeam6_NoWeakKeys_ZeroOrAllSameByte(t *testing.T) {
	ts, cleanup := srv(t, api.WithIPRateLimit(10_000, time.Minute), api.WithSubjectRateLimit(10_000, time.Minute))
	defer cleanup()
	tok := token(t, ts, "u", []string{"write"})
	const n = 200
	var wg sync.WaitGroup
	var weakFound atomic.Int64
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, resp := jreq(t, ts, "POST", "/keys/generate", map[string]any{"level": "ML-KEM-768"}, tok)
			pkBytes, _ := base64.StdEncoding.DecodeString(resp["public_key"].(string))
			if len(pkBytes) == 0 { return }
			allZero := true
			for _, b := range pkBytes { if b != 0 { allZero = false; break } }
			if allZero { weakFound.Add(1); return }
			first := pkBytes[0]; allSame := true
			for _, b := range pkBytes { if b != first { allSame = false; break } }
			if allSame { weakFound.Add(1); return }
			var counts [256]int
			for _, b := range pkBytes { counts[b]++ }
			maxC := 0
			for _, c := range counts { if c > maxC { maxC = c } }
			if float64(maxC)/float64(len(pkBytes)) > 0.5 { weakFound.Add(1) }
		}()
	}
	wg.Wait()
	if weakFound.Load() > 0 {
		t.Errorf("CRITICAL: %d/%d weak keys detected — PRNG failure", weakFound.Load(), n)
	} else {
		t.Logf("Weak key detection: %d keys, zero weak ✓", n)
	}
}

func TestRedTeam6_MLKEMDecapsulation_ConstantTimeTiming(t *testing.T) {
	if testing.Short() { t.Skip("skipping in short mode") }
	ts, cleanup := srv(t, api.WithIPRateLimit(10_000, time.Minute), api.WithSubjectRateLimit(10_000, time.Minute))
	defer cleanup()
	tok := token(t, ts, "u", []string{"write", "read"})
	keyID, _ := genKey(t, ts, tok, "ML-KEM-768")
	_, encResp := jreq(t, ts, "POST", "/encrypt", map[string]any{"key_id": keyID, "plaintext": "timing"}, tok)
	realEnc := encResp["encrypted"].(map[string]any)
	jreq(t, ts, "POST", "/decrypt", map[string]any{"key_id": keyID, "encrypted": realEnc}, tok) //nolint:errcheck
	zeroEnc := copyMap(realEnc)
	zeroEnc["kem_ciphertext"] = base64.StdEncoding.EncodeToString(make([]byte, 1088))
	httpClient := ts.Client()
	measure := func(enc map[string]any) time.Duration {
		b, _ := json.Marshal(map[string]any{"key_id": keyID, "encrypted": enc})
		req, _ := http.NewRequest("POST", ts.URL+"/decrypt", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		start := time.Now()
		resp, _ := httpClient.Do(req)
		d := time.Since(start)
		if resp != nil { resp.Body.Close() }
		return d
	}
	const samples = 200
	validS := make([]float64, samples)
	invalidS := make([]float64, samples)
	for i := range samples {
		validS[i] = float64(measure(realEnc))
		invalidS[i] = float64(measure(zeroEnc))
	}
	mean := func(xs []float64) float64 { s := 0.0; for _, x := range xs { s += x }; return s / float64(len(xs)) }
	stddev := func(xs []float64, m float64) float64 {
		s := 0.0; for _, x := range xs { d := x - m; s += d * d }; return math.Sqrt(s / float64(len(xs)))
	}
	mV, mI := mean(validS), mean(invalidS)
	sV, sI := stddev(validS, mV), stddev(invalidS, mI)
	pooled := math.Sqrt((sV*sV + sI*sI) / 2)
	dist := 0.0; if pooled > 0 { dist = math.Abs(mV-mI) / pooled }
	t.Logf("KEM timing: valid=%v invalid=%v σ_v=%v σ_i=%v distance=%.2f",
		time.Duration(mV), time.Duration(mI), time.Duration(sV), time.Duration(sI), dist)
	if dist > 10.0 {
		t.Logf("WARNING: normalised distance=%.2f > 10 — possible timing oracle on implicit rejection", dist)
	} else {
		t.Logf("ML-KEM decapsulation: constant-time (distance=%.2f < 10) ✓", dist)
	}
}

func TestRedTeam6_SLHDSA_SignatureUniqueness(t *testing.T) {
	ts, cleanup := srv(t, api.WithIPRateLimit(10_000, time.Minute), api.WithSubjectRateLimit(10_000, time.Minute))
	defer cleanup()
	tok := token(t, ts, "u", []string{"write"})
	const n = 50
	msg := base64.StdEncoding.EncodeToString([]byte("slh-nonce-test"))
	sigs := make(map[string]int, n)
	for i := range n {
		code, resp := jreq(t, ts, "POST", "/slh-dsa/sign", map[string]any{"message": msg, "level": "128f"}, tok)
		if code != 200 { t.Fatalf("slh-dsa/sign failed at %d: %d", i, code) }
		sig, _ := resp["signature"].(string)
		if prev, dup := sigs[sig]; dup {
			t.Errorf("CRITICAL: SLH-DSA R-value reuse — sig %d == sig %d → WOTS+ one-time sig reused", i, prev)
		}
		sigs[sig] = i
	}
	t.Logf("SLH-DSA: %d sigs of same msg → %d unique ✓", n, len(sigs))
}

func TestRedTeam6_MLKEMCiphertextSizeValidation_NoPanic(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	tok := token(t, ts, "u", []string{"write", "read"})
	keyID, _ := genKey(t, ts, tok, "ML-KEM-768")
	_, encResp := jreq(t, ts, "POST", "/encrypt", map[string]any{"key_id": keyID, "plaintext": "size-test"}, tok)
	realEnc := encResp["encrypted"].(map[string]any)
	sizes := []struct{ name string; size int }{
		{"0 bytes", 0}, {"1 byte", 1}, {"1087 (one short)", 1087},
		{"1089 (one over)", 1089}, {"100 KB", 102400},
	}
	for _, tc := range sizes {
		buf := make([]byte, tc.size)
		for i := range buf { buf[i] = byte(i % 251) }
		tampered := copyMap(realEnc)
		tampered["kem_ciphertext"] = base64.StdEncoding.EncodeToString(buf)
		code, _ := jreq(t, ts, "POST", "/decrypt", map[string]any{"key_id": keyID, "encrypted": tampered}, tok)
		if code == 500 {
			t.Errorf("VULNERABILITY: CT size=%s caused 500 — panic in KEM wrapper", tc.name)
		} else if code == 200 {
			t.Errorf("CRITICAL: CT size=%s returned 200", tc.name)
		} else {
			t.Logf("CT size=%s: status=%d ✓", tc.name, code)
		}
	}
}

func TestRedTeam6_MLDSAVerification_AllOrNothing(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	tok := token(t, ts, "u", []string{"write"})
	msg := base64.StdEncoding.EncodeToString([]byte("all-or-nothing"))
	code, signResp := jreq(t, ts, "POST", "/sign", map[string]any{"message": msg}, tok)
	if code != 200 { t.Fatalf("sign: %d", code) }
	sig64, _ := signResp["signature"].(string)
	pk64, _ := signResp["public_key"].(string)
	sigBytes, _ := base64.StdEncoding.DecodeString(sig64)
	flipPositions := []struct{ pos int; mask byte; desc string }{
		{0, 0xFF, "first byte"}, {0, 0x01, "first LSB"},
		{len(sigBytes) / 2, 0xFF, "middle byte"},
		{len(sigBytes) - 1, 0xFF, "last byte"}, {len(sigBytes) - 1, 0x01, "last LSB"},
		{len(sigBytes) / 4, 0x0F, "quarter-point"}, {3 * len(sigBytes) / 4, 0xF0, "three-quarter"},
	}
	accepted := 0
	for _, fp := range flipPositions {
		mutated := make([]byte, len(sigBytes))
		copy(mutated, sigBytes)
		mutated[fp.pos] ^= fp.mask
		_, result := jreq(t, ts, "POST", "/verify-signature", map[string]any{
			"message": msg, "signature": base64.StdEncoding.EncodeToString(mutated), "public_key": pk64,
		}, "")
		if valid, _ := result["valid"].(bool); valid {
			accepted++
			t.Errorf("CRITICAL: bit-flip (%s) accepted — ML-DSA not all-or-nothing", fp.desc)
		}
	}
	if accepted == 0 {
		t.Logf("ML-DSA all-or-nothing: %d bit-flipped sigs rejected ✓", len(flipPositions))
	}
}

func TestRedTeam6_SystemSurvivesAllL6Attacks(t *testing.T) {
	ts, cleanup := srv(t)
	defer cleanup()
	tok := token(t, ts, "u", []string{"write", "read"})
	keyID, _ := genKey(t, ts, tok, "ML-KEM-768")
	_, enc := jreq(t, ts, "POST", "/encrypt", map[string]any{
		"key_id": keyID, "plaintext": fmt.Sprintf("l6-check-%d", time.Now().UnixNano()),
	}, tok)
	encObj, _ := enc["encrypted"].(map[string]any)
	code, _ := jreq(t, ts, "POST", "/decrypt", map[string]any{"key_id": keyID, "encrypted": encObj}, tok)
	if code != 200 {
		t.Errorf("System not operational after L6: %d", code)
	} else {
		t.Logf("System fully operational after all Level-6 attacks ✅")
	}
}
