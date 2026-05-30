// White-box tests for GF(256) arithmetic — package vault (not vault_test)
// to access unexported gfMul and gfInv.
//
// # Side-channel / timing-attack rationale
//
// The original gfMul implementation had two data-dependent branches:
//
//	if b&1 != 0 { result ^= a }      // branch on plaintext bit
//	if carry != 0 { a ^= 0x1b }      // branch on intermediate value
//
// and a data-dependent loop:
//
//	for b > 0 { b >>= 1 }            // exits early when b becomes 0
//
// These allow a timing adversary to distinguish multiplication by 0x01 from
// multiplication by 0xFF (1 vs 8 loop iterations), and to recover secret
// polynomial coefficients via differential timing on Reconstruct().
//
// The fixed implementation uses:
//   - Fixed 8 iterations (loop count never depends on data)
//   - mask  = byte(0) - (b & 1)  →  0xFF when bit=1, 0x00 when bit=0
//   - carry = byte(0) - (a >> 7) →  0xFF when MSB=1, 0x00 when MSB=0
//
// Both of the above use unsigned arithmetic wrap-around (uint8); the CPU
// executes the subtraction regardless of the value — no branch prediction
// path divergence.
//
// The timing benchmarks below measure the wall-clock difference between
// worst-case (0xFF × 0xFF) and best-case (0x01 × 0x01) operand pairs.
// With the constant-time implementation both should land within noise.
package vault

import (
	"math"
	"testing"
	"time"
)

// ── Known-vector correctness tests ────────────────────────────────────────────

// gfVectors are (a, b, expected) triples derived from NIST FIPS 197
// Appendix B (MixColumns example) and the AES xtime function.
//
// gfMul(0x57, 0x83) = 0xC1 is the canonical FIPS 197 verification vector.
var gfVectors = []struct {
	a, b, want byte
	name       string
}{
	// FIPS 197 verification vector
	{0x57, 0x83, 0xC1, "FIPS197_0x57_0x83"},

	// xtime(x) = multiply by 0x02 (shift left, reduce if overflow)
	{0x02, 0x63, 0xC6, "xtime_0x63"},     // 0x63 MSB=0, no reduction
	{0x02, 0x80, 0x1b, "xtime_0x80"},     // 0x80 MSB=1, reduction: (0x80<<1)^0x1b
	{0x02, 0xFF, 0xE5, "xtime_0xFF"},     // 0xFF: shift=0xFE, reduction: 0xFE^0x1b=0xE5... actually: 0xFF>>7=1 so 0xFF<<1 as byte=0xFE, 0xFE^0x1b=0xE5

	// 3×x = xtime(x) XOR x  (used in MixColumns for coefficient 3)
	{0x03, 0x63, 0xA5, "mixcol_3x0x63"}, // 0xC6 XOR 0x63 = 0xA5

	// Identity: a×1 = a
	{0x01, 0x00, 0x00, "identity_0x00"},
	{0x01, 0x57, 0x57, "identity_0x57"},
	{0x01, 0xFF, 0xFF, "identity_0xFF"},

	// Zero: a×0 = 0
	{0x00, 0x00, 0x00, "zero_mul_zero"},
	{0xFF, 0x00, 0x00, "0xFF_mul_zero"},
	{0x57, 0x00, 0x00, "0x57_mul_zero"},

	// Commutativity spot-checks: gfMul(a,b) == gfMul(b,a)
	// (verified by running both and comparing, not hard-coded)
}

func TestGFMul_KnownVectors(t *testing.T) {
	for _, tc := range gfVectors {
		got := gfMul(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("gfMul(0x%02X, 0x%02X) = 0x%02X, want 0x%02X [%s]",
				tc.a, tc.b, got, tc.want, tc.name)
		}
	}
}

func TestGFMul_Commutativity(t *testing.T) {
	// GF(256) multiplication is commutative: a·b = b·a
	pairs := [][2]byte{
		{0x57, 0x83}, {0x02, 0x63}, {0xFF, 0xAA},
		{0x13, 0x7F}, {0x80, 0x80}, {0x01, 0xCC},
	}
	for _, p := range pairs {
		a, b := p[0], p[1]
		ab := gfMul(a, b)
		ba := gfMul(b, a)
		if ab != ba {
			t.Errorf("gfMul(0x%02X,0x%02X)=0x%02X ≠ gfMul(0x%02X,0x%02X)=0x%02X — commutativity violated",
				a, b, ab, b, a, ba)
		}
	}
}

func TestGFMul_Associativity(t *testing.T) {
	// GF(256) multiplication is associative: (a·b)·c = a·(b·c)
	triples := [][3]byte{
		{0x02, 0x03, 0x57},
		{0xFF, 0xAA, 0x55},
		{0x13, 0x7F, 0x01},
	}
	for _, tri := range triples {
		a, b, c := tri[0], tri[1], tri[2]
		lhs := gfMul(gfMul(a, b), c)
		rhs := gfMul(a, gfMul(b, c))
		if lhs != rhs {
			t.Errorf("(0x%02X·0x%02X)·0x%02X = 0x%02X ≠ 0x%02X = 0x%02X·(0x%02X·0x%02X)",
				a, b, c, lhs, rhs, a, b, c)
		}
	}
}

func TestGFMul_Distributivity(t *testing.T) {
	// GF(256): a·(b XOR c) = (a·b) XOR (a·c)
	cases := [][3]byte{
		{0x02, 0x57, 0x83},
		{0xFF, 0x0F, 0xF0},
		{0x13, 0xAA, 0x55},
	}
	for _, tri := range cases {
		a, b, c := tri[0], tri[1], tri[2]
		lhs := gfMul(a, b^c)
		rhs := gfMul(a, b) ^ gfMul(a, c)
		if lhs != rhs {
			t.Errorf("0x%02X·(0x%02X⊕0x%02X): 0x%02X ≠ 0x%02X",
				a, b, c, lhs, rhs)
		}
	}
}

// ── Inverse correctness ───────────────────────────────────────────────────────

func TestGFInv_MultipliesBackToOne(t *testing.T) {
	// For every non-zero a: gfMul(a, gfInv(a)) == 1
	for a := 1; a <= 255; a++ {
		inv := gfInv(byte(a))
		if gfMul(byte(a), inv) != 0x01 {
			t.Errorf("gfMul(0x%02X, gfInv(0x%02X)) = 0x%02X, want 0x01",
				a, a, gfMul(byte(a), inv))
		}
	}
}

func TestGFInv_Involution(t *testing.T) {
	// gfInv(gfInv(a)) == a for all non-zero a
	for a := 1; a <= 255; a++ {
		if gfInv(gfInv(byte(a))) != byte(a) {
			t.Errorf("gfInv(gfInv(0x%02X)) ≠ 0x%02X", a, a)
		}
	}
}

func TestGFInv_ZeroPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("gfInv(0) must panic — inverse of zero is undefined in GF(256)")
		}
	}()
	gfInv(0)
}

// ── Full-table exhaustive correctness ─────────────────────────────────────────

func TestGFMul_ExhaustiveDistributivity(t *testing.T) {
	// Verify a*(b XOR c) == a*b XOR a*c for all 256 values of a.
	// Uses a fixed (b, c) pair to keep the test fast but meaningful.
	b, c := byte(0x57), byte(0x83)
	for a := 0; a <= 255; a++ {
		lhs := gfMul(byte(a), b^c)
		rhs := gfMul(byte(a), b) ^ gfMul(byte(a), c)
		if lhs != rhs {
			t.Fatalf("distributivity failed at a=0x%02X: 0x%02X ≠ 0x%02X", a, lhs, rhs)
		}
	}
}

// ── Timing / side-channel tests ───────────────────────────────────────────────
//
// Formal timing-attack proof requires hardware counters (perf, eBPF) and
// controlled lab conditions. The tests here serve as regression guards and
// documentation of the constant-time property:
//
//  1. BenchmarkGFMul_WorstCase and BenchmarkGFMul_BestCase should show the
//     same ns/op in CI — data-dependent variation would be a red flag.
//
//  2. TestGFMul_TimingVariance measures wall-clock standard deviation across
//     ten input pairs. A branchless implementation should keep σ/μ < 50%.
//     (Higher tolerance than lab conditions — Go's goroutine scheduler
//     introduces noise; this is a smoke test, not a formal proof.)

func TestGFMul_TimingVariance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}

	const iterations = 500_000

	// Input pairs spanning the full operand space:
	//   best-case: b=0x01 (mask fires once, seven 0x00 masks)
	//   worst-case: b=0xFF (all eight masks fire, all carry branches active)
	inputPairs := [][2]byte{
		{0xFF, 0xFF}, // all bits set — every iteration active
		{0x01, 0x01}, // minimal bits — only first iteration active
		{0xAA, 0x55}, // alternating bits
		{0x00, 0xFF}, // zero × anything = 0
		{0xFF, 0x00}, // anything × zero = 0
		{0x57, 0x83}, // FIPS 197 vector
	}

	times := make([]float64, len(inputPairs))
	for i, pair := range inputPairs {
		a, b := pair[0], pair[1]
		start := time.Now()
		for k := 0; k < iterations; k++ {
			_ = gfMul(a, b)
		}
		elapsed := time.Since(start)
		times[i] = float64(elapsed.Nanoseconds()) / float64(iterations)
	}

	// Compute mean and standard deviation of ns/op across input pairs.
	var sum float64
	for _, v := range times {
		sum += v
	}
	mean := sum / float64(len(times))

	var variance float64
	for _, v := range times {
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(times))
	stddev := math.Sqrt(variance)
	cv := stddev / mean // coefficient of variation

	t.Logf("gfMul timing across %d input pairs: mean=%.2fns/op stddev=%.2fns/op CV=%.1f%%",
		len(inputPairs), mean, stddev, cv*100)

	// A constant-time implementation should have low coefficient of variation.
	// Threshold of 50% is deliberately loose to tolerate OS scheduler noise
	// in CI. Tighten to 20% in a dedicated perf lab.
	const maxCV = 0.50
	if cv > maxCV {
		t.Errorf("timing coefficient of variation %.1f%% exceeds threshold %.0f%% — "+
			"possible data-dependent execution path in gfMul", cv*100, maxCV*100)
	}
}

// BenchmarkGFMul_BestCase benchmarks the operand pair with fewest active bits.
// Compare with BenchmarkGFMul_WorstCase — ns/op must be within noise.
func BenchmarkGFMul_BestCase(b *testing.B) {
	for b.Loop() {
		_ = gfMul(0x01, 0x01)
	}
}

// BenchmarkGFMul_WorstCase benchmarks the operand pair with all bits set.
// Compare with BenchmarkGFMul_BestCase — ns/op must be within noise.
func BenchmarkGFMul_WorstCase(b *testing.B) {
	for b.Loop() {
		_ = gfMul(0xFF, 0xFF)
	}
}

// BenchmarkGFMul_ZeroOperand benchmarks multiplication by zero (result always 0).
func BenchmarkGFMul_ZeroOperand(b *testing.B) {
	for b.Loop() {
		_ = gfMul(0xFF, 0x00)
	}
}

// BenchmarkGFInv runs gfInv across a rotating set of non-zero inputs.
func BenchmarkGFInv(b *testing.B) {
	i := byte(1)
	for b.Loop() {
		_ = gfInv(i)
		if i == 255 {
			i = 1
		} else {
			i++
		}
	}
}
