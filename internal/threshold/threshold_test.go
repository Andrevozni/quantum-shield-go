package threshold_test

import (
	"sync"
	"testing"

	"github.com/quantum-shield/quantum-shield-go/internal/threshold"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func trustedMap(tb testing.TB, signers []*threshold.Signer) map[string][]byte {
	tb.Helper()
	m := make(map[string][]byte)
	for _, s := range signers {
		pk, err := s.PublicKeyBytes()
		if err != nil {
			tb.Fatalf("PublicKeyBytes: %v", err)
		}
		m[s.ID()] = pk
	}
	return m
}

func makeSigners(t *testing.T, n int) []*threshold.Signer {
	t.Helper()
	signers := make([]*threshold.Signer, n)
	for i := range n {
		id := string(rune('A' + i))
		s, err := threshold.NewSigner(id)
		if err != nil {
			t.Fatalf("NewSigner(%q): %v", id, err)
		}
		signers[i] = s
	}
	return signers
}

// doRound runs a full signing round: all signers sign, coordinator collects.
// Returns the AuthorisedSignature once threshold is reached.
func doRound(t *testing.T, msg []byte, signers []*threshold.Signer, threshold_ int) *threshold.AuthorisedSignature {
	t.Helper()
	nonce, err := threshold.NewNonce()
	if err != nil {
		t.Fatalf("NewNonce: %v", err)
	}
	coord, err := threshold.NewCoordinator(msg, nonce, threshold_)
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	for _, s := range signers {
		partial, err := s.Sign(msg, nonce)
		if err != nil {
			t.Fatalf("Sign(%q): %v", s.ID(), err)
		}
		done, auth, err := coord.Submit(partial)
		if err != nil {
			t.Fatalf("Submit(%q): %v", s.ID(), err)
		}
		if done {
			return auth
		}
	}
	t.Fatal("threshold not reached")
	return nil
}

// ── Correctness ───────────────────────────────────────────────────────────────

func TestThreshold_3of5(t *testing.T) {
	signers := makeSigners(t, 5)
	msg := []byte("Authorise transfer of EUR 500,000 — ref TX-2025-001")
	auth := doRound(t, msg, signers[:3], 3)
	if auth == nil {
		t.Fatal("auth must not be nil")
	}
	if auth.Threshold != 3 {
		t.Errorf("threshold: got %d, want 3", auth.Threshold)
	}
	if len(auth.Partials) != 3 {
		t.Errorf("partials: got %d, want 3", len(auth.Partials))
	}
}

func TestThreshold_1of1(t *testing.T) {
	signers := makeSigners(t, 1)
	msg := []byte("single-approver action")
	auth := doRound(t, msg, signers, 1)
	if auth == nil {
		t.Fatal("auth must not be nil")
	}
}

func TestThreshold_NofN(t *testing.T) {
	const n = 5
	signers := makeSigners(t, n)
	msg := []byte("unanimous decision")
	auth := doRound(t, msg, signers, n)
	if len(auth.Partials) != n {
		t.Errorf("expected %d partials, got %d", n, len(auth.Partials))
	}
}

func TestVerify_ValidBundle(t *testing.T) {
	signers := makeSigners(t, 5)
	msg := []byte("approved action")
	auth := doRound(t, msg, signers, 3)
	trusted := trustedMap(t, signers)
	if err := threshold.Verify(msg, auth, trusted); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

func TestVerify_WrongMessage(t *testing.T) {
	signers := makeSigners(t, 3)
	msg := []byte("original message")
	auth := doRound(t, msg, signers, 3)
	trusted := trustedMap(t, signers)
	err := threshold.Verify([]byte("TAMPERED"), auth, trusted)
	if err == nil {
		t.Fatal("Verify must reject wrong message")
	}
}

func TestVerify_UntrustedSigner(t *testing.T) {
	signers := makeSigners(t, 3)
	msg := []byte("action")
	auth := doRound(t, msg, signers, 3)
	// Don't add signer[2] to trusted
	trusted := trustedMap(t, signers[:2])
	err := threshold.Verify(msg, auth, trusted)
	if err == nil {
		t.Fatal("Verify must reject signer not in trusted registry")
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	signers := makeSigners(t, 3)
	msg := []byte("action")
	auth := doRound(t, msg, signers, 3)
	auth.Partials[0].Signature[0] ^= 0xFF
	trusted := trustedMap(t, signers)
	err := threshold.Verify(msg, auth, trusted)
	if err == nil {
		t.Fatal("Verify must reject tampered signature")
	}
}

func TestVerify_NilAuth(t *testing.T) {
	err := threshold.Verify([]byte("msg"), nil, nil)
	if err == nil {
		t.Fatal("Verify must reject nil AuthorisedSignature")
	}
}

// ── Coordinator: adversarial ──────────────────────────────────────────────────

func TestCoordinator_DuplicateSigner(t *testing.T) {
	signers := makeSigners(t, 3)
	msg := []byte("test")
	nonce, _ := threshold.NewNonce()
	coord, _ := threshold.NewCoordinator(msg, nonce, 3)

	p, _ := signers[0].Sign(msg, nonce)
	coord.Submit(p)
	_, _, err := coord.Submit(p) // submit again
	if err == nil {
		t.Fatal("duplicate signer submission must be rejected")
	}
}

func TestCoordinator_WrongNonce(t *testing.T) {
	signers := makeSigners(t, 2)
	msg := []byte("test")
	nonce1, _ := threshold.NewNonce()
	nonce2, _ := threshold.NewNonce()

	coord, _ := threshold.NewCoordinator(msg, nonce1, 2)
	p, _ := signers[0].Sign(msg, nonce2) // signed with wrong nonce
	_, _, err := coord.Submit(p)
	if err == nil {
		t.Fatal("wrong nonce must be rejected")
	}
}

func TestCoordinator_InvalidPartialSignature(t *testing.T) {
	signers := makeSigners(t, 2)
	msg := []byte("test")
	nonce, _ := threshold.NewNonce()
	coord, _ := threshold.NewCoordinator(msg, nonce, 2)

	p, _ := signers[0].Sign(msg, nonce)
	p.Signature[0] ^= 0xFF // corrupt
	_, _, err := coord.Submit(p)
	if err == nil {
		t.Fatal("invalid partial signature must be rejected")
	}
}

func TestCoordinator_NotEnoughSigners(t *testing.T) {
	signers := makeSigners(t, 5)
	msg := []byte("action")
	nonce, _ := threshold.NewNonce()
	coord, _ := threshold.NewCoordinator(msg, nonce, 3)

	for _, s := range signers[:2] {
		p, _ := s.Sign(msg, nonce)
		done, auth, err := coord.Submit(p)
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		if done || auth != nil {
			t.Fatal("threshold must not be reached with only 2 signers")
		}
	}
	if coord.Count() != 2 {
		t.Errorf("expected count=2, got %d", coord.Count())
	}
}

func TestSigner_EmptyMessage(t *testing.T) {
	s, _ := threshold.NewSigner("A")
	nonce, _ := threshold.NewNonce()
	_, err := s.Sign([]byte{}, nonce)
	if err == nil {
		t.Error("empty message must be rejected")
	}
}

func TestSigner_EmptyID(t *testing.T) {
	_, err := threshold.NewSigner("")
	if err == nil {
		t.Error("empty signer ID must be rejected")
	}
}

// ── Concurrency ───────────────────────────────────────────────────────────────

func TestConcurrentSubmit(t *testing.T) {
	const n = 20
	signers := makeSigners(t, n)
	msg := []byte("concurrent approval")
	nonce, _ := threshold.NewNonce()
	coord, _ := threshold.NewCoordinator(msg, nonce, 10)

	var wg sync.WaitGroup
	var authMu sync.Mutex
	var finalAuth *threshold.AuthorisedSignature

	partials := make([]*threshold.PartialSignature, n)
	for i, s := range signers {
		p, err := s.Sign(msg, nonce)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		partials[i] = p
	}

	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			done, auth, err := coord.Submit(partials[i])
			if err != nil {
				// Might fail for signers after threshold reached — that's fine
				return
			}
			if done && auth != nil {
				authMu.Lock()
				if finalAuth == nil {
					finalAuth = auth
				}
				authMu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if finalAuth == nil {
		t.Fatal("threshold must be reached concurrently")
	}
	trusted := trustedMap(t, signers)
	if err := threshold.Verify(msg, finalAuth, trusted); err != nil {
		t.Fatalf("concurrent auth failed verification: %v", err)
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

func BenchmarkSign(b *testing.B) {
	s, _ := threshold.NewSigner("bench")
	msg := []byte("benchmark message for threshold signing")
	nonce, _ := threshold.NewNonce()
	b.ResetTimer()
	for b.Loop() {
		s.Sign(msg, nonce)
	}
}

func BenchmarkVerify3of5(b *testing.B) {
	signers := make([]*threshold.Signer, 5)
	for i := range 5 {
		signers[i], _ = threshold.NewSigner(string(rune('A' + i)))
	}
	msg := []byte("bench approval message")
	nonce, _ := threshold.NewNonce()
	coord, _ := threshold.NewCoordinator(msg, nonce, 3)
	var auth *threshold.AuthorisedSignature
	for _, s := range signers {
		p, _ := s.Sign(msg, nonce)
		done, a, _ := coord.Submit(p)
		if done {
			auth = a
			break
		}
	}
	trusted := trustedMap(b, signers)
	b.ResetTimer()
	for b.Loop() {
		threshold.Verify(msg, auth, trusted)
	}
}

