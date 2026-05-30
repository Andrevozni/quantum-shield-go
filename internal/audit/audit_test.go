package audit_test

import (
	"sync"
	"testing"

	"github.com/quantum-shield/quantum-shield-go/internal/audit"
)

func newLogger(t *testing.T) *audit.Logger {
	t.Helper()
	l, err := audit.NewLogger("TestService")
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	return l
}

// ── Correctness ───────────────────────────────────────────────────────────────

func TestBasicLog(t *testing.T) {
	l := newLogger(t)
	if err := l.Log("alice", "transfer", "approved", "acc-001"); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if l.Count() != 1 {
		t.Fatalf("expected 1 entry, got %d", l.Count())
	}
	entries := l.Entries()
	if entries[0].Actor != "alice" {
		t.Errorf("actor: got %q", entries[0].Actor)
	}
	if entries[0].Hash == "" {
		t.Error("hash must not be empty")
	}
	if entries[0].Signature == "" {
		t.Error("signature must not be empty")
	}
}

func TestChainIntegrity(t *testing.T) {
	l := newLogger(t)
	for i := range 20 {
		if err := l.Log("user", "action", "ok", string(rune('A'+i))); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}
	result := l.VerifyChain()
	if !result.Valid {
		t.Fatalf("chain invalid: %s", result.Message)
	}
	if result.Entries != 20 {
		t.Errorf("expected 20 entries, got %d", result.Entries)
	}
}

func TestEmptyLogIntegrity(t *testing.T) {
	l := newLogger(t)
	result := l.VerifyChain()
	if !result.Valid {
		t.Fatalf("empty log should be valid: %s", result.Message)
	}
}

func TestHashChainLinks(t *testing.T) {
	l := newLogger(t)
	for range 5 {
		l.Log("alice", "read", "ok", "res-1")
	}
	entries := l.Entries()
	for i := 1; i < len(entries); i++ {
		if entries[i].PrevHash != entries[i-1].Hash {
			t.Errorf("entry %d: PrevHash does not match entry %d Hash", i, i-1)
		}
	}
}

// ── Tamper detection ──────────────────────────────────────────────────────────

func TestTamperedActor(t *testing.T) {
	l := newLogger(t)
	l.Log("alice", "transfer", "approved", "acc-001")
	l.Log("bob", "read", "ok", "acc-002")
	l.Log("carol", "login", "ok", "")

	// Tamper entry 0: change actor after the fact
	if err := audit.TamperEntry(l, 0, "hacker"); err != nil {
		t.Fatal(err)
	}

	result := l.VerifyChain()
	if result.Valid {
		t.Fatal("tampered log should fail integrity check")
	}
	if !result.ChainBroken {
		t.Fatal("chain should be marked as broken")
	}
	if result.BrokenAt != 0 {
		t.Errorf("expected break at entry 0, got %d", result.BrokenAt)
	}
}

func TestTamperedMiddleEntry(t *testing.T) {
	l := newLogger(t)
	for i := range 10 {
		l.Log("user", "action", "ok", string(rune('A'+i)))
	}
	// Tamper entry 5
	audit.TamperEntry(l, 5, "hacker")
	result := l.VerifyChain()
	if result.Valid {
		t.Fatal("tampered middle entry should break chain")
	}
	if result.BrokenAt > 6 { // break at 5 or 6 (hash or chain check)
		t.Errorf("expected break near entry 5, got %d", result.BrokenAt)
	}
}

// ── Concurrency ───────────────────────────────────────────────────────────────

func TestConcurrentLogging(t *testing.T) {
	l := newLogger(t)
	const goroutines = 100
	var wg sync.WaitGroup
	errc := make(chan error, goroutines)

	wg.Add(goroutines)
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			errc <- l.Log("user", "action", "ok", string(rune('A'+i%26)))
		}(i)
	}
	wg.Wait()
	close(errc)

	for err := range errc {
		if err != nil {
			t.Errorf("concurrent Log error: %v", err)
		}
	}
	if l.Count() != goroutines {
		t.Errorf("expected %d entries, got %d", goroutines, l.Count())
	}

	result := l.VerifyChain()
	if !result.Valid {
		t.Fatalf("concurrent log chain invalid: %s", result.Message)
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

func BenchmarkLog(b *testing.B) {
	l, _ := audit.NewLogger("BenchService")
	b.ResetTimer()
	for b.Loop() {
		l.Log("alice", "transfer", "approved", "acc-001")
	}
}

func BenchmarkVerifyChain100(b *testing.B) {
	l, _ := audit.NewLogger("BenchService")
	for range 100 {
		l.Log("alice", "action", "ok", "res")
	}
	b.ResetTimer()
	for b.Loop() {
		l.VerifyChain()
	}
}
