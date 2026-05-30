// Package audit implements a tamper-evident audit log.
//
// Security properties:
//   - SHA-256 hash chain: each entry includes hash of previous entry
//   - Breaking any entry invalidates all subsequent entries
//   - ML-DSA signature on each entry (non-repudiation)
//   - Append-only: no delete or modify operations
//   - Thread-safe: safe for concurrent logging
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/quantum-shield/quantum-shield-go/internal/dsa"
)

// Entry is one immutable record in the audit log.
type Entry struct {
	Sequence  uint64 `json:"seq"`           // monotonically increasing
	Timestamp int64  `json:"ts"`            // Unix nanoseconds
	Service   string `json:"service"`       // source service name
	Actor     string `json:"actor"`         // who performed the action
	Action    string `json:"action"`        // what was done
	Result    string `json:"result"`        // outcome: "ok", "denied", etc.
	Resource  string `json:"resource,omitempty"` // affected resource
	PrevHash  string `json:"prev_hash"`     // SHA-256 of previous entry JSON
	Hash      string `json:"hash"`          // SHA-256 of this entry (without hash field)
	Signature string `json:"sig"`           // ML-DSA signature over Hash
}

// IntegrityResult is returned by VerifyChain.
type IntegrityResult struct {
	Valid       bool   `json:"valid"`
	Entries     int    `json:"entries"`
	ChainBroken bool   `json:"chain_broken"`
	BrokenAt    int    `json:"broken_at,omitempty"`
	Message     string `json:"message"`
}

// Logger is a tamper-evident, ML-DSA signed audit logger.
type Logger struct {
	service string
	pk      *dsa.PublicKey
	sk      *dsa.PrivateKey

	mu      sync.Mutex
	entries []*Entry
	prevHash string // hash of last committed entry
}

// NewLogger creates a Logger for the given service name.
// A fresh ML-DSA-65 signing keypair is generated.
func NewLogger(service string) (*Logger, error) {
	pk, sk, err := dsa.GenerateKey(dsa.Level65)
	if err != nil {
		return nil, fmt.Errorf("audit.NewLogger: %w", err)
	}
	return &Logger{
		service:  service,
		pk:       pk,
		sk:       sk,
		prevHash: genesisHash(),
	}, nil
}

// Log appends a new signed entry to the audit trail.
func (l *Logger) Log(actor, action, result, resource string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	e := &Entry{
		Sequence:  uint64(len(l.entries)),
		Timestamp: time.Now().UnixNano(),
		Service:   l.service,
		Actor:     actor,
		Action:    action,
		Result:    result,
		Resource:  resource,
		PrevHash:  l.prevHash,
	}

	// Hash covers all fields except Hash and Signature
	e.Hash = entryHash(e)

	// Sign the hash with ML-DSA
	sig, err := dsa.Sign(l.sk, []byte(e.Hash))
	if err != nil {
		return fmt.Errorf("audit.Log: sign: %w", err)
	}
	e.Signature = hex.EncodeToString(sig)

	l.entries = append(l.entries, e)
	l.prevHash = e.Hash
	return nil
}

// Entries returns a copy of all entries (safe for external use).
func (l *Logger) Entries() []*Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]*Entry, len(l.entries))
	copy(out, l.entries)
	return out
}

// Count returns the number of log entries.
func (l *Logger) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// VerifyChain verifies the integrity of the entire audit log:
//  1. Hash chain: each entry's PrevHash matches predecessor's Hash
//  2. Entry hash: recompute hash and compare
//  3. Signature: verify ML-DSA signature on each entry's hash
func (l *Logger) VerifyChain() IntegrityResult {
	l.mu.Lock()
	entries := make([]*Entry, len(l.entries))
	copy(entries, l.entries)
	pk := l.pk
	l.mu.Unlock()

	if len(entries) == 0 {
		return IntegrityResult{Valid: true, Entries: 0, Message: "empty log"}
	}

	prevHash := genesisHash()
	for i, e := range entries {
		// 1. Check chain link
		if e.PrevHash != prevHash {
			return IntegrityResult{
				Valid:       false,
				Entries:     len(entries),
				ChainBroken: true,
				BrokenAt:    i,
				Message:     fmt.Sprintf("chain broken at entry %d: prev_hash mismatch", i),
			}
		}

		// 2. Recompute and verify entry hash
		computed := entryHash(e)
		if computed != e.Hash {
			return IntegrityResult{
				Valid:       false,
				Entries:     len(entries),
				ChainBroken: true,
				BrokenAt:    i,
				Message:     fmt.Sprintf("hash mismatch at entry %d", i),
			}
		}

		// 3. Verify ML-DSA signature
		sigBytes, err := hex.DecodeString(e.Signature)
		if err != nil || !dsa.Verify(pk, []byte(e.Hash), sigBytes) {
			return IntegrityResult{
				Valid:       false,
				Entries:     len(entries),
				ChainBroken: true,
				BrokenAt:    i,
				Message:     fmt.Sprintf("invalid signature at entry %d", i),
			}
		}

		prevHash = e.Hash
	}

	return IntegrityResult{
		Valid:   true,
		Entries: len(entries),
		Message: fmt.Sprintf("chain intact — %d entries verified", len(entries)),
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// entryHash computes SHA-256 over the entry fields (excluding Hash and Signature).
func entryHash(e *Entry) string {
	canonical := struct {
		Seq      uint64 `json:"seq"`
		TS       int64  `json:"ts"`
		Service  string `json:"service"`
		Actor    string `json:"actor"`
		Action   string `json:"action"`
		Result   string `json:"result"`
		Resource string `json:"resource,omitempty"`
		PrevHash string `json:"prev_hash"`
	}{
		Seq:      e.Sequence,
		TS:       e.Timestamp,
		Service:  e.Service,
		Actor:    e.Actor,
		Action:   e.Action,
		Result:   e.Result,
		Resource: e.Resource,
		PrevHash: e.PrevHash,
	}
	b, _ := json.Marshal(canonical)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// genesisHash is the fixed prev_hash of the first entry.
func genesisHash() string {
	sum := sha256.Sum256([]byte("quantum-shield-audit-genesis-v1"))
	return hex.EncodeToString(sum[:])
}

// TamperEntry modifies an entry's field — for testing only.
// Returns an error if the logger has no entries.
func TamperEntry(l *Logger, index int, newActor string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index >= len(l.entries) {
		return errors.New("audit.TamperEntry: index out of range")
	}
	l.entries[index].Actor = newActor
	return nil
}
