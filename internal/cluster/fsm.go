package cluster

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/hashicorp/raft"

	"github.com/quantum-shield/quantum-shield-go/internal/ca"
)

// ── FSM state ─────────────────────────────────────────────────────────────────

// KeyEntry is the in-cluster representation of a KEM keypair.
type KeyEntry struct {
	KeyID   string `json:"key_id"`
	Level   string `json:"level"`
	EKBytes []byte `json:"ek"`
	DKBytes []byte `json:"dk"`
}

// fsmState is the full replicated state.  It is serialised to/from snapshots.
type fsmState struct {
	Keys            map[string]*KeyEntry    `json:"keys"`
	CARoot          *ca.Snapshot            `json:"ca_root,omitempty"`
	CAIntermediates map[string]*ca.Snapshot `json:"ca_intermediates"` // serial → snapshot
}

func newFSMState() *fsmState {
	return &fsmState{
		Keys:            make(map[string]*KeyEntry),
		CAIntermediates: make(map[string]*ca.Snapshot),
	}
}

// ── FSM ───────────────────────────────────────────────────────────────────────

// FSM implements raft.FSM for QuantumShield.
// It is the single source of truth for replicated state on each node.
// All mutations arrive via Apply; reads are served directly from the fields.
type FSM struct {
	mu    sync.RWMutex
	state *fsmState
}

// NewFSM creates an empty FSM ready to accept log entries.
func NewFSM() *FSM {
	return &FSM{state: newFSMState()}
}

// ── raft.FSM interface ────────────────────────────────────────────────────────

// Apply is called by Raft on the leader and every follower whenever a log
// entry is committed.  It must be deterministic and idempotent.
func (f *FSM) Apply(l *raft.Log) any {
	cmd, err := decode(l.Data)
	if err != nil {
		return fmt.Errorf("fsm.Apply: decode: %w", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	switch cmd.Op {
	case OpGenerateKey:
		return f.applyGenerateKey(cmd.Payload)
	case OpDeleteKey:
		return f.applyDeleteKey(cmd.Payload)
	case OpCAInit:
		return f.applyCAInit(cmd.Payload)
	case OpCASign:
		return f.applyCASign(cmd.Payload) // no-op: cert is in the payload for audit only
	case OpCARevoke:
		return f.applyCARevoke(cmd.Payload)
	case OpCAIntermediate:
		return f.applyCAIntermediate(cmd.Payload)
	default:
		return fmt.Errorf("fsm.Apply: unknown op %q", cmd.Op)
	}
}

// Snapshot returns a snapshot of the FSM state for Raft's log compaction.
func (f *FSM) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Deep-copy the state to avoid holding the lock during serialisation.
	raw, err := json.Marshal(f.state)
	if err != nil {
		return nil, fmt.Errorf("fsm.Snapshot: marshal: %w", err)
	}
	return &fsmSnapshot{data: raw}, nil
}

// Restore replaces the FSM state from a snapshot.  Called by Raft after a
// leader sends a snapshot to a lagging follower.
func (f *FSM) Restore(rc io.ReadCloser) error {
	defer rc.Close()

	var s fsmState
	if err := json.NewDecoder(rc).Decode(&s); err != nil {
		return fmt.Errorf("fsm.Restore: decode: %w", err)
	}
	if s.Keys == nil {
		s.Keys = make(map[string]*KeyEntry)
	}
	if s.CAIntermediates == nil {
		s.CAIntermediates = make(map[string]*ca.Snapshot)
	}

	f.mu.Lock()
	f.state = &s
	f.mu.Unlock()
	return nil
}

// ── Apply helpers (called with f.mu held) ────────────────────────────────────

func (f *FSM) applyGenerateKey(raw json.RawMessage) error {
	var p GenerateKeyPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("applyGenerateKey: %w", err)
	}
	f.state.Keys[p.KeyID] = &KeyEntry{
		KeyID:   p.KeyID,
		Level:   p.Level,
		EKBytes: p.EKBytes,
		DKBytes: p.DKBytes,
	}
	return nil
}

func (f *FSM) applyDeleteKey(raw json.RawMessage) error {
	var p DeleteKeyPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("applyDeleteKey: %w", err)
	}
	delete(f.state.Keys, p.KeyID)
	return nil
}

func (f *FSM) applyCAInit(raw json.RawMessage) error {
	var p CAInitPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("applyCAInit: %w", err)
	}
	var snap ca.Snapshot
	if err := json.Unmarshal(p.Snapshot, &snap); err != nil {
		return fmt.Errorf("applyCAInit: unmarshal snapshot: %w", err)
	}
	f.state.CARoot = &snap
	return nil
}

// applyCASign is a no-op at the FSM level — certificates are issued
// transiently and not stored in the replicated state (they are stateless
// once issued; revocation is tracked via the CRL in the CA snapshot).
// The command still flows through Raft so that every node's audit log records it.
func (f *FSM) applyCASign(_ json.RawMessage) error {
	return nil
}

func (f *FSM) applyCARevoke(raw json.RawMessage) error {
	var p CARevokePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("applyCARevoke: %w", err)
	}
	if f.state.CARoot == nil {
		return fmt.Errorf("applyCARevoke: CA not initialised")
	}
	// Restore the CA, revoke, re-export.
	root, err := ca.Restore(*f.state.CARoot)
	if err != nil {
		return fmt.Errorf("applyCARevoke: restore CA: %w", err)
	}
	if err := root.Revoke(p.Serial); err != nil {
		return fmt.Errorf("applyCARevoke: revoke serial %s: %w", p.Serial, err)
	}
	snap, err := root.Export()
	if err != nil {
		return fmt.Errorf("applyCARevoke: re-export CA: %w", err)
	}
	f.state.CARoot = &snap
	return nil
}

func (f *FSM) applyCAIntermediate(raw json.RawMessage) error {
	var p CAIntermediatePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("applyCAIntermediate: %w", err)
	}
	var snap ca.Snapshot
	if err := json.Unmarshal(p.Snapshot, &snap); err != nil {
		return fmt.Errorf("applyCAIntermediate: unmarshal snapshot: %w", err)
	}
	f.state.CAIntermediates[p.SubSerial] = &snap
	return nil
}

// ── Test helper ──────────────────────────────────────────────────────────────

// ApplyRaw is a test-only helper that calls Apply with a synthetic raft.Log.
// It allows unit-testing FSM mutations without spinning up a real Raft cluster.
func (f *FSM) ApplyRaw(data []byte) any {
	return f.Apply(&raft.Log{Data: data})
}

// ── Read accessors (safe for concurrent use) ──────────────────────────────────

// Key returns the KeyEntry for keyID, or nil if not present.
func (f *FSM) Key(keyID string) *KeyEntry {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.state.Keys[keyID]
}

// Keys returns a snapshot copy of all keys.
func (f *FSM) Keys() map[string]*KeyEntry {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make(map[string]*KeyEntry, len(f.state.Keys))
	for k, v := range f.state.Keys {
		out[k] = v
	}
	return out
}

// KeyCount returns the number of stored keys.
func (f *FSM) KeyCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.state.Keys)
}

// CARoot returns a live *ca.CA restored from the snapshot, or nil if the CA
// has not been initialised yet.
func (f *FSM) CARoot() (*ca.CA, error) {
	f.mu.RLock()
	snap := f.state.CARoot
	f.mu.RUnlock()
	if snap == nil {
		return nil, nil
	}
	return ca.Restore(*snap)
}

// CAIntermediate returns a live *ca.CA for the given serial, or nil.
func (f *FSM) CAIntermediate(serial string) (*ca.CA, error) {
	f.mu.RLock()
	snap := f.state.CAIntermediates[serial]
	f.mu.RUnlock()
	if snap == nil {
		return nil, nil
	}
	return ca.Restore(*snap)
}

// CAIntermediateSerials returns the serials of all intermediate CAs.
func (f *FSM) CAIntermediateSerials() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]string, 0, len(f.state.CAIntermediates))
	for s := range f.state.CAIntermediates {
		out = append(out, s)
	}
	return out
}

// ── fsmSnapshot ───────────────────────────────────────────────────────────────

// fsmSnapshot implements raft.FSMSnapshot.
type fsmSnapshot struct {
	data []byte // pre-serialised JSON
}

// Persist writes the snapshot to the sink provided by Raft.
func (s *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	if _, err := sink.Write(s.data); err != nil {
		sink.Cancel() //nolint:errcheck
		return fmt.Errorf("fsmSnapshot.Persist: write: %w", err)
	}
	return sink.Close()
}

// Release is called by Raft after the snapshot has been persisted.
func (s *fsmSnapshot) Release() {}
