// Package cluster provides a replicated state machine for QuantumShield using
// the Raft consensus algorithm (hashicorp/raft v1.7).
//
// # Architecture
//
// Each QuantumShield node runs one Raft peer.  All state-mutating operations
// (key generation, CA init, certificate issuance, revocation) are serialised
// through the Raft log.  Reads can be served locally from any peer; this means
// reads are eventually consistent by default (use ReadIndex / Linearizable read
// for strict consistency if needed).
//
// # Command types
//
// Every write is wrapped in a Command and appended to the log via Node.Apply.
// The FSM's Apply method decodes the command and mutates the local in-memory
// state.  On leader change or restart, Raft replays the log (or restores a
// snapshot) to reconstruct state.
//
// # Snapshots
//
// The FSM implements Snapshot() which serialises the full cluster state to an
// io.WriteCloser.  Raft calls this periodically (configurable via
// SnapshotInterval / SnapshotThreshold) and on leader elections.  The
// Restore() method replaces the FSM state from the snapshot.
//
// # Thread safety
//
// All exported methods on Node and FSM are safe for concurrent use.
package cluster

import "encoding/json"

// OpType identifies the kind of state mutation encoded in a Command.
type OpType string

const (
	// Key management
	OpGenerateKey OpType = "generate_key"
	OpDeleteKey   OpType = "delete_key"

	// CA operations
	OpCAInit         OpType = "ca_init"
	OpCASign         OpType = "ca_sign"
	OpCARevoke       OpType = "ca_revoke"
	OpCAIntermediate OpType = "ca_intermediate"

	// Cluster membership
	OpAddVoter    OpType = "add_voter"
	OpRemoveVoter OpType = "remove_voter"
)

// Command is the unit that is appended to the Raft log.
// Every state-mutating API call on the leader is translated into a Command,
// serialised to JSON, and applied through Raft.Apply before the HTTP response
// is returned.
type Command struct {
	Op      OpType          `json:"op"`
	Payload json.RawMessage `json:"payload"`
}

// ── Key payloads ──────────────────────────────────────────────────────────────

// GenerateKeyPayload carries the result of a key-generation operation.
// The leader generates the key, then replicates the raw bytes so all peers
// store identical key material.
type GenerateKeyPayload struct {
	KeyID   string `json:"key_id"`
	Level   string `json:"level"` // "ML-KEM-768" | "ML-KEM-1024"
	EKBytes []byte `json:"ek"`    // encapsulation key (public)
	DKBytes []byte `json:"dk"`    // decapsulation key (private) — replicated encrypted
}

// DeleteKeyPayload identifies a key to remove from the store.
type DeleteKeyPayload struct {
	KeyID string `json:"key_id"`
}

// ── CA payloads ───────────────────────────────────────────────────────────────

// CAInitPayload carries the CA snapshot produced by ca.Init on the leader.
// Restoring it on followers gives them the identical CA state.
type CAInitPayload struct {
	Snapshot json.RawMessage `json:"snapshot"` // ca.Snapshot marshalled to JSON
}

// CASignPayload carries a newly issued leaf certificate so all peers cache it.
type CASignPayload struct {
	Certificate json.RawMessage `json:"certificate"` // ca.Certificate marshalled to JSON
}

// CARevokePayload carries the serial number to add to the CRL.
type CARevokePayload struct {
	Serial string `json:"serial"`
}

// CAIntermediatePayload carries a new subordinate CA snapshot and the issuing
// CA serial (to route sub-CA issuance to the right CA).
type CAIntermediatePayload struct {
	IssuerSerial string          `json:"issuer_serial"`
	SubSerial    string          `json:"sub_serial"`
	Snapshot     json.RawMessage `json:"snapshot"` // sub-CA ca.Snapshot
	Certificate  json.RawMessage `json:"certificate"`
}

// ── Encoding helpers ──────────────────────────────────────────────────────────

// encode marshals cmd to JSON, suitable for raft.Log.Data.
func encode(cmd Command) ([]byte, error) {
	return json.Marshal(cmd)
}

// decode unmarshals JSON log data into a Command.
func decode(data []byte) (Command, error) {
	var c Command
	return c, json.Unmarshal(data, &c)
}
