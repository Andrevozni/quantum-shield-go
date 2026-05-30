package cluster

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
)

// ── Configuration ─────────────────────────────────────────────────────────────

// Config is the configuration for a single Raft node.
type Config struct {
	// NodeID is a unique, stable identifier for this peer (e.g. "node-1").
	NodeID string

	// BindAddr is the TCP address this node listens on for Raft RPCs, e.g.
	// "127.0.0.1:7000". Must be reachable by all other cluster members.
	BindAddr string

	// DataDir is where Raft stores its log, stable store, and snapshots.
	// Created if it does not exist.
	DataDir string

	// Bootstrap must be true for the very first node that forms a new cluster.
	// Subsequent nodes joining an existing cluster set Bootstrap=false and
	// call Node.Join after the Node is created.
	Bootstrap bool

	// ApplyTimeout is the maximum duration to wait for a Raft.Apply call to
	// be committed across a quorum.  Defaults to 5 seconds.
	ApplyTimeout time.Duration

	// HeartbeatTimeout / ElectionTimeout / LeaderLeaseTimeout control leader
	// election timing.  Defaults: 150 ms / 150 ms / 150 ms.
	//
	// Constraint: LeaderLeaseTimeout ≤ HeartbeatTimeout.
	// When HeartbeatTimeout is set without LeaderLeaseTimeout, the lease
	// timeout is automatically clamped to HeartbeatTimeout.
	HeartbeatTimeout    time.Duration
	ElectionTimeout     time.Duration
	LeaderLeaseTimeout  time.Duration

	// SnapshotInterval controls how often Raft considers taking a snapshot.
	// Default: 30 seconds.
	SnapshotInterval time.Duration

	// SnapshotThreshold is the minimum number of new log entries since the
	// last snapshot before a new one is taken.  Default: 8192.
	SnapshotThreshold uint64
}

func (c *Config) applyDefaults() {
	if c.ApplyTimeout == 0 {
		c.ApplyTimeout = 5 * time.Second
	}
	if c.HeartbeatTimeout == 0 {
		c.HeartbeatTimeout = 150 * time.Millisecond
	}
	if c.ElectionTimeout == 0 {
		c.ElectionTimeout = 150 * time.Millisecond
	}
	// LeaderLeaseTimeout must be ≤ HeartbeatTimeout (Raft constraint).
	if c.LeaderLeaseTimeout == 0 || c.LeaderLeaseTimeout > c.HeartbeatTimeout {
		c.LeaderLeaseTimeout = c.HeartbeatTimeout
	}
	if c.SnapshotInterval == 0 {
		c.SnapshotInterval = 30 * time.Second
	}
	if c.SnapshotThreshold == 0 {
		c.SnapshotThreshold = 8192
	}
}

// ── Node ──────────────────────────────────────────────────────────────────────

// Node wraps a Raft instance and the FSM.  It is the main entry point for
// cluster operations.
//
// Usage:
//
//	n, err := cluster.NewNode(cfg, fsm)
//	// First node only:
//	n.Bootstrap()
//	// Other nodes:
//	n.Join(leaderAddr, leaderNodeID)
//	// Write operation:
//	err = n.Apply(cmd, timeout)
//	// Read:
//	entry := n.FSM().Key(keyID)
type Node struct {
	cfg    Config
	raft   *raft.Raft
	fsm    *FSM
	tm     *raft.NetworkTransport
	boltDB *raftboltdb.BoltStore // kept so Shutdown can close it
}

// NewNode creates a Raft node with the given configuration and FSM.
// The node is started immediately; call Bootstrap or Join to make it active.
func NewNode(cfg Config, fsm *FSM) (*Node, error) {
	cfg.applyDefaults()

	if cfg.NodeID == "" {
		return nil, errors.New("cluster.NewNode: NodeID must not be empty")
	}
	if cfg.BindAddr == "" {
		return nil, errors.New("cluster.NewNode: BindAddr must not be empty")
	}
	if cfg.DataDir == "" {
		return nil, errors.New("cluster.NewNode: DataDir must not be empty")
	}
	if fsm == nil {
		return nil, errors.New("cluster.NewNode: fsm must not be nil")
	}

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("cluster.NewNode: create data dir: %w", err)
	}

	// ── TCP transport ─────────────────────────────────────────────────────────
	addr, err := net.ResolveTCPAddr("tcp", cfg.BindAddr)
	if err != nil {
		return nil, fmt.Errorf("cluster.NewNode: resolve bind addr %q: %w", cfg.BindAddr, err)
	}
	transport, err := raft.NewTCPTransport(cfg.BindAddr, addr, 3, 10*time.Second,
		hclog.NewNullLogger().StandardWriter(&hclog.StandardLoggerOptions{}))
	if err != nil {
		return nil, fmt.Errorf("cluster.NewNode: create transport: %w", err)
	}

	// ── Stable store + log store (BoltDB) ────────────────────────────────────
	boltPath := filepath.Join(cfg.DataDir, "raft.db")
	boltDB, err := raftboltdb.New(raftboltdb.Options{Path: boltPath})
	if err != nil {
		transport.Close() //nolint:errcheck
		return nil, fmt.Errorf("cluster.NewNode: open bolt store: %w", err)
	}

	// ── Snapshot store ────────────────────────────────────────────────────────
	snapDir := filepath.Join(cfg.DataDir, "snapshots")
	snapStore, err := raft.NewFileSnapshotStore(snapDir, 3,
		hclog.NewNullLogger().StandardWriter(&hclog.StandardLoggerOptions{}))
	if err != nil {
		transport.Close() //nolint:errcheck
		return nil, fmt.Errorf("cluster.NewNode: create snapshot store: %w", err)
	}

	// ── Raft config ───────────────────────────────────────────────────────────
	rc := raft.DefaultConfig()
	rc.LocalID = raft.ServerID(cfg.NodeID)
	rc.HeartbeatTimeout = cfg.HeartbeatTimeout
	rc.ElectionTimeout = cfg.ElectionTimeout
	rc.LeaderLeaseTimeout = cfg.LeaderLeaseTimeout // must be ≤ HeartbeatTimeout
	rc.SnapshotInterval = cfg.SnapshotInterval
	rc.SnapshotThreshold = cfg.SnapshotThreshold
	rc.Logger = hclog.NewNullLogger() // suppress hashicorp logger in tests

	r, err := raft.NewRaft(rc, fsm, boltDB, boltDB, snapStore, transport)
	if err != nil {
		transport.Close() //nolint:errcheck
		boltDB.Close()    //nolint:errcheck
		return nil, fmt.Errorf("cluster.NewNode: create raft: %w", err)
	}

	return &Node{
		cfg:    cfg,
		raft:   r,
		fsm:    fsm,
		tm:     transport,
		boltDB: boltDB,
	}, nil
}

// Bootstrap bootstraps the cluster with this node as the sole initial voter.
// Call this only on the very first node when starting a fresh cluster.
// All other nodes must call Join instead.
func (n *Node) Bootstrap() error {
	cfg := raft.Configuration{
		Servers: []raft.Server{
			{
				ID:      raft.ServerID(n.cfg.NodeID),
				Address: raft.ServerAddress(n.cfg.BindAddr),
			},
		},
	}
	f := n.raft.BootstrapCluster(cfg)
	if err := f.Error(); err != nil {
		// ErrCantBootstrap means the node already has state — ignore.
		if err != raft.ErrCantBootstrap {
			return fmt.Errorf("cluster.Node.Bootstrap: %w", err)
		}
	}
	return nil
}

// Join sends an AddVoter RPC to the node at leaderAddr to add this node to the
// cluster.  The leaderAddr node must already be the Raft leader.
//
// Join is idempotent — if this node is already a voter, the call succeeds.
func (n *Node) Join(leaderAddr, joiningNodeID, joiningBindAddr string) error {
	// We need the leader's raft instance to add us as a voter.
	// In practice this is called on the LEADER node on behalf of the joiner.
	f := n.raft.AddVoter(
		raft.ServerID(joiningNodeID),
		raft.ServerAddress(joiningBindAddr),
		0, 0,
	)
	if err := f.Error(); err != nil {
		return fmt.Errorf("cluster.Node.Join: AddVoter: %w", err)
	}
	return nil
}

// Remove removes a node from the cluster (on the leader).
func (n *Node) Remove(nodeID string) error {
	f := n.raft.RemoveServer(raft.ServerID(nodeID), 0, 0)
	if err := f.Error(); err != nil {
		return fmt.Errorf("cluster.Node.Remove: %w", err)
	}
	return nil
}

// Apply serialises cmd to JSON and appends it to the Raft log.
// Blocks until the entry is committed on a quorum (or timeout expires).
// Returns an error if this node is not the leader.
func (n *Node) Apply(cmd Command) error {
	if !n.IsLeader() {
		return ErrNotLeader
	}
	data, err := encode(cmd)
	if err != nil {
		return fmt.Errorf("cluster.Node.Apply: encode: %w", err)
	}
	f := n.raft.Apply(data, n.cfg.ApplyTimeout)
	if err := f.Error(); err != nil {
		return fmt.Errorf("cluster.Node.Apply: raft: %w", err)
	}
	// The FSM's Apply return value is carried here.
	if resp := f.Response(); resp != nil {
		if err, ok := resp.(error); ok {
			return fmt.Errorf("cluster.Node.Apply: fsm: %w", err)
		}
	}
	return nil
}

// ApplyJSON is a convenience wrapper that marshals payload and builds the
// Command for you.
func (n *Node) ApplyJSON(op OpType, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("cluster.Node.ApplyJSON: marshal payload: %w", err)
	}
	return n.Apply(Command{Op: op, Payload: raw})
}

// ── Status helpers ────────────────────────────────────────────────────────────

// IsLeader reports whether this node is currently the Raft leader.
func (n *Node) IsLeader() bool {
	return n.raft.State() == raft.Leader
}

// LeaderAddr returns the bind address of the current Raft leader, or an empty
// string if the cluster has no leader.
func (n *Node) LeaderAddr() string {
	addr, _ := n.raft.LeaderWithID()
	return string(addr)
}

// LeaderID returns the node ID of the current Raft leader.
func (n *Node) LeaderID() string {
	_, id := n.raft.LeaderWithID()
	return string(id)
}

// State returns the current Raft state ("Leader", "Follower", "Candidate",
// "Shutdown").
func (n *Node) State() string {
	return n.raft.State().String()
}

// Stats returns raw Raft statistics (log index, commit index, leader, etc.).
func (n *Node) Stats() map[string]string {
	return n.raft.Stats()
}

// Servers returns the current cluster configuration (list of peers).
func (n *Node) Servers() ([]raft.Server, error) {
	f := n.raft.GetConfiguration()
	if err := f.Error(); err != nil {
		return nil, fmt.Errorf("cluster.Node.Servers: %w", err)
	}
	return f.Configuration().Servers, nil
}

// WaitForLeader blocks until the cluster has elected a leader or the timeout
// expires.  Returns the leader's bind address, or an error on timeout.
func (n *Node) WaitForLeader(timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if addr := n.LeaderAddr(); addr != "" {
			return addr, nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return "", fmt.Errorf("cluster.Node.WaitForLeader: no leader elected within %s", timeout)
}

// FSM returns the FSM so callers can read replicated state directly.
func (n *Node) FSM() *FSM { return n.fsm }

// Snapshot triggers a Raft snapshot and returns the future so the caller can
// wait for it to complete.  Exposed primarily for testing.
func (n *Node) Snapshot() raft.SnapshotFuture { return n.raft.Snapshot() }

// ── Lifecycle ─────────────────────────────────────────────────────────────────

// Shutdown gracefully stops the Raft node, closes the transport, and releases
// the BoltDB file handle.  It is idempotent.
func (n *Node) Shutdown() error {
	var errs []string
	if f := n.raft.Shutdown(); f.Error() != nil {
		errs = append(errs, "raft: "+f.Error().Error())
	}
	if err := n.tm.Close(); err != nil {
		errs = append(errs, "transport: "+err.Error())
	}
	if err := n.boltDB.Close(); err != nil {
		errs = append(errs, "boltdb: "+err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("cluster.Node.Shutdown: %v", errs)
	}
	return nil
}

// ── Errors ────────────────────────────────────────────────────────────────────

// ErrNotLeader is returned by Apply when this node is not the current leader.
// The caller should look up LeaderAddr() and forward the request there.
var ErrNotLeader = errors.New("cluster: this node is not the Raft leader")
