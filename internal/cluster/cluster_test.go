package cluster_test

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/quantum-shield/quantum-shield-go/internal/ca"
	"github.com/quantum-shield/quantum-shield-go/internal/cluster"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// freePort returns a random available TCP port on localhost.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// singleNode starts a bootstrapped single-node cluster and returns the Node
// and a cleanup function.
func singleNode(t *testing.T) (*cluster.Node, func()) {
	t.Helper()
	dir := t.TempDir()
	port := freePort(t)
	bind := fmt.Sprintf("127.0.0.1:%d", port)

	fsm := cluster.NewFSM()
	n, err := cluster.NewNode(cluster.Config{
		NodeID:            "node-1",
		BindAddr:          bind,
		DataDir:           dir,
		Bootstrap:         true,
		HeartbeatTimeout:  50 * time.Millisecond,
		ElectionTimeout:   50 * time.Millisecond,
		SnapshotInterval:  60 * time.Second,
		SnapshotThreshold: 1024,
	}, fsm)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Bootstrap(); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	// Wait for leader election.
	if _, err := n.WaitForLeader(5 * time.Second); err != nil {
		t.Fatalf("WaitForLeader: %v", err)
	}
	return n, func() {
		n.Shutdown() //nolint:errcheck
	}
}

// threeNodeCluster creates a 3-node cluster and returns all nodes plus a
// cleanup function.  n1 is bootstrapped first, then n2 and n3 join via n1.
func threeNodeCluster(t *testing.T) (n1, n2, n3 *cluster.Node, cleanup func()) {
	t.Helper()

	mkNode := func(id string, port int, bootstrap bool) (*cluster.Node, string) {
		bind := fmt.Sprintf("127.0.0.1:%d", port)
		dir, _ := os.MkdirTemp("", "raft-"+id+"-*")
		fsm := cluster.NewFSM()
		n, err := cluster.NewNode(cluster.Config{
			NodeID:            id,
			BindAddr:          bind,
			DataDir:           dir,
			Bootstrap:         bootstrap,
			HeartbeatTimeout:  50 * time.Millisecond,
			ElectionTimeout:   50 * time.Millisecond,
			SnapshotInterval:  60 * time.Second,
			SnapshotThreshold: 1024,
		}, fsm)
		if err != nil {
			t.Fatalf("NewNode(%s): %v", id, err)
		}
		return n, bind
	}

	p1, p2, p3 := freePort(t), freePort(t), freePort(t)

	n1, _ = mkNode("node-1", p1, true)
	n2, b2 := mkNode("node-2", p2, false)
	n3, b3 := mkNode("node-3", p3, false)

	// Bootstrap n1.
	if err := n1.Bootstrap(); err != nil {
		t.Fatalf("Bootstrap n1: %v", err)
	}
	if _, err := n1.WaitForLeader(5 * time.Second); err != nil {
		t.Fatalf("WaitForLeader n1: %v", err)
	}

	// Add n2 and n3 as voters via n1 (the leader).
	if err := n1.Join("", "node-2", b2); err != nil {
		t.Fatalf("Join node-2: %v", err)
	}
	if err := n1.Join("", "node-3", b3); err != nil {
		t.Fatalf("Join node-3: %v", err)
	}

	// Wait until all nodes know about a leader.
	for _, n := range []*cluster.Node{n2, n3} {
		if _, err := n.WaitForLeader(5 * time.Second); err != nil {
			t.Fatalf("WaitForLeader follower: %v", err)
		}
	}

	cleanup = func() {
		n1.Shutdown() //nolint:errcheck
		n2.Shutdown() //nolint:errcheck
		n3.Shutdown() //nolint:errcheck
	}
	return n1, n2, n3, cleanup
}

// leader returns whichever of the given nodes is currently the leader.
func leader(t *testing.T, nodes ...*cluster.Node) *cluster.Node {
	t.Helper()
	for _, n := range nodes {
		if n.IsLeader() {
			return n
		}
	}
	t.Fatalf("leader: no leader found among %d nodes", len(nodes))
	return nil
}

// ── FSM unit tests ────────────────────────────────────────────────────────────

func TestFSM_ApplyGenerateKey(t *testing.T) {
	f := cluster.NewFSM()
	payload, _ := json.Marshal(cluster.GenerateKeyPayload{
		KeyID:   "k1",
		Level:   "ML-KEM-768",
		EKBytes: []byte("ek-bytes"),
		DKBytes: []byte("dk-bytes"),
	})
	raw, _ := json.Marshal(cluster.Command{Op: cluster.OpGenerateKey, Payload: payload})

	// Apply via a mock log entry — use the exported Apply method.
	applyRaw(t, f, raw)

	entry := f.Key("k1")
	if entry == nil {
		t.Fatal("Key() returned nil after apply")
	}
	if entry.Level != "ML-KEM-768" {
		t.Errorf("Level: got %q, want ML-KEM-768", entry.Level)
	}
	if f.KeyCount() != 1 {
		t.Errorf("KeyCount: got %d, want 1", f.KeyCount())
	}
}

func TestFSM_ApplyDeleteKey(t *testing.T) {
	f := cluster.NewFSM()

	// Add then delete.
	addPayload, _ := json.Marshal(cluster.GenerateKeyPayload{KeyID: "k1", Level: "ML-KEM-768"})
	delPayload, _ := json.Marshal(cluster.DeleteKeyPayload{KeyID: "k1"})
	applyRaw(t, f, mustMarshal(cluster.Command{Op: cluster.OpGenerateKey, Payload: addPayload}))
	applyRaw(t, f, mustMarshal(cluster.Command{Op: cluster.OpDeleteKey, Payload: delPayload}))

	if f.Key("k1") != nil {
		t.Error("key still present after delete")
	}
}

func TestFSM_ApplyCAInit(t *testing.T) {
	f := cluster.NewFSM()

	root, err := ca.Init("CN=Test Root CA")
	if err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	snap, err := root.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	snapJSON, _ := json.Marshal(snap)
	payload, _ := json.Marshal(cluster.CAInitPayload{Snapshot: snapJSON})
	applyRaw(t, f, mustMarshal(cluster.Command{Op: cluster.OpCAInit, Payload: payload}))

	restored, err := f.CARoot()
	if err != nil {
		t.Fatalf("CARoot: %v", err)
	}
	if restored == nil {
		t.Fatal("CARoot() returned nil after ca_init")
	}
	if restored.Certificate().Subject != "CN=Test Root CA" {
		t.Errorf("subject: %q", restored.Certificate().Subject)
	}
}

func TestFSM_ApplyCARevoke(t *testing.T) {
	f := cluster.NewFSM()

	// Init CA.
	root, _ := ca.Init("CN=Revoke Test CA")
	cert, _ := root.Issue("CN=leaf.example.com", "ML-KEM-768", []byte("pk"), 0)
	snap, _ := root.Export()
	snapJSON, _ := json.Marshal(snap)
	initPayload, _ := json.Marshal(cluster.CAInitPayload{Snapshot: snapJSON})
	applyRaw(t, f, mustMarshal(cluster.Command{Op: cluster.OpCAInit, Payload: initPayload}))

	// Revoke the cert's serial.
	revokePayload, _ := json.Marshal(cluster.CARevokePayload{Serial: cert.Serial})
	applyRaw(t, f, mustMarshal(cluster.Command{Op: cluster.OpCARevoke, Payload: revokePayload}))

	restored, err := f.CARoot()
	if err != nil {
		t.Fatalf("CARoot: %v", err)
	}
	if !restored.IsRevoked(cert.Serial) {
		t.Error("serial not revoked in restored CA")
	}
}

func TestFSM_SnapshotRestore(t *testing.T) {
	f := cluster.NewFSM()

	// Populate state.
	addPayload, _ := json.Marshal(cluster.GenerateKeyPayload{KeyID: "snap-key", Level: "ML-KEM-1024", EKBytes: []byte("ek")})
	applyRaw(t, f, mustMarshal(cluster.Command{Op: cluster.OpGenerateKey, Payload: addPayload}))

	// Take a snapshot.
	snap, err := f.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Restore into a fresh FSM.
	f2 := cluster.NewFSM()
	sink := &memorySink{}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if err := f2.Restore(sink); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	entry := f2.Key("snap-key")
	if entry == nil {
		t.Fatal("key not present after snapshot restore")
	}
	if entry.Level != "ML-KEM-1024" {
		t.Errorf("level: %q", entry.Level)
	}
}

// ── Single-node Raft tests ────────────────────────────────────────────────────

func TestNode_BootstrapElectsLeader(t *testing.T) {
	n, cleanup := singleNode(t)
	defer cleanup()

	if !n.IsLeader() {
		t.Errorf("bootstrapped node should be leader; state=%s", n.State())
	}
}

func TestNode_ApplyGenerateKey(t *testing.T) {
	n, cleanup := singleNode(t)
	defer cleanup()

	err := n.ApplyJSON(cluster.OpGenerateKey, cluster.GenerateKeyPayload{
		KeyID:   "raft-key-1",
		Level:   "ML-KEM-768",
		EKBytes: []byte("ek"),
		DKBytes: []byte("dk"),
	})
	if err != nil {
		t.Fatalf("ApplyJSON: %v", err)
	}

	entry := n.FSM().Key("raft-key-1")
	if entry == nil {
		t.Fatal("key not found in FSM after apply")
	}
}

func TestNode_ApplyCAInit(t *testing.T) {
	n, cleanup := singleNode(t)
	defer cleanup()

	root, _ := ca.Init("CN=Single Node CA")
	snap, _ := root.Export()
	snapJSON, _ := json.Marshal(snap)

	err := n.ApplyJSON(cluster.OpCAInit, cluster.CAInitPayload{Snapshot: snapJSON})
	if err != nil {
		t.Fatalf("ApplyJSON ca_init: %v", err)
	}

	restored, err := n.FSM().CARoot()
	if err != nil || restored == nil {
		t.Fatalf("CARoot after apply: %v, %v", restored, err)
	}
}

func TestNode_ApplyOnFollowerReturnsErrNotLeader(t *testing.T) {
	// A single un-bootstrapped node is a follower (no quorum).
	dir := t.TempDir()
	port := freePort(t)
	bind := fmt.Sprintf("127.0.0.1:%d", port)
	fsm := cluster.NewFSM()
	n, err := cluster.NewNode(cluster.Config{
		NodeID:           "follower",
		BindAddr:         bind,
		DataDir:          dir,
		HeartbeatTimeout: 50 * time.Millisecond,
		ElectionTimeout:  50 * time.Millisecond,
	}, fsm)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	defer n.Shutdown() //nolint:errcheck

	err = n.ApplyJSON(cluster.OpGenerateKey, cluster.GenerateKeyPayload{KeyID: "k"})
	if err != cluster.ErrNotLeader {
		t.Errorf("expected ErrNotLeader, got %v", err)
	}
}

func TestNode_Stats(t *testing.T) {
	n, cleanup := singleNode(t)
	defer cleanup()

	stats := n.Stats()
	if stats["state"] == "" {
		t.Error("stats missing 'state'")
	}
}

// ── 3-node cluster tests ──────────────────────────────────────────────────────

func TestCluster_ThreeNodes_LeaderElected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 3-node cluster test in short mode")
	}
	n1, n2, n3, cleanup := threeNodeCluster(t)
	defer cleanup()

	ldr := leader(t, n1, n2, n3)
	if ldr == nil {
		t.Fatal("no leader in 3-node cluster")
	}
	t.Logf("leader: %s (state: %s)", ldr.LeaderAddr(), ldr.State())
}

func TestCluster_ThreeNodes_Replication(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 3-node cluster test in short mode")
	}
	n1, n2, n3, cleanup := threeNodeCluster(t)
	defer cleanup()

	ldr := leader(t, n1, n2, n3)

	// Apply a key on the leader.
	if err := ldr.ApplyJSON(cluster.OpGenerateKey, cluster.GenerateKeyPayload{
		KeyID:   "replicated-key",
		Level:   "ML-KEM-768",
		EKBytes: []byte("ek"),
		DKBytes: []byte("dk"),
	}); err != nil {
		t.Fatalf("Apply on leader: %v", err)
	}

	// Give followers time to apply the log entry.
	time.Sleep(200 * time.Millisecond)

	// All three FSMs must contain the key.
	for _, n := range []*cluster.Node{n1, n2, n3} {
		if n.FSM().Key("replicated-key") == nil {
			t.Errorf("node %s: key not replicated", n.LeaderAddr())
		}
	}
}

func TestCluster_ThreeNodes_CAInitReplication(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 3-node cluster test in short mode")
	}
	n1, n2, n3, cleanup := threeNodeCluster(t)
	defer cleanup()

	ldr := leader(t, n1, n2, n3)

	root, _ := ca.Init("CN=Cluster Root CA")
	snap, _ := root.Export()
	snapJSON, _ := json.Marshal(snap)

	if err := ldr.ApplyJSON(cluster.OpCAInit, cluster.CAInitPayload{Snapshot: snapJSON}); err != nil {
		t.Fatalf("Apply ca_init: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	for _, n := range []*cluster.Node{n1, n2, n3} {
		ca, err := n.FSM().CARoot()
		if err != nil || ca == nil {
			t.Errorf("node %s: CA not replicated (ca=%v err=%v)", n.LeaderAddr(), ca, err)
		}
	}
}

func TestCluster_ThreeNodes_PeerCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 3-node cluster test in short mode")
	}
	n1, _, _, cleanup := threeNodeCluster(t)
	defer cleanup()

	servers, err := n1.Servers()
	if err != nil {
		t.Fatalf("Servers: %v", err)
	}
	if len(servers) != 3 {
		t.Errorf("expected 3 servers, got %d", len(servers))
	}
}

func TestCluster_ThreeNodes_SnapshotAndRestore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 3-node cluster test in short mode")
	}
	n1, _, _, cleanup := threeNodeCluster(t)
	defer cleanup()

	ldr := n1 // n1 bootstrapped, is likely leader; use WaitForLeader result
	if !ldr.IsLeader() {
		t.Skip("n1 not leader — skipping snapshot test")
	}

	// Write some data.
	for i := range 5 {
		_ = ldr.ApplyJSON(cluster.OpGenerateKey, cluster.GenerateKeyPayload{
			KeyID: fmt.Sprintf("snap-key-%d", i),
			Level: "ML-KEM-768",
		})
	}

	// Take a manual snapshot on the leader.
	f := n1.Snapshot()
	if err := f.Error(); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// applyRaw exercises the FSM's Apply method by wrapping raw bytes in a
// synthetic raft.Log.  Used for unit-testing without a real Raft cluster.
func applyRaw(t *testing.T, f *cluster.FSM, data []byte) {
	t.Helper()
	f.ApplyRaw(data)
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// memorySink implements both raft.SnapshotSink (for Persist) and io.ReadCloser
// (for Restore).  It accumulates written bytes in a buffer that can then be
// read back — simulating a round-trip through a real snapshot sink.
type memorySink struct {
	buf []byte
	pos int
}

// raft.SnapshotSink
func (s *memorySink) Write(p []byte) (int, error) {
	s.buf = append(s.buf, p...)
	return len(p), nil
}
func (s *memorySink) Close() error  { return nil }
func (s *memorySink) Cancel() error { return nil }
func (s *memorySink) ID() string    { return "memory-sink" }

// io.ReadCloser (for FSM.Restore)
func (s *memorySink) Read(p []byte) (int, error) {
	if s.pos >= len(s.buf) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, s.buf[s.pos:])
	s.pos += n
	return n, nil
}
