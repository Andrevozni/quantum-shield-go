package channel_test

import (
	"bytes"
	"sync"
	"testing"

	"github.com/quantum-shield/quantum-shield-go/internal/channel"
	"github.com/quantum-shield/quantum-shield-go/internal/dsa"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newIdentity(t *testing.T) (*dsa.PublicKey, *dsa.PrivateKey) {
	t.Helper()
	pk, sk, err := dsa.GenerateKey(dsa.Level65)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pk, sk
}

// doHandshake performs a full PQ handshake and returns both sessions.
func doHandshake(t *testing.T) (iSess, rSess *channel.Session) {
	t.Helper()
	iPK, iSK := newIdentity(t)
	rPK, rSK := newIdentity(t)

	initiator, err := channel.NewInitiator(iSK, iPK)
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	responder, err := channel.NewResponder(rSK, rPK)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}

	req, err := initiator.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	resp, rSess, err := responder.Accept(req)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	iSess, err = initiator.Complete(resp)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	return iSess, rSess
}

// ── Handshake ─────────────────────────────────────────────────────────────────

func TestHandshake_Completes(t *testing.T) {
	iSess, rSess := doHandshake(t)
	if iSess == nil || rSess == nil {
		t.Fatal("sessions must not be nil")
	}
}

func TestHandshake_SessionIDMatch(t *testing.T) {
	iSess, rSess := doHandshake(t)
	if iSess.ID() != rSess.ID() {
		t.Errorf("session IDs differ: %q vs %q", iSess.ID(), rSess.ID())
	}
}

func TestHandshake_RemotePKAuthenticated(t *testing.T) {
	iPK, iSK := newIdentity(t)
	rPK, rSK := newIdentity(t)

	initiator, _ := channel.NewInitiator(iSK, iPK)
	responder, _ := channel.NewResponder(rSK, rPK)

	req, _ := initiator.Begin()
	resp, rSess, _ := responder.Accept(req)
	iSess, _ := initiator.Complete(resp)

	// iSess.RemotePK must be rPK (serialised equal)
	rPKBytes, _ := rPK.Bytes()
	iRemoteBytes, _ := iSess.RemotePK.Bytes()
	if !bytes.Equal(rPKBytes, iRemoteBytes) {
		t.Error("initiator: RemotePK does not match responder's identity key")
	}

	// rSess.RemotePK must be iPK
	iPKBytes, _ := iPK.Bytes()
	rRemoteBytes, _ := rSess.RemotePK.Bytes()
	if !bytes.Equal(iPKBytes, rRemoteBytes) {
		t.Error("responder: RemotePK does not match initiator's identity key")
	}
}

// ── Messaging ─────────────────────────────────────────────────────────────────

func TestSealOpen_RoundTrip(t *testing.T) {
	iSess, rSess := doHandshake(t)

	plain := []byte("Transfer EUR 1,000,000 — classified")
	msg, err := iSess.Seal(plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := rSess.Open(msg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("plaintext mismatch: got %q", got)
	}
}

func TestSealOpen_MultipleMessages(t *testing.T) {
	iSess, rSess := doHandshake(t)

	for i := range 20 {
		plain := []byte("message number " + string(rune('A'+i)))
		msg, err := iSess.Seal(plain)
		if err != nil {
			t.Fatalf("Seal %d: %v", i, err)
		}
		got, err := rSess.Open(msg)
		if err != nil {
			t.Fatalf("Open %d: %v", i, err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("message %d: plaintext mismatch", i)
		}
	}
}

func TestSealOpen_BidirectionalIndependent(t *testing.T) {
	// Both sides can send and receive simultaneously
	iSess, rSess := doHandshake(t)

	iMsg, _ := iSess.Seal([]byte("from initiator"))
	rMsg, _ := rSess.Seal([]byte("from responder"))

	fromI, err := rSess.Open(iMsg)
	if err != nil {
		t.Fatalf("responder Open: %v", err)
	}
	fromR, err := iSess.Open(rMsg)
	if err != nil {
		t.Fatalf("initiator Open: %v", err)
	}
	if string(fromI) != "from initiator" {
		t.Errorf("got %q", fromI)
	}
	if string(fromR) != "from responder" {
		t.Errorf("got %q", fromR)
	}
}

func TestSealOpen_EmptyPlaintext(t *testing.T) {
	iSess, rSess := doHandshake(t)
	msg, err := iSess.Seal([]byte{})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := rSess.Open(msg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(got))
	}
}

func TestSealOpen_LargePayload(t *testing.T) {
	iSess, rSess := doHandshake(t)
	plain := bytes.Repeat([]byte("A"), 1<<20) // 1 MB
	msg, err := iSess.Seal(plain)
	if err != nil {
		t.Fatalf("Seal 1MB: %v", err)
	}
	got, err := rSess.Open(msg)
	if err != nil {
		t.Fatalf("Open 1MB: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("1MB payload mismatch")
	}
}

// ── Security: replay / tamper ─────────────────────────────────────────────────

func TestReplayRejected(t *testing.T) {
	iSess, rSess := doHandshake(t)
	msg, _ := iSess.Seal([]byte("hello"))
	rSess.Open(msg)
	_, err := rSess.Open(msg) // replay
	if err == nil {
		t.Fatal("replayed message must be rejected")
	}
}

func TestOutOfOrderRejected(t *testing.T) {
	iSess, rSess := doHandshake(t)
	m1, _ := iSess.Seal([]byte("first"))
	m2, _ := iSess.Seal([]byte("second"))
	rSess.Open(m2) // accept seq=2 first
	_, err := rSess.Open(m1) // seq=1 now ≤ max — reject
	if err == nil {
		t.Fatal("out-of-order message must be rejected")
	}
}

func TestTamperedCiphertext(t *testing.T) {
	iSess, rSess := doHandshake(t)
	msg, _ := iSess.Seal([]byte("secret"))
	msg.Ciphertext[0] ^= 0xFF
	_, err := rSess.Open(msg)
	if err == nil {
		t.Fatal("tampered ciphertext must fail")
	}
}

func TestWrongSessionNonce(t *testing.T) {
	iSess, rSess := doHandshake(t)
	_, rSess2 := doHandshake(t)

	msg, _ := iSess.Seal([]byte("hi"))
	_, err := rSess2.Open(msg) // different session
	if err == nil {
		t.Fatal("cross-session message must be rejected")
	}
	_ = rSess
}

func TestTamperedSeqNum(t *testing.T) {
	iSess, rSess := doHandshake(t)

	m1, _ := iSess.Seal([]byte("one"))
	m2, _ := iSess.Seal([]byte("two"))

	// Accept m1, then try m2 with seq forged to 1
	rSess.Open(m1)
	m2.SeqNum = 1
	_, err := rSess.Open(m2)
	if err == nil {
		t.Fatal("forged seq number must be rejected")
	}
}

// ── Handshake: adversarial ────────────────────────────────────────────────────

func TestWrongResponderIdentity(t *testing.T) {
	iPK, iSK := newIdentity(t)
	rPK, rSK := newIdentity(t)
	_, evil := newIdentity(t) // evil has a different SK

	initiator, _ := channel.NewInitiator(iSK, iPK)
	// Responder with mismatched SK/PK (evil SK but honest PK → signature over wrong key)
	responder, _ := channel.NewResponder(evil, rPK)

	req, _ := initiator.Begin()
	resp, _, _ := responder.Accept(req)
	_, err := initiator.Complete(resp)
	if err == nil {
		t.Fatal("initiator must reject mismatched responder identity")
	}
	_ = rSK
}

func TestTamperedInitiatorSignature(t *testing.T) {
	iPK, iSK := newIdentity(t)
	rPK, rSK := newIdentity(t)

	initiator, _ := channel.NewInitiator(iSK, iPK)
	responder, _ := channel.NewResponder(rSK, rPK)

	req, _ := initiator.Begin()
	req.Signature[0] ^= 0xFF // corrupt sig
	_, _, err := responder.Accept(req)
	if err == nil {
		t.Fatal("responder must reject tampered initiator signature")
	}
}

func TestNilInputs(t *testing.T) {
	_, err := channel.NewInitiator(nil, nil)
	if err == nil {
		t.Error("NewInitiator(nil,nil) must fail")
	}
	_, err = channel.NewResponder(nil, nil)
	if err == nil {
		t.Error("NewResponder(nil,nil) must fail")
	}
}

// ── Concurrency ───────────────────────────────────────────────────────────────

func TestConcurrentSeal(t *testing.T) {
	iSess, rSess := doHandshake(t)
	const n = 100
	msgs := make([]*channel.Message, n)
	var mu sync.Mutex
	var wg sync.WaitGroup

	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			msg, err := iSess.Seal([]byte("concurrent"))
			if err != nil {
				t.Errorf("concurrent Seal %d: %v", i, err)
				return
			}
			mu.Lock()
			msgs[i] = msg
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// All messages must be openable (order may vary)
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		_, err := rSess.Open(msg)
		// Some will fail due to out-of-order (seq already surpassed) — that's correct.
		// We just want to ensure no panics and no data races.
		_ = err
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

func BenchmarkHandshake(b *testing.B) {
	iPK, iSK, _ := func() (*dsa.PublicKey, *dsa.PrivateKey, error) {
		pk, sk, err := dsa.GenerateKey(dsa.Level65)
		return pk, sk, err
	}()
	rPK, rSK, _ := func() (*dsa.PublicKey, *dsa.PrivateKey, error) {
		pk, sk, err := dsa.GenerateKey(dsa.Level65)
		return pk, sk, err
	}()
	b.ResetTimer()
	for b.Loop() {
		i, _ := channel.NewInitiator(iSK, iPK)
		r, _ := channel.NewResponder(rSK, rPK)
		req, _ := i.Begin()
		resp, _, _ := r.Accept(req)
		i.Complete(resp)
	}
}

func BenchmarkSeal1KB(b *testing.B) {
	iSess, _ := doHandshake_bench(b)
	plain := bytes.Repeat([]byte{0xAB}, 1024)
	b.ResetTimer()
	for b.Loop() {
		iSess.Seal(plain)
	}
}

func doHandshake_bench(b *testing.B) (*channel.Session, *channel.Session) {
	b.Helper()
	iPK, iSK, _ := func() (*dsa.PublicKey, *dsa.PrivateKey, error) {
		pk, sk, err := dsa.GenerateKey(dsa.Level65)
		return pk, sk, err
	}()
	rPK, rSK, _ := func() (*dsa.PublicKey, *dsa.PrivateKey, error) {
		pk, sk, err := dsa.GenerateKey(dsa.Level65)
		return pk, sk, err
	}()
	i, _ := channel.NewInitiator(iSK, iPK)
	r, _ := channel.NewResponder(rSK, rPK)
	req, _ := i.Begin()
	resp, rSess, _ := r.Accept(req)
	iSess, _ := i.Complete(resp)
	return iSess, rSess
}
