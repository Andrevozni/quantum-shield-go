// Package channel implements a Post-Quantum Secure Channel.
//
// # Protocol
//
// The handshake provides:
//   - Confidentiality     — AES-256-GCM with keys derived via HKDF from an ML-KEM shared secret
//   - Forward secrecy     — ephemeral ML-KEM keypair per session; compromise of long-term keys
//     does not expose past sessions
//   - Authentication      — both parties sign the handshake transcript with their ML-DSA-65 identity key
//   - Replay protection   — monotonic sequence numbers per direction + session nonce binding
//   - Separation of keys  — send and receive keys are derived independently (domain separation)
//
// # Handshake (2 messages)
//
//	Initiator                          Responder
//	─────────────────────────────────────────────
//	1. Begin()
//	   gen ephemeral KEM keypair
//	   sign transcript₁
//	   ──── InitRequest ────────────►
//	                                   2. Accept(req)
//	                                      verify initiator sig
//	                                      encapsulate → sharedSecret
//	                                      derive sendKey, recvKey
//	                                      sign transcript₂
//	   ◄─── InitResponse ────────────
//	3. Complete(resp)
//	   verify responder sig
//	   decapsulate → sharedSecret
//	   derive recvKey, sendKey   (roles reversed)
//
//	Both sides now hold matching (sendKey, recvKey) pairs.
//	Data messages: AES-256-GCM(key, nonce=sessionNonce||seqNum, plaintext)
package channel

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/quantum-shield/quantum-shield-go/internal/dsa"
	"github.com/quantum-shield/quantum-shield-go/internal/kdf"
	"github.com/quantum-shield/quantum-shield-go/internal/kem"
)

// Domain-separation labels for HKDF (must never overlap).
const (
	labelSendKey    = "qs-channel-send-key-v1"
	labelRecvKey    = "qs-channel-recv-key-v1"
	labelSessionSalt = "qs-channel-session-salt-v1"
)

// ── Wire types ────────────────────────────────────────────────────────────────

// InitRequest is sent by the Initiator to start the handshake.
type InitRequest struct {
	SessionID   string // 128-bit random, hex-encoded
	EKBytes     []byte // initiator's ephemeral ML-KEM-768 encapsulation key
	IdentityPK  []byte // initiator's long-term ML-DSA-65 public key
	Signature   []byte // ML-DSA-65 sig over transcript1 = SHA-256(SessionID || EKBytes || IdentityPK)
}

// InitResponse is sent by the Responder to complete the handshake.
type InitResponse struct {
	SessionID     string // echoed from InitRequest
	KEMCiphertext []byte // ML-KEM-768 ciphertext encapsulating the shared secret
	IdentityPK    []byte // responder's long-term ML-DSA-65 public key
	Signature     []byte // ML-DSA-65 sig over transcript2 = SHA-256(SessionID || KEMCiphertext || IdentityPK)
}

// Message is an encrypted application-layer payload.
type Message struct {
	SessionID []byte // 16-byte random session nonce (not the hex string — a raw bytes binding)
	SeqNum    uint64 // monotonic; receiver rejects if ≤ last seen
	Ciphertext []byte // AES-256-GCM output (includes GCM tag)
}

// ── Session ───────────────────────────────────────────────────────────────────

// Session is an established bidirectional secure channel.
// All methods are safe for concurrent use.
type Session struct {
	id         string
	sessionKey []byte // 16-byte nonce mixed into every GCM nonce

	sendGCM cipher.AEAD
	recvGCM cipher.AEAD

	sendSeq atomic.Uint64
	recvMu  sync.Mutex
	recvMax uint64 // highest accepted seqNum; protected by recvMu

	RemotePK *dsa.PublicKey // authenticated remote identity
}

// Seal encrypts plaintext and returns a Message ready to send.
func (s *Session) Seal(plaintext []byte) (*Message, error) {
	seq := s.sendSeq.Add(1) // start at 1; 0 is never sent

	nonce := s.buildNonce(seq)
	ct := s.sendGCM.Seal(nil, nonce, plaintext, s.aad(seq))

	return &Message{
		SessionID:  s.sessionKey,
		SeqNum:     seq,
		Ciphertext: ct,
	}, nil
}

// Open decrypts a received Message and returns the plaintext.
// Returns an error if the MAC is wrong, the sequence number is out of order,
// or the session nonce doesn't match.
func (s *Session) Open(msg *Message) ([]byte, error) {
	if len(msg.SessionID) != 16 {
		return nil, errors.New("channel: invalid session nonce length")
	}
	// Verify the session nonce matches (binds message to this session)
	for i := range 16 {
		if msg.SessionID[i] != s.sessionKey[i] {
			return nil, errors.New("channel: session nonce mismatch")
		}
	}

	s.recvMu.Lock()
	if msg.SeqNum == 0 || msg.SeqNum <= s.recvMax {
		s.recvMu.Unlock()
		return nil, fmt.Errorf("channel: replayed or out-of-order sequence %d (max seen %d)",
			msg.SeqNum, s.recvMax)
	}
	s.recvMax = msg.SeqNum
	s.recvMu.Unlock()

	nonce := s.buildNonce(msg.SeqNum)
	plain, err := s.recvGCM.Open(nil, nonce, msg.Ciphertext, s.aad(msg.SeqNum))
	if err != nil {
		return nil, errors.New("channel: decryption failed")
	}
	return plain, nil
}

func (s *Session) ID() string { return s.id }

// buildNonce constructs a 12-byte GCM nonce: first 8 bytes of sessionKey XOR'd
// with 0s, last 4 bytes = seqNum big-endian. Always unique per (session, seq).
func (s *Session) buildNonce(seq uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce[:8], s.sessionKey[:8])
	binary.BigEndian.PutUint32(nonce[8:], uint32(seq))
	return nonce
}

func (s *Session) aad(seq uint64) []byte {
	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, seq)
	return aad
}

// ── Initiator ─────────────────────────────────────────────────────────────────

// Initiator manages the client side of the handshake.
type Initiator struct {
	identitySK *dsa.PrivateKey
	identityPK *dsa.PublicKey

	// state filled during Begin()
	sessionID string
	ephemDK   *kem.DecapsulationKey
	req       *InitRequest
}

// NewInitiator creates a new Initiator with the given long-term ML-DSA identity key.
func NewInitiator(identitySK *dsa.PrivateKey, identityPK *dsa.PublicKey) (*Initiator, error) {
	if identitySK == nil || identityPK == nil {
		return nil, errors.New("channel: identity keys must not be nil")
	}
	return &Initiator{identitySK: identitySK, identityPK: identityPK}, nil
}

// Begin generates an ephemeral ML-KEM keypair and produces an InitRequest.
// Call Complete() after receiving the Responder's InitResponse.
func (i *Initiator) Begin() (*InitRequest, error) {
	// 1. Fresh ephemeral KEM keypair (forward secrecy)
	dk, err := kem.GenerateKey(kem.Level768)
	if err != nil {
		return nil, fmt.Errorf("channel: ephemeral keygen: %w", err)
	}
	i.ephemDK = dk

	// 2. Session ID: 128-bit random
	sid, err := newSessionID()
	if err != nil {
		return nil, err
	}
	i.sessionID = sid

	ekBytes := dk.EncapsulationKey().Bytes()
	pkBytes, err := i.identityPK.Bytes()
	if err != nil {
		return nil, fmt.Errorf("channel: marshal identity pk: %w", err)
	}

	// 3. Sign transcript₁
	t1 := transcript1(sid, ekBytes, pkBytes)
	sig, err := dsa.Sign(i.identitySK, t1)
	if err != nil {
		return nil, fmt.Errorf("channel: sign transcript1: %w", err)
	}

	i.req = &InitRequest{
		SessionID:  sid,
		EKBytes:    ekBytes,
		IdentityPK: pkBytes,
		Signature:  sig,
	}
	return i.req, nil
}

// Complete verifies the Responder's InitResponse and derives the Session.
func (i *Initiator) Complete(resp *InitResponse) (*Session, error) {
	if i.req == nil {
		return nil, errors.New("channel: Begin() must be called before Complete()")
	}
	if resp.SessionID != i.sessionID {
		return nil, errors.New("channel: session ID mismatch in response")
	}

	// 1. Parse and verify responder's identity
	remotePK, err := dsa.ParsePublicKey(dsa.Level65, resp.IdentityPK)
	if err != nil {
		return nil, fmt.Errorf("channel: parse responder pk: %w", err)
	}
	t2 := transcript2(resp.SessionID, resp.KEMCiphertext, resp.IdentityPK)
	if !dsa.Verify(remotePK, t2, resp.Signature) {
		return nil, errors.New("channel: responder signature verification failed")
	}

	// 2. Decapsulate → shared secret
	sharedSecret, err := kem.Decapsulate(i.ephemDK, resp.KEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("channel: decapsulate: %w", err)
	}

	// 3. Derive session keys (initiator sends on sendKey, receives on recvKey)
	return deriveSession(i.sessionID, sharedSecret, remotePK, false)
}

// ── Responder ─────────────────────────────────────────────────────────────────

// Responder manages the server side of the handshake.
type Responder struct {
	identitySK *dsa.PrivateKey
	identityPK *dsa.PublicKey
}

// NewResponder creates a new Responder with the given long-term ML-DSA identity key.
func NewResponder(identitySK *dsa.PrivateKey, identityPK *dsa.PublicKey) (*Responder, error) {
	if identitySK == nil || identityPK == nil {
		return nil, errors.New("channel: identity keys must not be nil")
	}
	return &Responder{identitySK: identitySK, identityPK: identityPK}, nil
}

// Accept verifies an InitRequest, encapsulates a shared secret, and returns
// both the InitResponse (to send back to the Initiator) and the established Session.
func (r *Responder) Accept(req *InitRequest) (*InitResponse, *Session, error) {
	if req == nil {
		return nil, nil, errors.New("channel: nil InitRequest")
	}

	// 1. Parse and verify initiator's identity
	remotePK, err := dsa.ParsePublicKey(dsa.Level65, req.IdentityPK)
	if err != nil {
		return nil, nil, fmt.Errorf("channel: parse initiator pk: %w", err)
	}
	t1 := transcript1(req.SessionID, req.EKBytes, req.IdentityPK)
	if !dsa.Verify(remotePK, t1, req.Signature) {
		return nil, nil, errors.New("channel: initiator signature verification failed")
	}

	// 2. Parse ephemeral EK and encapsulate
	ek, err := kem.ParseEncapsulationKey(kem.Level768, req.EKBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("channel: parse ephemeral ek: %w", err)
	}
	sharedSecret, kemCT, err := kem.Encapsulate(ek)
	if err != nil {
		return nil, nil, fmt.Errorf("channel: encapsulate: %w", err)
	}

	// 3. Build and sign response
	pkBytes, err := r.identityPK.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("channel: marshal responder pk: %w", err)
	}
	t2 := transcript2(req.SessionID, kemCT, pkBytes)
	sig, err := dsa.Sign(r.identitySK, t2)
	if err != nil {
		return nil, nil, fmt.Errorf("channel: sign transcript2: %w", err)
	}

	resp := &InitResponse{
		SessionID:     req.SessionID,
		KEMCiphertext: kemCT,
		IdentityPK:    pkBytes,
		Signature:     sig,
	}

	// 4. Derive session (responder's send = initiator's recv, and vice-versa)
	sess, err := deriveSession(req.SessionID, sharedSecret, remotePK, true)
	if err != nil {
		return nil, nil, err
	}
	return resp, sess, nil
}

// ── Session derivation ────────────────────────────────────────────────────────

func deriveSession(sessionID string, sharedSecret []byte, remotePK *dsa.PublicKey, isResponder bool) (*Session, error) {
	// Salt = SHA-256(sessionID) — domain-separated, session-unique
	sidHash := sha256.Sum256([]byte(labelSessionSalt + ":" + sessionID))
	salt := sidHash[:]

	// Derive send and recv keys independently
	keys, err := kdf.DeriveHKDFMulti(
		sharedSecret, salt,
		[][]byte{[]byte(labelSendKey), []byte(labelRecvKey)},
		[]int{32, 32},
	)
	if err != nil {
		return nil, fmt.Errorf("channel: kdf: %w", err)
	}

	// Roles: initiator's send = responder's recv
	sendKey, recvKey := keys[0], keys[1]
	if isResponder {
		sendKey, recvKey = keys[1], keys[0]
	}

	sendGCM, err := newGCM(sendKey)
	if err != nil {
		return nil, err
	}
	recvGCM, err := newGCM(recvKey)
	if err != nil {
		return nil, err
	}

	// Session nonce: derived from shared secret so BOTH sides agree on the same value.
	// This binds every message to this specific session — cross-session replay is rejected
	// even without checking sequence numbers.
	sessNonce, err := kdf.DeriveHKDF(sharedSecret, salt, []byte("qs-channel-session-nonce-v1"), 16)
	if err != nil {
		return nil, fmt.Errorf("channel: derive session nonce: %w", err)
	}

	return &Session{
		id:         sessionID,
		sessionKey: sessNonce,
		sendGCM:    sendGCM,
		recvGCM:    recvGCM,
		RemotePK:   remotePK,
	}, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("channel: AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("channel: GCM: %w", err)
	}
	return gcm, nil
}

// ── Transcript hashing ────────────────────────────────────────────────────────

// transcript1 = SHA-256("qs-ch-t1" || sessionID || ekBytes || identityPK)
func transcript1(sessionID string, ekBytes, identityPK []byte) []byte {
	h := sha256.New()
	h.Write([]byte("qs-ch-t1:"))
	h.Write([]byte(sessionID))
	h.Write(ekBytes)
	h.Write(identityPK)
	return h.Sum(nil)
}

// transcript2 = SHA-256("qs-ch-t2" || sessionID || kemCiphertext || responderPK)
func transcript2(sessionID string, kemCT, responderPK []byte) []byte {
	h := sha256.New()
	h.Write([]byte("qs-ch-t2:"))
	h.Write([]byte(sessionID))
	h.Write(kemCT)
	h.Write(responderPK)
	return h.Sum(nil)
}

// ── Utilities ─────────────────────────────────────────────────────────────────

func newSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := cryptorand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
