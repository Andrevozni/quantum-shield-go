//go:build pkcs11

// Package hsm – PKCS#11 backend (compiled with -tags pkcs11 only).
//
// # Supported hardware
//
// Any PKCS#11 v2.40-compliant library:
//   - SoftHSMv2  (dev / CI)       libsofthsm2.so
//   - Thales Luna Network HSM      cryptoki.so
//   - AWS CloudHSM client          libcloudhsm_pkcs11.so
//   - nCipher nShield              libcknfast.so
//   - Utimaco SecurityServer       pkcs11.so
//
// # Key provisioning (SoftHSM2 example)
//
//	softhsm2-util --init-token --slot 0 --label "qs-token" \
//	              --so-pin changeit --pin changeit
//	pkcs11-tool --module libsofthsm2.so --login --pin changeit \
//	            --keygen --key-type AES:32 --label qs-master-key
//
// # Environment variables
//
//	QS_PKCS11_LIB       path to the PKCS#11 shared library
//	QS_PKCS11_SLOT      token slot index (default: 0)
//	QS_PKCS11_PIN       HSM user PIN
//	QS_PKCS11_KEY_LABEL CKA_LABEL of the AES-256 secret key object
//
// # Non-extractable keys
//
// If the key has CKA_EXTRACTABLE=false the raw CKA_VALUE read in MasterKey
// will fail. In that case keep all encryption / decryption inside the HSM
// via C_EncryptInit / C_Encrypt and C_DecryptInit / C_Decrypt, wrapping the
// keystore AEAD key with the HSM-resident key.  The current implementation
// assumes CKA_EXTRACTABLE=true (the SoftHSM2 default).
package hsm

import (
	"errors"
	"fmt"
	"sync"

	"github.com/miekg/pkcs11"
)

// ── PKCS11Provider ────────────────────────────────────────────────────────────

// PKCS11Provider retrieves the 32-byte AES-256 master key from a PKCS#11
// hardware security module.
//
// The provider is lazily connected on the first call to MasterKey.  The
// derived key is cached in memory and the raw attribute buffer is zeroed
// immediately after reading to minimise exposure.
//
// Only available when built with -tags pkcs11.
type PKCS11Provider struct {
	lib      string
	slot     uint
	pin      string
	keyLabel string

	mu      sync.Mutex
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	derived []byte // 32 bytes; nil until first MasterKey call
	initErr error  // sticky error from library initialisation
	closed  bool
}

// NewPKCS11Provider validates parameters and returns a PKCS11Provider.
//
// The actual PKCS#11 library is loaded and a session opened on the first call
// to MasterKey (lazy initialisation), so the constructor never blocks on HSM
// round-trips.
//
//   - lib:      absolute path to the PKCS#11 shared library (.so / .dll / .dylib).
//   - slot:     token slot index – typically 0 for a single-token deployment.
//   - pin:      HSM user PIN; may be empty if the token has no PIN.
//   - keyLabel: CKA_LABEL of the AES-256 (32-byte) secret key object.
func NewPKCS11Provider(lib string, slot uint, pin, keyLabel string) (*PKCS11Provider, error) {
	if lib == "" {
		return nil, errors.New("hsm.PKCS11Provider: lib path must not be empty")
	}
	if keyLabel == "" {
		return nil, errors.New("hsm.PKCS11Provider: keyLabel must not be empty")
	}
	return &PKCS11Provider{
		lib:      lib,
		slot:     slot,
		pin:      pin,
		keyLabel: keyLabel,
	}, nil
}

// MasterKey returns the 32-byte AES-256 key material extracted from the HSM.
//
// The first call initialises the PKCS#11 library, opens a session, logs in,
// locates the key object by label, and reads CKA_VALUE.  The result is cached;
// subsequent calls return the cached value in O(1).
func (p *PKCS11Provider) MasterKey() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, errors.New("hsm.PKCS11Provider: provider is closed")
	}
	if p.initErr != nil {
		return nil, p.initErr // sticky: don't retry a failed initialisation
	}
	if p.derived != nil {
		return p.derived, nil
	}

	// ── 1. Initialise library ─────────────────────────────────────────────────
	if p.ctx == nil {
		ctx := pkcs11.New(p.lib)
		if ctx == nil {
			p.initErr = fmt.Errorf("hsm.PKCS11Provider: pkcs11.New(%q) returned nil — library not found or incompatible", p.lib)
			return nil, p.initErr
		}
		if err := ctx.Initialize(); err != nil {
			ctx.Destroy()
			p.initErr = fmt.Errorf("hsm.PKCS11Provider: C_Initialize: %w", err)
			return nil, p.initErr
		}
		p.ctx = ctx
	}

	// ── 2. Open session ───────────────────────────────────────────────────────
	session, err := p.ctx.OpenSession(p.slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		p.initErr = fmt.Errorf("hsm.PKCS11Provider: C_OpenSession(slot=%d): %w", p.slot, err)
		return nil, p.initErr
	}
	p.session = session

	// ── 3. Login ──────────────────────────────────────────────────────────────
	if p.pin != "" {
		if err := p.ctx.Login(p.session, pkcs11.CKU_USER, p.pin); err != nil {
			_ = p.ctx.CloseSession(p.session)
			p.initErr = fmt.Errorf("hsm.PKCS11Provider: C_Login: %w", err)
			return nil, p.initErr
		}
	}

	// ── 4. Find key by label ──────────────────────────────────────────────────
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, p.keyLabel),
	}
	if err := p.ctx.FindObjectsInit(p.session, template); err != nil {
		return nil, fmt.Errorf("hsm.PKCS11Provider: C_FindObjectsInit: %w", err)
	}
	handles, _, err := p.ctx.FindObjects(p.session, 2) // ask for 2 to detect ambiguity
	if finErr := p.ctx.FindObjectsFinal(p.session); finErr != nil && err == nil {
		err = finErr
	}
	if err != nil {
		return nil, fmt.Errorf("hsm.PKCS11Provider: C_FindObjects: %w", err)
	}
	switch len(handles) {
	case 0:
		return nil, fmt.Errorf("hsm.PKCS11Provider: no CKO_SECRET_KEY found with CKA_LABEL=%q on slot %d", p.keyLabel, p.slot)
	default: // > 1
		return nil, fmt.Errorf("hsm.PKCS11Provider: ambiguous — %d secret keys share CKA_LABEL=%q; use a unique label", len(handles), p.keyLabel)
	case 1: // exactly one — proceed
	}

	// ── 5. Read CKA_VALUE ─────────────────────────────────────────────────────
	attrs, err := p.ctx.GetAttributeValue(p.session, handles[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("hsm.PKCS11Provider: C_GetAttributeValue(CKA_VALUE): %w\n"+
			"hint: key may have CKA_EXTRACTABLE=false; use C_EncryptInit/C_DecryptInit instead", err)
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, errors.New("hsm.PKCS11Provider: CKA_VALUE attribute is empty")
	}
	if got := len(attrs[0].Value); got != 32 {
		return nil, fmt.Errorf("hsm.PKCS11Provider: CKA_VALUE is %d bytes, want 32 (AES-256)", got)
	}

	// Copy key bytes and zero the attribute buffer immediately.
	key := make([]byte, 32)
	copy(key, attrs[0].Value)
	for i := range attrs[0].Value {
		attrs[0].Value[i] = 0
	}
	p.derived = key
	return p.derived, nil
}

// Close logs out, closes the PKCS#11 session, finalises the library, and
// zeroes all cached key material.  Safe to call multiple times.
func (p *PKCS11Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true

	// Zero cached key material first.
	for i := range p.derived {
		p.derived[i] = 0
	}
	p.derived = nil

	if p.ctx == nil {
		return nil // never initialised
	}

	var errs []string

	if p.pin != "" {
		if err := p.ctx.Logout(p.session); err != nil {
			errs = append(errs, fmt.Sprintf("C_Logout: %v", err))
		}
	}
	if err := p.ctx.CloseSession(p.session); err != nil {
		errs = append(errs, fmt.Sprintf("C_CloseSession: %v", err))
	}
	if err := p.ctx.Finalize(); err != nil {
		errs = append(errs, fmt.Sprintf("C_Finalize: %v", err))
	}
	p.ctx.Destroy()
	p.ctx = nil

	if len(errs) > 0 {
		return fmt.Errorf("hsm.PKCS11Provider.Close: %v", errs)
	}
	return nil
}
