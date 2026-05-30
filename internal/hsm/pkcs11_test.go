//go:build pkcs11

package hsm_test

import (
	"os"
	"strconv"
	"testing"

	"github.com/quantum-shield/quantum-shield-go/internal/hsm"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// softhsmEnv reads the four environment variables used by the PKCS#11 provider.
// Returns ("", 0, "", "") when QS_PKCS11_LIB is unset (integration tests skip).
func softhsmEnv() (lib string, slot uint, pin, label string) {
	lib = os.Getenv("QS_PKCS11_LIB")
	if lib == "" {
		return
	}
	slotStr := os.Getenv("QS_PKCS11_SLOT")
	if s, err := strconv.ParseUint(slotStr, 10, 64); err == nil {
		slot = uint(s)
	}
	pin = os.Getenv("QS_PKCS11_PIN")
	label = os.Getenv("QS_PKCS11_KEY_LABEL")
	if label == "" {
		label = "qs-master-key" // conventional default
	}
	return
}

func skipIfNoHSM(t *testing.T) (lib string, slot uint, pin, label string) {
	t.Helper()
	lib, slot, pin, label = softhsmEnv()
	if lib == "" {
		t.Skip("QS_PKCS11_LIB not set — skipping PKCS#11 integration tests")
	}
	return
}

// ── Constructor validation (no HSM required) ──────────────────────────────────

func TestNewPKCS11Provider_EmptyLib(t *testing.T) {
	_, err := hsm.NewPKCS11Provider("", 0, "pin", "label")
	if err == nil {
		t.Error("expected error for empty lib, got nil")
	}
}

func TestNewPKCS11Provider_EmptyLabel(t *testing.T) {
	_, err := hsm.NewPKCS11Provider("/usr/lib/libsofthsm2.so", 0, "pin", "")
	if err == nil {
		t.Error("expected error for empty keyLabel, got nil")
	}
}

func TestNewPKCS11Provider_ValidParams(t *testing.T) {
	p, err := hsm.NewPKCS11Provider("/usr/lib/libsofthsm2.so", 0, "pin", "my-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestPKCS11Provider_CloseBeforeMasterKey(t *testing.T) {
	p, err := hsm.NewPKCS11Provider("/usr/lib/libsofthsm2.so", 0, "pin", "my-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Close without ever calling MasterKey must not panic.
	if err := p.Close(); err != nil {
		t.Errorf("Close (before MasterKey) returned error: %v", err)
	}
}

func TestPKCS11Provider_MasterKeyAfterClose(t *testing.T) {
	p, err := hsm.NewPKCS11Provider("/usr/lib/libsofthsm2.so", 0, "pin", "my-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = p.Close()
	_, err = p.MasterKey()
	if err == nil {
		t.Error("expected error calling MasterKey after Close")
	}
}

func TestPKCS11Provider_DoubleClose(t *testing.T) {
	p, err := hsm.NewPKCS11Provider("/usr/lib/libsofthsm2.so", 0, "pin", "my-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = p.Close()
	if err := p.Close(); err != nil {
		t.Errorf("second Close returned error: %v", err)
	}
}

func TestPKCS11Provider_BadLibReturnsError(t *testing.T) {
	p, err := hsm.NewPKCS11Provider("/nonexistent/libpkcs11.so", 0, "pin", "my-key")
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}
	// MasterKey must fail because the library does not exist.
	_, err = p.MasterKey()
	if err == nil {
		t.Error("expected error for non-existent library, got nil")
	}
	// Second call must return the same sticky error.
	_, err2 := p.MasterKey()
	if err2 == nil {
		t.Error("expected sticky error on second MasterKey call, got nil")
	}
}

// ── Integration tests (require QS_PKCS11_LIB + pre-provisioned key) ──────────

// TestPKCS11_Integration_MasterKey verifies the full path:
// C_Initialize → C_OpenSession → C_Login → C_FindObjects → C_GetAttributeValue.
//
// Prerequisites (SoftHSM2):
//
//	softhsm2-util --init-token --slot 0 --label "qs-token" \
//	              --so-pin changeit --pin changeit
//	pkcs11-tool --module libsofthsm2.so --login --pin changeit \
//	            --keygen --key-type AES:32 --label qs-master-key
//
// Then run:
//
//	go test -tags pkcs11 ./internal/hsm/... \
//	  -run TestPKCS11_Integration \
//	  QS_PKCS11_LIB=/usr/lib/softhsm/libsofthsm2.so \
//	  QS_PKCS11_PIN=changeit \
//	  QS_PKCS11_KEY_LABEL=qs-master-key
func TestPKCS11_Integration_MasterKey(t *testing.T) {
	lib, slot, pin, label := skipIfNoHSM(t)

	p, err := hsm.NewPKCS11Provider(lib, slot, pin, label)
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	key, err := p.MasterKey()
	if err != nil {
		t.Fatalf("MasterKey: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("MasterKey returned %d bytes, want 32", len(key))
	}

	// Must not be all-zero.
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("MasterKey returned all-zero key — suspicious")
	}
}

func TestPKCS11_Integration_Idempotent(t *testing.T) {
	lib, slot, pin, label := skipIfNoHSM(t)

	p, err := hsm.NewPKCS11Provider(lib, slot, pin, label)
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	key1, err := p.MasterKey()
	if err != nil {
		t.Fatalf("first MasterKey: %v", err)
	}
	key2, err := p.MasterKey()
	if err != nil {
		t.Fatalf("second MasterKey: %v", err)
	}
	if len(key1) != len(key2) {
		t.Fatalf("key lengths differ: %d vs %d", len(key1), len(key2))
	}
	for i := range key1 {
		if key1[i] != key2[i] {
			t.Errorf("key mismatch at byte %d", i)
			break
		}
	}
}

func TestPKCS11_Integration_WrongLabel(t *testing.T) {
	lib, slot, pin, _ := skipIfNoHSM(t)

	p, err := hsm.NewPKCS11Provider(lib, slot, pin, "no-such-key-xxxxxxxx")
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	_, err = p.MasterKey()
	if err == nil {
		t.Error("expected error for non-existent key label, got nil")
	}
}

func TestPKCS11_Integration_CloseZeroesKey(t *testing.T) {
	lib, slot, pin, label := skipIfNoHSM(t)

	p, err := hsm.NewPKCS11Provider(lib, slot, pin, label)
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}

	key, err := p.MasterKey()
	if err != nil {
		t.Fatalf("MasterKey: %v", err)
	}
	// Capture a copy.
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	if err := p.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	// After Close the returned slice should be zeroed.
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("key slice was not zeroed after Close")
	}
}

func TestPKCS11_Integration_MasterKeyAfterClose(t *testing.T) {
	lib, slot, pin, label := skipIfNoHSM(t)

	p, err := hsm.NewPKCS11Provider(lib, slot, pin, label)
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}

	_, err = p.MasterKey()
	if err != nil {
		t.Fatalf("MasterKey: %v", err)
	}

	_ = p.Close()

	_, err = p.MasterKey()
	if err == nil {
		t.Error("expected error calling MasterKey after Close, got nil")
	}
}
