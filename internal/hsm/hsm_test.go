package hsm_test

import (
	"bytes"
	"testing"

	"github.com/quantum-shield/quantum-shield-go/internal/hsm"
)

// ── EnvProvider ───────────────────────────────────────────────────────────────

func TestEnvProvider_MasterKey_Returns32Bytes(t *testing.T) {
	p, err := hsm.NewEnvProvider("test-password-1234", "qs-keystore-master-key-v1")
	if err != nil {
		t.Fatalf("NewEnvProvider: %v", err)
	}
	defer p.Close()

	key, err := p.MasterKey()
	if err != nil {
		t.Fatalf("MasterKey: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length %d, want 32", len(key))
	}
}

func TestEnvProvider_MasterKey_Idempotent(t *testing.T) {
	p, err := hsm.NewEnvProvider("stable-password", "qs-keystore-master-key-v1")
	if err != nil {
		t.Fatalf("NewEnvProvider: %v", err)
	}
	defer p.Close()

	k1, err := p.MasterKey()
	if err != nil {
		t.Fatalf("first MasterKey: %v", err)
	}
	k2, err := p.MasterKey()
	if err != nil {
		t.Fatalf("second MasterKey: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("MasterKey returned different values on repeated calls")
	}
}

func TestEnvProvider_MasterKey_DeterministicForSamePassword(t *testing.T) {
	const pw = "reproducible-password"
	const salt = "qs-keystore-master-key-v1"

	p1, _ := hsm.NewEnvProvider(pw, salt)
	defer p1.Close()
	p2, _ := hsm.NewEnvProvider(pw, salt)
	defer p2.Close()

	k1, err := p1.MasterKey()
	if err != nil {
		t.Fatalf("p1 MasterKey: %v", err)
	}
	k2, err := p2.MasterKey()
	if err != nil {
		t.Fatalf("p2 MasterKey: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("same password+salt must yield same master key")
	}
}

func TestEnvProvider_MasterKey_DifferentPasswordYieldsDifferentKey(t *testing.T) {
	const salt = "qs-keystore-master-key-v1"

	p1, _ := hsm.NewEnvProvider("password-alpha", salt)
	defer p1.Close()
	p2, _ := hsm.NewEnvProvider("password-beta", salt)
	defer p2.Close()

	k1, _ := p1.MasterKey()
	k2, _ := p2.MasterKey()
	if bytes.Equal(k1, k2) {
		t.Error("different passwords must yield different keys")
	}
}

func TestEnvProvider_MasterKey_DifferentSaltYieldsDifferentKey(t *testing.T) {
	const pw = "shared-password"

	p1, _ := hsm.NewEnvProvider(pw, "domain-salt-one")
	defer p1.Close()
	p2, _ := hsm.NewEnvProvider(pw, "domain-salt-two")
	defer p2.Close()

	k1, _ := p1.MasterKey()
	k2, _ := p2.MasterKey()
	if bytes.Equal(k1, k2) {
		t.Error("different salts must yield different keys")
	}
}

func TestEnvProvider_Close_PreventsSubsequentUse(t *testing.T) {
	p, _ := hsm.NewEnvProvider("some-password", "some-salt")

	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err := p.MasterKey()
	if err == nil {
		t.Error("expected error calling MasterKey after Close")
	}
}

func TestEnvProvider_Close_Idempotent(t *testing.T) {
	p, _ := hsm.NewEnvProvider("pw", "salt")
	if err := p.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close (should be a no-op): %v", err)
	}
}

func TestNewEnvProvider_EmptyPassword(t *testing.T) {
	_, err := hsm.NewEnvProvider("", "some-salt")
	if err == nil {
		t.Error("expected error for empty password")
	}
}

func TestNewEnvProvider_EmptyDomainSalt(t *testing.T) {
	_, err := hsm.NewEnvProvider("some-password", "")
	if err == nil {
		t.Error("expected error for empty domainSalt")
	}
}

// ── Interface compliance ───────────────────────────────────────────────────────

// Compile-time check: EnvProvider implements MasterKeyProvider.
var _ hsm.MasterKeyProvider = (*hsm.EnvProvider)(nil)
