package castore_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quantum-shield/quantum-shield-go/internal/ca"
	"github.com/quantum-shield/quantum-shield-go/internal/castore"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func tmpPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "ca.qsc")
}

func makeRoot(t *testing.T) *ca.CA {
	t.Helper()
	root, err := ca.Init("CN=Test Root CA,O=Example Corp")
	if err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	return root
}

// ── Store basics ──────────────────────────────────────────────────────────────

func TestStore_SetAndGetRoot(t *testing.T) {
	root := makeRoot(t)
	s := castore.New()
	s.SetRoot(root)
	if s.Root() == nil {
		t.Error("Root() returned nil after SetRoot")
	}
}

func TestStore_SetAndGetIntermediate(t *testing.T) {
	root := makeRoot(t)
	sub, intCert, err := root.IssueIntermediate("CN=Intermediate CA", 0)
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}
	s := castore.New()
	s.SetIntermediate(intCert.Serial, sub)
	if got := s.Intermediate(intCert.Serial); got == nil {
		t.Error("Intermediate() returned nil after SetIntermediate")
	}
	if s.Intermediate("nonexistent") != nil {
		t.Error("Intermediate(unknown) should return nil")
	}
}

func TestStore_Intermediates_Copy(t *testing.T) {
	root := makeRoot(t)
	sub, intCert, _ := root.IssueIntermediate("CN=Sub CA", 0)
	s := castore.New()
	s.SetIntermediate(intCert.Serial, sub)

	m := s.Intermediates()
	if len(m) != 1 {
		t.Errorf("expected 1 intermediate, got %d", len(m))
	}
	// Mutating the returned copy must not affect the store.
	delete(m, intCert.Serial)
	if s.Intermediate(intCert.Serial) == nil {
		t.Error("deleting from Intermediates() copy affected the store")
	}
}

// ── Save / Load round-trip ────────────────────────────────────────────────────

func TestSaveLoad_RootOnly(t *testing.T) {
	path := tmpPath(t)
	root := makeRoot(t)

	// Issue + revoke a cert so the CRL is non-empty.
	cert, _ := root.Issue("CN=leaf.example.com", "ML-KEM-768", []byte("pk"), 0)
	root.Revoke(cert.Serial) //nolint:errcheck

	s := castore.New()
	s.SetRoot(root)
	if err := s.Save(path, "s3cr3t"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	s2, err := castore.Load(path, "s3cr3t")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	root2 := s2.Root()
	if root2 == nil {
		t.Fatal("loaded store has nil root")
	}

	// Certificate identity must survive.
	if root2.Certificate().Subject != root.Certificate().Subject {
		t.Errorf("subject mismatch: %q vs %q",
			root2.Certificate().Subject, root.Certificate().Subject)
	}
	if root2.Certificate().Serial != root.Certificate().Serial {
		t.Errorf("serial mismatch")
	}

	// Loaded CA must still verify certs issued before save.
	cert2, _ := root2.Issue("CN=post-load.example.com", "ML-KEM-768", []byte("pk2"), 0)
	if err := root2.Verify(cert2); err != nil {
		t.Errorf("Verify after load: %v", err)
	}

	// Revocation list must be restored.
	if !root2.IsRevoked(cert.Serial) {
		t.Error("revoked serial not present after load")
	}
}

func TestSaveLoad_WithIntermediates(t *testing.T) {
	path := tmpPath(t)
	root := makeRoot(t)
	sub, intCert, _ := root.IssueIntermediate("CN=Intermediate CA", 0)

	// Issue a leaf via the intermediate.
	leaf, _ := sub.Issue("CN=leaf.example.com", "ML-KEM-768", []byte("pk"), 0)

	s := castore.New()
	s.SetRoot(root)
	s.SetIntermediate(intCert.Serial, sub)
	if err := s.Save(path, "pass123"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	s2, err := castore.Load(path, "pass123")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	sub2 := s2.Intermediate(intCert.Serial)
	if sub2 == nil {
		t.Fatal("intermediate CA not found after load")
	}
	if sub2.Certificate().Subject != "CN=Intermediate CA" {
		t.Errorf("intermediate subject: %q", sub2.Certificate().Subject)
	}

	// Loaded intermediate must verify its pre-save leaf.
	if err := sub2.Verify(leaf); err != nil {
		t.Errorf("sub2.Verify(pre-save leaf): %v", err)
	}

	// Loaded intermediate must still be able to issue new certs.
	leaf2, err := sub2.Issue("CN=post-load.example.com", "ML-KEM-768", []byte("pk2"), 0)
	if err != nil {
		t.Fatalf("sub2.Issue after load: %v", err)
	}
	if err := sub2.Verify(leaf2); err != nil {
		t.Errorf("Verify newly issued cert after load: %v", err)
	}
}

func TestSaveLoad_MultipleIntermediates(t *testing.T) {
	path := tmpPath(t)
	root := makeRoot(t)

	sub1, c1, _ := root.IssueIntermediate("CN=Intermediate CA 1", 0)
	sub2, c2, _ := root.IssueIntermediate("CN=Intermediate CA 2", 0)

	s := castore.New()
	s.SetRoot(root)
	s.SetIntermediate(c1.Serial, sub1)
	s.SetIntermediate(c2.Serial, sub2)
	s.Save(path, "pw") //nolint:errcheck

	s2, err := castore.Load(path, "pw")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ints := s2.Intermediates()
	if len(ints) != 2 {
		t.Errorf("expected 2 intermediates, got %d", len(ints))
	}
}

// ── Wrong password ────────────────────────────────────────────────────────────

func TestLoad_WrongPassword(t *testing.T) {
	path := tmpPath(t)
	s := castore.New()
	s.SetRoot(makeRoot(t))
	s.Save(path, "correct-password") //nolint:errcheck

	_, err := castore.Load(path, "wrong-password")
	if err == nil {
		t.Error("Load with wrong password should return error")
	}
}

// ── Save errors ───────────────────────────────────────────────────────────────

func TestSave_EmptyPassword(t *testing.T) {
	s := castore.New()
	s.SetRoot(makeRoot(t))
	if err := s.Save(tmpPath(t), ""); err == nil {
		t.Error("Save with empty password should fail")
	}
}

func TestLoad_EmptyPassword(t *testing.T) {
	path := tmpPath(t)
	os.WriteFile(path, []byte("dummy"), 0o600) //nolint:errcheck
	if _, err := castore.Load(path, ""); err == nil {
		t.Error("Load with empty password should fail")
	}
}

func TestLoad_NonExistentFile(t *testing.T) {
	_, err := castore.Load("/nonexistent/path/ca.qsc", "password")
	if err == nil {
		t.Error("Load of non-existent file should fail")
	}
}

func TestLoad_CorruptedFile(t *testing.T) {
	path := tmpPath(t)
	os.WriteFile(path, []byte("this is not a valid store file"), 0o600) //nolint:errcheck
	_, err := castore.Load(path, "password")
	if err == nil {
		t.Error("Load of corrupted file should fail")
	}
}

// ── Atomic write — overwrite ──────────────────────────────────────────────────

func TestSave_Overwrite(t *testing.T) {
	path := tmpPath(t)
	root := makeRoot(t)

	// First save.
	s := castore.New()
	s.SetRoot(root)
	s.Save(path, "pw") //nolint:errcheck

	// Modify CA state (revoke a cert) and save again.
	cert, _ := root.Issue("CN=x.example.com", "ML-KEM-768", []byte("pk"), 0)
	root.Revoke(cert.Serial) //nolint:errcheck
	s.Save(path, "pw")       //nolint:errcheck

	// Load must reflect the latest save.
	s2, err := castore.Load(path, "pw")
	if err != nil {
		t.Fatalf("Load after overwrite: %v", err)
	}
	if !s2.Root().IsRevoked(cert.Serial) {
		t.Error("revocation not present after overwrite save/load")
	}
}

// ── Export / Restore ──────────────────────────────────────────────────────────

func TestExportRestore_RoundTrip(t *testing.T) {
	root := makeRoot(t)
	cert, _ := root.Issue("CN=leaf.example.com", "ML-KEM-768", []byte("pk"), 0)
	root.Revoke(cert.Serial) //nolint:errcheck

	snap, err := root.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	restored, err := ca.Restore(snap)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}

	if restored.Certificate().Serial != root.Certificate().Serial {
		t.Errorf("serial mismatch after Restore")
	}
	if !restored.IsRevoked(cert.Serial) {
		t.Error("CRL not preserved across Export/Restore")
	}

	// Restored CA must verify certs issued before export.
	if err := restored.Verify(cert); err == nil {
		// cert was revoked — should fail
		t.Error("Verify revoked cert should fail")
	}

	// Restored CA can issue new certs.
	leaf2, err := restored.Issue("CN=new.example.com", "ML-KEM-768", []byte("pk2"), 0)
	if err != nil {
		t.Fatalf("Issue after Restore: %v", err)
	}
	if err := restored.Verify(leaf2); err != nil {
		t.Errorf("Verify new cert after Restore: %v", err)
	}
}

func TestRestore_InvalidPrivKey(t *testing.T) {
	root := makeRoot(t)
	snap, _ := root.Export()
	snap.PrivKey = "bm90LWEtdmFsaWQta2V5" // base64 of "not-a-valid-key"
	if _, err := ca.Restore(snap); err == nil {
		t.Error("Restore with invalid private key should fail")
	}
}

func TestRestore_NilCertificate(t *testing.T) {
	snap := ca.Snapshot{Version: 1, PrivKey: "dGVzdA=="}
	if _, err := ca.Restore(snap); err == nil {
		t.Error("Restore with nil certificate should fail")
	}
}

func TestRestore_EmptyPrivKey(t *testing.T) {
	root := makeRoot(t)
	snap, _ := root.Export()
	snap.PrivKey = ""
	if _, err := ca.Restore(snap); err == nil {
		t.Error("Restore with empty priv_key should fail")
	}
}

// ── Persistence smoke: revoke after load ─────────────────────────────────────

func TestSaveLoad_RevokeAfterLoad(t *testing.T) {
	path := tmpPath(t)
	root := makeRoot(t)
	cert, _ := root.Issue("CN=revoke-after.example.com", "ML-KEM-768", []byte("pk"), 0)

	s := castore.New()
	s.SetRoot(root)
	s.Save(path, "pw") //nolint:errcheck

	// Load and revoke in the loaded instance.
	s2, _ := castore.Load(path, "pw")
	root2 := s2.Root()
	root2.Revoke(cert.Serial) //nolint:errcheck

	// Save again — revocation must survive a second round-trip.
	s2.Save(path, "pw") //nolint:errcheck

	s3, _ := castore.Load(path, "pw")
	if !s3.Root().IsRevoked(cert.Serial) {
		t.Error("revocation not preserved across two save/load cycles")
	}
}

// ── TTL is preserved ──────────────────────────────────────────────────────────

func TestSaveLoad_CertValidityPreserved(t *testing.T) {
	path := tmpPath(t)
	root := makeRoot(t)

	// Save.
	s := castore.New()
	s.SetRoot(root)
	s.Save(path, "pw") //nolint:errcheck

	// Load.
	s2, _ := castore.Load(path, "pw")
	origNotAfter := root.Certificate().NotAfter
	loadedNotAfter := s2.Root().Certificate().NotAfter

	diff := origNotAfter.Sub(loadedNotAfter)
	if diff < 0 {
		diff = -diff
	}
	if diff > time.Second {
		t.Errorf("NotAfter changed after load: orig=%v loaded=%v", origNotAfter, loadedNotAfter)
	}
}
