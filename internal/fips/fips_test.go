package fips_test

import (
	"testing"

	"github.com/quantum-shield/quantum-shield-go/internal/fips"
)

func TestCheck_AllPass(t *testing.T) {
	report := fips.Check()
	if report.Overall != fips.StatusPass {
		t.Errorf("overall status: %s (want pass)", report.Overall)
		for _, p := range report.Probes {
			if p.Status == fips.StatusFail {
				t.Errorf("  FAIL %s: %s", p.Algorithm, p.Error)
			}
		}
	}
}

func TestCheck_AllProbesPresent(t *testing.T) {
	report := fips.Check()

	want := map[string]bool{
		"ML-KEM-768":        false,
		"ML-KEM-1024":       false,
		"ML-DSA-44":         false,
		"ML-DSA-65":         false,
		"ML-DSA-87":         false,
		"SLH-DSA-SHA2-128f": false,
		"SLH-DSA-SHA2-256f": false,
		"AES-256-GCM":       false,
		"HKDF-SHA256":       false,
		"Argon2id":          false,
		"CSPRNG":            false,
	}
	for _, p := range report.Probes {
		if _, expected := want[p.Algorithm]; expected {
			want[p.Algorithm] = true
		}
	}
	for alg, seen := range want {
		if !seen {
			t.Errorf("probe for %q not found in report", alg)
		}
	}
}

func TestCheck_ProbesDurationSet(t *testing.T) {
	report := fips.Check()
	for _, p := range report.Probes {
		if p.DurationMs < 0 {
			t.Errorf("probe %q has negative duration %f", p.Algorithm, p.DurationMs)
		}
	}
}

func TestCheck_TimestampSet(t *testing.T) {
	report := fips.Check()
	if report.Timestamp.IsZero() {
		t.Error("report timestamp should not be zero")
	}
}

func TestCheck_GoVersionSet(t *testing.T) {
	report := fips.Check()
	if report.GoVersion == "" {
		t.Error("report go_version should not be empty")
	}
}

func TestCheck_ProbesHaveStandards(t *testing.T) {
	report := fips.Check()
	for _, p := range report.Probes {
		if p.Standard == "" {
			t.Errorf("probe %q has empty standard", p.Algorithm)
		}
	}
}

func TestCheck_Idempotent(t *testing.T) {
	r1 := fips.Check()
	r2 := fips.Check()
	if r1.Overall != r2.Overall {
		t.Errorf("Check() not idempotent: %s vs %s", r1.Overall, r2.Overall)
	}
	if len(r1.Probes) != len(r2.Probes) {
		t.Errorf("probe count changed between calls: %d vs %d", len(r1.Probes), len(r2.Probes))
	}
}
