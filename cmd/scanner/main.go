// QuantumShield RSA/ECDSA Migration Scanner
//
// Scans source code for quantum-vulnerable cryptographic primitives and
// reports which files and line numbers need to be migrated to post-quantum
// equivalents (ML-KEM-768, ML-DSA-65).
//
// Usage:
//
//	quantum-scanner [flags] [path ...]
//
// Flags:
//
//	-json    output results as JSON
//	-strict  exit code 1 if any findings
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ── Vulnerability patterns ────────────────────────────────────────────────────

type pattern struct {
	id          string
	description string
	severity    string // critical | high | medium
	pqReplacement string
	re          *regexp.Regexp
}

var patterns = []pattern{
	// RSA
	{
		id: "RSA-KEYGEN", severity: "critical",
		description:   "RSA key generation — vulnerable to Shor's algorithm",
		pqReplacement: "ML-KEM-768 (crypto/mlkem) for encryption, ML-DSA-65 (circl) for signatures",
		re: regexp.MustCompile(`(?i)(rsa\.GenerateKey|RSA_generate_key|generateRSAKey|new\s+RSAKey|KeyPairGenerator\.getInstance\("RSA"\))`),
	},
	{
		id: "RSA-ENCRYPT", severity: "critical",
		description:   "RSA encryption (PKCS1v15 / OAEP)",
		pqReplacement: "ML-KEM-768 + AES-256-GCM hybrid encryption",
		re: regexp.MustCompile(`(?i)(rsa\.EncryptOAEP|rsa\.EncryptPKCS1v15|RSA_public_encrypt|Cipher\.getInstance\("RSA)`),
	},
	{
		id: "RSA-SIGN", severity: "critical",
		description:   "RSA signature — vulnerable to Shor's algorithm",
		pqReplacement: "ML-DSA-65 (NIST FIPS 204)",
		re: regexp.MustCompile(`(?i)(rsa\.SignPKCS1v15|rsa\.SignPSS|RSA_sign|\.sign\(.*RSA)`),
	},
	// ECDSA / ECDH
	{
		id: "ECDSA", severity: "critical",
		description:   "ECDSA signature — vulnerable to Shor's algorithm",
		pqReplacement: "ML-DSA-65 (NIST FIPS 204)",
		re: regexp.MustCompile(`(?i)(ecdsa\.Sign|ecdsa\.Verify|EC_sign|EC_verify|Signature\.getInstance\("SHA.*withECDSA"\))`),
	},
	{
		id: "ECDH", severity: "critical",
		description:   "ECDH key exchange — vulnerable to Shor's algorithm",
		pqReplacement: "ML-KEM-768 (NIST FIPS 203)",
		re: regexp.MustCompile(`(?i)(ecdh\.|ECDH\b|elliptic\.P256|elliptic\.P384|elliptic\.P521|KeyAgreement\.getInstance\("ECDH"\))`),
	},
	// Weak symmetric
	{
		id: "DES", severity: "critical",
		description:   "DES/3DES — broken (56-bit key, Sweet32 attack)",
		pqReplacement: "AES-256-GCM",
		re: regexp.MustCompile(`(?i)(des\.New|triple_des|3des|DESKeySpec|\"DES\"|\"DESede\")`),
	},
	{
		id: "AES-128", severity: "high",
		description:   "AES-128 — Grover's algorithm halves security to 64-bit",
		pqReplacement: "AES-256-GCM (doubles Grover cost to 128-bit quantum security)",
		re: regexp.MustCompile(`AES-128|aes\.NewCipher\b`), // AES without explicit 256
	},
	{
		id: "MD5", severity: "high",
		description:   "MD5 hash — collision attacks, broken for security",
		pqReplacement: "SHA-256 or SHA3-256",
		re: regexp.MustCompile(`(?i)(md5\.New|MD5\.digest|MessageDigest\.getInstance\("MD5"\)|crypto/md5)`),
	},
	{
		id: "SHA1", severity: "high",
		description:   "SHA-1 — SHAttered collision attack (2017)",
		pqReplacement: "SHA-256 or SHA3-256",
		re: regexp.MustCompile(`(?i)(sha1\.New|SHA1\b|sha-1|MessageDigest\.getInstance\("SHA-1"\)|crypto/sha1)`),
	},
	// Weak RNG
	{
		id: "WEAK-RNG", severity: "critical",
		description:   "Non-cryptographic RNG — predictable, must not be used for keys/nonces",
		pqReplacement: "crypto/rand (Go) / os.urandom (Python) / /dev/urandom",
		re: regexp.MustCompile(`(?i)(math/rand|rand\.Seed|rand\.Intn|random\.random\(\)|Random\(\)|new\s+Random\(\))`),
	},
	// Hardcoded key indicators
	{
		id: "HARDCODED-KEY", severity: "critical",
		description:   "Potential hardcoded secret key",
		pqReplacement: "Environment variable or secrets manager",
		re: regexp.MustCompile(`(?i)(private_?key\s*=\s*["']|secret\s*=\s*["'][A-Za-z0-9+/]{16,}|api_?key\s*=\s*["'][A-Za-z0-9]{16,})`),
	},
}

// ── Finding ───────────────────────────────────────────────────────────────────

type Finding struct {
	File          string `json:"file"`
	Line          int    `json:"line"`
	PatternID     string `json:"pattern_id"`
	Severity      string `json:"severity"`
	Description   string `json:"description"`
	Snippet       string `json:"snippet"`
	PQReplacement string `json:"pq_replacement"`
}

// ── Scanner ───────────────────────────────────────────────────────────────────

var skipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true,
	".venv": true, "__pycache__": true, "dist": true, "build": true,
}

var scanExts = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true,
	".java": true, ".cs": true, ".cpp": true, ".c": true,
	".rs": true, ".rb": true, ".php": true, ".kt": true, ".swift": true,
}

func scan(root string) ([]Finding, error) {
	var findings []Finding

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !scanExts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			// Skip comment-only lines
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") ||
				strings.HasPrefix(trimmed, "#") ||
				strings.HasPrefix(trimmed, "*") {
				continue
			}
			for _, p := range patterns {
				if p.re.MatchString(line) {
					snippet := strings.TrimSpace(line)
					if len(snippet) > 120 {
						snippet = snippet[:120] + "…"
					}
					findings = append(findings, Finding{
						File:          path,
						Line:          i + 1,
						PatternID:     p.id,
						Severity:      p.severity,
						Description:   p.description,
						Snippet:       snippet,
						PQReplacement: p.pqReplacement,
					})
				}
			}
		}
		return nil
	})
	return findings, err
}

// ── main ─────────────────────────────────────────────────────────────────────

func main() {
	jsonOut := flag.Bool("json", false, "output findings as JSON")
	strict  := flag.Bool("strict", false, "exit 1 if any findings")
	flag.Parse()

	roots := flag.Args()
	if len(roots) == 0 {
		roots = []string{"."}
	}

	var all []Finding
	for _, root := range roots {
		f, err := scan(root)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		}
		all = append(all, f...)
	}

	// Sort: severity (critical first), then file, then line
	sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2}
	sort.Slice(all, func(i, j int) bool {
		si, sj := sevOrder[all[i].Severity], sevOrder[all[j].Severity]
		if si != sj {
			return si < sj
		}
		if all[i].File != all[j].File {
			return all[i].File < all[j].File
		}
		return all[i].Line < all[j].Line
	})

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(map[string]any{
			"total":    len(all),
			"findings": all,
		})
	} else {
		printText(all)
	}

	if *strict && len(all) > 0 {
		os.Exit(1)
	}
}

func printText(findings []Finding) {
	if len(findings) == 0 {
		fmt.Println("✅  No quantum-vulnerable primitives found.")
		return
	}

	// Count by severity
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	fmt.Printf("\n🔍 QuantumShield Migration Scanner\n")
	fmt.Printf("   %d finding(s): %d critical  %d high  %d medium\n\n",
		len(findings), counts["critical"], counts["high"], counts["medium"])

	prevFile := ""
	for _, f := range findings {
		if f.File != prevFile {
			fmt.Printf("📄 %s\n", f.File)
			prevFile = f.File
		}
		sev := map[string]string{
			"critical": "🔴 CRITICAL",
			"high":     "🟠 HIGH    ",
			"medium":   "🟡 MEDIUM  ",
		}[f.Severity]
		fmt.Printf("   %s  line %-5d [%s]\n", sev, f.Line, f.PatternID)
		fmt.Printf("              %s\n", f.Description)
		fmt.Printf("              Snippet: %s\n", f.Snippet)
		fmt.Printf("              → Replace with: %s\n\n", f.PQReplacement)
	}
}
