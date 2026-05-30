// qs — QuantumShield command-line client.
//
// Usage:
//
//	qs [--server URL] [--token TOKEN] [--insecure] [--json] <command> [flags]
//
// Global flags (must come before the command):
//
//	--server URL     QuantumShield server base URL
//	                 (default: $QS_SERVER or http://localhost:8080)
//	--token TOKEN    Bearer token for authenticated requests
//	                 (default: $QS_TOKEN)
//	--insecure       Skip TLS certificate verification (dev/test only)
//	--json           Print raw JSON responses instead of formatted output
//
// Commands:
//
//	health                              Check server liveness
//	key generate [--algorithm A]        Generate a key pair
//	key list                            List stored key IDs
//	sign --key ID [--algorithm A] MSG   Sign a message (MSG is base64 or a @file path)
//	verify --key ID --sig SIG MSG       Verify a signature
//	encrypt --key ID DATA               Encrypt data (DATA is base64 or a @file path)
//	decrypt --key ID DATA               Decrypt ciphertext (DATA is base64)
//	ca init --subject DN                Initialise the CA
//	ca sign --subject DN --key ID       Issue a certificate for a public key
//	ca verify CERT_JSON                 Verify a JSON certificate
//	token issue --user ID --roles ROLES Issue a bearer token
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// version is stamped by the release pipeline via -ldflags.
var version = "dev"

// ── Global client ─────────────────────────────────────────────────────────────

type client struct {
	server   string
	token    string
	insecure bool
	rawJSON  bool
	http     *http.Client
}

func newClient(server, token string, insecure, rawJSON bool) *client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec — explicit user opt-in
	}
	return &client{
		server:  strings.TrimRight(server, "/"),
		token:   token,
		insecure: insecure,
		rawJSON: rawJSON,
		http:    &http.Client{Transport: tr, Timeout: 30 * time.Second},
	}
}

// do sends a JSON request and returns the parsed response body and status code.
func (c *client) do(method, path string, body any) (map[string]any, int, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, 0, fmt.Errorf("encode request: %w", err)
		}
	}

	req, err := http.NewRequest(method, c.server+path, &buf)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}

	var result map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("decode response (status=%d body=%s): %w",
				resp.StatusCode, raw, err)
		}
	}
	return result, resp.StatusCode, nil
}

// print outputs data to stdout. With --json, it emits pretty JSON;
// otherwise it calls the supplied formatter for human-readable output.
func (c *client) print(data map[string]any, format func(map[string]any)) {
	if c.rawJSON {
		b, _ := json.MarshalIndent(data, "", "  ")
		fmt.Println(string(b))
		return
	}
	format(data)
}

// require asserts HTTP 2xx and exits on failure.
func require2xx(code int, data map[string]any, context string) {
	if code >= 200 && code < 300 {
		return
	}
	errMsg := ""
	if e, ok := data["error"].(string); ok {
		errMsg = e
	}
	fatalf("%s: HTTP %d — %s", context, code, errMsg)
}

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	server  := flag.String("server", envOr("QS_SERVER", "http://localhost:8080"), "server base URL")
	token   := flag.String("token", envOr("QS_TOKEN", ""), "bearer token")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification")
	rawJSON := flag.Bool("json", false, "output raw JSON")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Printf("qs %s\n", version)
		return
	}

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	c := newClient(*server, *token, *insecure, *rawJSON)

	switch args[0] {
	case "health":
		cmdHealth(c, args[1:])
	case "key":
		cmdKey(c, args[1:])
	case "sign":
		cmdSign(c, args[1:])
	case "verify":
		cmdVerify(c, args[1:])
	case "encrypt":
		cmdEncrypt(c, args[1:])
	case "decrypt":
		cmdDecrypt(c, args[1:])
	case "ca":
		cmdCA(c, args[1:])
	case "token":
		cmdToken(c, args[1:])
	default:
		fatalf("unknown command %q — run 'qs --help' for usage", args[0])
	}
}

// ── health ────────────────────────────────────────────────────────────────────

func cmdHealth(c *client, _ []string) {
	data, code, err := c.do("GET", "/health/live", nil)
	dieOnErr(err)
	require2xx(code, data, "health")
	c.print(data, func(d map[string]any) {
		status, _ := d["status"].(string)
		fmt.Printf("status: %s\n", status)
	})
}

// ── key ───────────────────────────────────────────────────────────────────────

func cmdKey(c *client, args []string) {
	if len(args) == 0 {
		fatalf("usage: qs key <generate|list>")
	}
	switch args[0] {
	case "generate":
		cmdKeyGenerate(c, args[1:])
	case "list":
		cmdKeyList(c, args[1:])
	default:
		fatalf("unknown key sub-command %q", args[0])
	}
}

func cmdKeyGenerate(c *client, args []string) {
	fs := flag.NewFlagSet("key generate", flag.ExitOnError)
	algorithm := fs.String("algorithm", "ML-KEM-768", "key algorithm (ML-KEM-768 or ML-KEM-1024)")
	name      := fs.String("name", "", "key ID (auto-generated if empty)")
	fs.Parse(args) //nolint:errcheck — ExitOnError

	body := map[string]any{"algorithm": *algorithm}
	if *name != "" {
		body["key_id"] = *name
	}

	data, code, err := c.do("POST", "/keys/generate", body)
	dieOnErr(err)
	require2xx(code, data, "key generate")
	c.print(data, func(d map[string]any) {
		fmt.Printf("key_id:    %s\n", d["key_id"])
		fmt.Printf("algorithm: %s\n", d["algorithm"])
		if pk, ok := d["public_key"].(string); ok {
			short := pk
			if len(short) > 64 {
				short = short[:64] + "…"
			}
			fmt.Printf("public_key: %s\n", short)
		}
	})
}

func cmdKeyList(c *client, _ []string) {
	data, code, err := c.do("GET", "/keys", nil)
	dieOnErr(err)
	require2xx(code, data, "key list")
	c.print(data, func(d map[string]any) {
		count, _ := d["count"].(float64)
		backend, _ := d["backend"].(string)
		fmt.Printf("count:   %d\nbackend: %s\n", int(count), backend)
		if keys, ok := d["keys"].([]any); ok {
			for _, k := range keys {
				fmt.Printf("  - %s\n", k)
			}
		}
	})
}

// ── sign ──────────────────────────────────────────────────────────────────────

func cmdSign(c *client, args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyID     := fs.String("key", "", "key ID to sign with (required)")
	algorithm := fs.String("algorithm", "ML-DSA-65", "signing algorithm")
	fs.Parse(args) //nolint:errcheck

	if *keyID == "" {
		fatalf("sign: --key is required")
	}
	msg := readArgOrStdin(fs.Args(), "message")

	data, code, err := c.do("POST", "/sign", map[string]any{
		"key_id":    *keyID,
		"algorithm": *algorithm,
		"message":   msg,
	})
	dieOnErr(err)
	require2xx(code, data, "sign")
	c.print(data, func(d map[string]any) {
		fmt.Printf("key_id:    %s\n", d["key_id"])
		fmt.Printf("algorithm: %s\n", d["algorithm"])
		fmt.Printf("signature: %s\n", d["signature"])
	})
}

// ── verify ────────────────────────────────────────────────────────────────────

func cmdVerify(c *client, args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	keyID := fs.String("key", "", "key ID that produced the signature (required)")
	sig   := fs.String("sig", "", "base64-encoded signature (required)")
	fs.Parse(args) //nolint:errcheck

	if *keyID == "" || *sig == "" {
		fatalf("verify: --key and --sig are required")
	}
	msg := readArgOrStdin(fs.Args(), "message")

	data, code, err := c.do("POST", "/verify-signature", map[string]any{
		"key_id":    *keyID,
		"message":   msg,
		"signature": *sig,
	})
	dieOnErr(err)
	require2xx(code, data, "verify")
	c.print(data, func(d map[string]any) {
		valid, _ := d["valid"].(bool)
		if valid {
			fmt.Println("✓ signature valid")
		} else {
			fmt.Fprintln(os.Stderr, "✗ signature INVALID")
			os.Exit(1)
		}
	})
}

// ── encrypt ───────────────────────────────────────────────────────────────────

func cmdEncrypt(c *client, args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	keyID := fs.String("key", "", "recipient key ID (required)")
	fs.Parse(args) //nolint:errcheck

	if *keyID == "" {
		fatalf("encrypt: --key is required")
	}
	plaintext := readArgOrStdin(fs.Args(), "data")

	data, code, err := c.do("POST", "/encrypt", map[string]any{
		"key_id":    *keyID,
		"plaintext": plaintext,
	})
	dieOnErr(err)
	require2xx(code, data, "encrypt")
	c.print(data, func(d map[string]any) {
		fmt.Printf("ciphertext: %s\n", d["ciphertext"])
		if ct, ok := d["ciphertext_type"].(string); ok {
			fmt.Printf("type:       %s\n", ct)
		}
	})
}

// ── decrypt ───────────────────────────────────────────────────────────────────

func cmdDecrypt(c *client, args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	keyID := fs.String("key", "", "key ID (required)")
	fs.Parse(args) //nolint:errcheck

	if *keyID == "" {
		fatalf("decrypt: --key is required")
	}
	ciphertext := readArgOrStdin(fs.Args(), "ciphertext")

	data, code, err := c.do("POST", "/decrypt", map[string]any{
		"key_id":     *keyID,
		"ciphertext": ciphertext,
	})
	dieOnErr(err)
	require2xx(code, data, "decrypt")
	c.print(data, func(d map[string]any) {
		fmt.Printf("plaintext: %s\n", d["plaintext"])
	})
}

// ── ca ────────────────────────────────────────────────────────────────────────

func cmdCA(c *client, args []string) {
	if len(args) == 0 {
		fatalf("usage: qs ca <init|sign|verify>")
	}
	switch args[0] {
	case "init":
		cmdCAInit(c, args[1:])
	case "sign":
		cmdCASign(c, args[1:])
	case "verify":
		cmdCAVerify(c, args[1:])
	case "crl":
		cmdCACRL(c)
	case "cert", "certificate":
		cmdCACert(c)
	default:
		fatalf("unknown ca sub-command %q", args[0])
	}
}

func cmdCAInit(c *client, args []string) {
	fs := flag.NewFlagSet("ca init", flag.ExitOnError)
	subject := fs.String("subject", "", "CA subject DN, e.g. CN=Root CA,O=Acme (required)")
	fs.Parse(args) //nolint:errcheck

	if *subject == "" {
		fatalf("ca init: --subject is required")
	}

	data, code, err := c.do("POST", "/ca/init", map[string]string{"subject": *subject})
	dieOnErr(err)
	require2xx(code, data, "ca init")
	c.print(data, func(d map[string]any) {
		if cert, ok := d["certificate"].(map[string]any); ok {
			printCert(cert)
		} else {
			printCert(d)
		}
	})
}

func cmdCASign(c *client, args []string) {
	fs := flag.NewFlagSet("ca sign", flag.ExitOnError)
	subject    := fs.String("subject", "", "leaf certificate subject DN (required)")
	keyID      := fs.String("key", "", "key ID whose public key to certify (required)")
	keyType    := fs.String("key-type", "ML-KEM-768", "public key algorithm type")
	ttlStr     := fs.String("ttl", "", "certificate TTL, e.g. 8760h (default: 1 year)")
	publicKey  := fs.String("public-key", "", "explicit base64 public key (alternative to --key)")
	fs.Parse(args) //nolint:errcheck

	if *subject == "" {
		fatalf("ca sign: --subject is required")
	}

	body := map[string]any{
		"subject":         *subject,
		"public_key_type": *keyType,
	}

	// Resolve the public key: either from --key (fetch from server) or --public-key.
	if *publicKey != "" {
		body["public_key"] = *publicKey
	} else if *keyID != "" {
		// Fetch the public key from the server.
		pkData, pkCode, pkErr := c.do("GET", "/keys/"+*keyID+"/public", nil)
		dieOnErr(pkErr)
		require2xx(pkCode, pkData, "key/public")
		pk, _ := pkData["public_key"].(string)
		if pk == "" {
			fatalf("ca sign: could not retrieve public key for %s", *keyID)
		}
		body["public_key"] = pk
	} else {
		fatalf("ca sign: either --key or --public-key is required")
	}

	if *ttlStr != "" {
		d, err := time.ParseDuration(*ttlStr)
		if err != nil {
			fatalf("ca sign: invalid --ttl %q: %v", *ttlStr, err)
		}
		body["ttl_seconds"] = int64(d.Seconds())
	}

	data, code, err := c.do("POST", "/ca/sign", body)
	dieOnErr(err)
	require2xx(code, data, "ca sign")
	c.print(data, func(d map[string]any) {
		if cert, ok := d["certificate"].(map[string]any); ok {
			printCert(cert)
		} else {
			printCert(d)
		}
	})
}

func cmdCAVerify(c *client, args []string) {
	fs := flag.NewFlagSet("ca verify", flag.ExitOnError)
	fs.Parse(args) //nolint:errcheck

	certJSON := readArgOrStdin(fs.Args(), "certificate JSON")

	// The certificate is passed as a JSON object, not a string.
	var certObj map[string]any
	if err := json.Unmarshal([]byte(certJSON), &certObj); err != nil {
		fatalf("ca verify: invalid certificate JSON: %v", err)
	}

	data, code, err := c.do("POST", "/ca/verify", map[string]any{"certificate": certObj})
	dieOnErr(err)
	require2xx(code, data, "ca verify")
	c.print(data, func(d map[string]any) {
		valid, _ := d["valid"].(bool)
		if valid {
			fmt.Println("✓ certificate valid")
		} else {
			msg, _ := d["error"].(string)
			fmt.Fprintf(os.Stderr, "✗ certificate INVALID: %s\n", msg)
			os.Exit(1)
		}
	})
}

func cmdCACRL(c *client) {
	data, code, err := c.do("GET", "/ca/crl", nil)
	dieOnErr(err)
	require2xx(code, data, "ca crl")
	c.print(data, func(d map[string]any) {
		issuer, _ := d["issuer"].(string)
		fmt.Printf("issuer: %s\n", issuer)
		entries, _ := d["entries"].([]any)
		fmt.Printf("revoked: %d certificate(s)\n", len(entries))
		for _, e := range entries {
			if entry, ok := e.(map[string]any); ok {
				fmt.Printf("  serial=%s  revoked_at=%s\n", entry["serial"], entry["revoked_at"])
			}
		}
	})
}

func cmdCACert(c *client) {
	data, code, err := c.do("GET", "/ca/certificate", nil)
	dieOnErr(err)
	require2xx(code, data, "ca certificate")
	c.print(data, func(d map[string]any) {
		printCert(d)
	})
}

// ── token ─────────────────────────────────────────────────────────────────────

func cmdToken(c *client, args []string) {
	if len(args) == 0 {
		fatalf("usage: qs token issue --user ID --roles ROLES")
	}
	switch args[0] {
	case "issue":
		cmdTokenIssue(c, args[1:])
	default:
		fatalf("unknown token sub-command %q", args[0])
	}
}

func cmdTokenIssue(c *client, args []string) {
	fs := flag.NewFlagSet("token issue", flag.ExitOnError)
	userID := fs.String("user", "", "user ID / subject claim (required)")
	roles  := fs.String("roles", "read", "comma-separated role list (read,write,admin)")
	fs.Parse(args) //nolint:errcheck

	if *userID == "" {
		fatalf("token issue: --user is required")
	}
	roleList := strings.Split(*roles, ",")
	for i, r := range roleList {
		roleList[i] = strings.TrimSpace(r)
	}

	data, code, err := c.do("POST", "/auth/token", map[string]any{
		"user_id": *userID,
		"roles":   roleList,
	})
	dieOnErr(err)
	require2xx(code, data, "token issue")
	c.print(data, func(d map[string]any) {
		fmt.Printf("token:   %s\n", d["token"])
		fmt.Printf("expires: %s\n", d["expires_at"])
		fmt.Printf("subject: %s\n", d["subject"])
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "qs: "+format+"\n", args...)
	os.Exit(1)
}

func dieOnErr(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

// readArgOrStdin returns the first positional argument, or reads from stdin
// if no arguments are provided.  Supports "@path" file references.
func readArgOrStdin(args []string, what string) string {
	if len(args) > 0 {
		v := args[0]
		if strings.HasPrefix(v, "@") {
			b, err := os.ReadFile(v[1:])
			if err != nil {
				fatalf("read %s file %s: %v", what, v[1:], err)
			}
			return strings.TrimRight(string(b), "\n")
		}
		return v
	}
	// Fall back to stdin.
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatalf("read %s from stdin: %v", what, err)
	}
	return strings.TrimRight(string(b), "\n")
}

// printCert formats a certificate map for human-readable output.
func printCert(cert map[string]any) {
	fields := []struct{ key, label string }{
		{"serial", "serial"},
		{"subject", "subject"},
		{"issuer", "issuer"},
		{"algorithm", "algorithm"},
		{"public_key_type", "key_type"},
		{"is_ca", "is_ca"},
		{"not_before", "not_before"},
		{"not_after", "not_after"},
		{"version", "version"},
	}
	for _, f := range fields {
		if v, ok := cert[f.key]; ok && v != nil {
			fmt.Printf("%-12s %v\n", f.label+":", v)
		}
	}
	if sig, ok := cert["signature"].(string); ok {
		short := sig
		if len(short) > 64 {
			short = short[:64] + "…"
		}
		fmt.Printf("%-12s %s\n", "signature:", short)
	}
}

// usage prints global help.
func usage() {
	fmt.Fprintf(os.Stderr, `qs %s — QuantumShield command-line client

Usage:
  qs [global flags] <command> [command flags]

Global flags:
  --server URL     Server base URL (default: $QS_SERVER or http://localhost:8080)
  --token TOKEN    Bearer token   (default: $QS_TOKEN)
  --insecure       Skip TLS certificate verification
  --json           Output raw JSON
  --version        Print version and exit

Commands:
  health                                  Check server liveness
  key generate [--algorithm A] [--name N] Generate a key pair
  key list                                List stored key IDs
  sign --key ID [--algorithm A] <msg>     Sign a message
  verify --key ID --sig SIG <msg>         Verify a signature
  encrypt --key ID <data>                 Encrypt data
  decrypt --key ID <ciphertext>           Decrypt data
  ca init --subject DN                    Initialise the CA
  ca sign --subject DN --key ID           Issue a certificate
  ca verify <cert-json>                   Verify a certificate
  ca crl                                  Show the certificate revocation list
  ca cert                                 Show the CA root certificate
  token issue --user ID --roles ROLES     Issue a bearer token

Use '@path' to read arguments from a file (e.g. qs sign --key k1 @message.b64).
`, version)
}
