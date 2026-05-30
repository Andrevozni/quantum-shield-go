// QuantumShield API Server — post-quantum cryptography platform.
//
// # Environment variables — HTTP
//
//	LISTEN_ADDR          TCP address (default ":8443" with TLS, ":8080" without)
//	TLS_CERT_FILE        PEM certificate path (with TLS_KEY_FILE → enables TLS)
//	TLS_KEY_FILE         PEM private key path
//	TLS_AUTO_SELF_SIGNED "true" → auto-generate self-signed cert (dev only)
//	TLS_MIN_VERSION      "1.3" (default) | "1.2"
//	TLS_CLIENT_CA_FILE   PEM CA cert for mutual TLS (mTLS)
//	LOG_LEVEL            DEBUG | INFO | WARN | ERROR
//	ALLOWED_ORIGINS      Comma-separated CORS allow-list
//	BOOTSTRAP_SECRET     Bearer secret for POST /auth/token
//
// # Environment variables — Storage
//
//	REVOCATION_FILE      Persistent JWT revocation list path
//	KEYSTORE_PATH        Encrypted key-store path
//	KEYSTORE_PASSWORD    Keystore password (or KEYSTORE_PASSWORD_FILE)
//	CA_STORE_PATH        Encrypted CA hierarchy file
//	CA_STORE_PASSWORD    CA store password (or CA_STORE_PASSWORD_FILE)
//
// # Environment variables — Raft cluster (all optional)
//
//	QS_CLUSTER_ENABLED   "true" to enable Raft cluster mode
//	QS_CLUSTER_NODE_ID   Unique node identifier (e.g. "node-1")
//	QS_CLUSTER_BIND_ADDR Raft TCP address (e.g. "127.0.0.1:7000" or "qs-node1:7000")
//	QS_CLUSTER_DATA_DIR  Directory for Raft log + snapshots (default "./data/raft")
//	QS_CLUSTER_BOOTSTRAP "true" on the very first node that forms a new cluster
//	QS_CLUSTER_JOIN_ADDR Raft address of an existing leader to join
//	QS_CLUSTER_HTTP_ADDR Full HTTP URL of THIS node for leader-redirect responses
//	                     (e.g. "http://qs-node1:8080").  Clients follow this to
//	                     reach the leader when they land on a follower.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/quantum-shield/quantum-shield-go/internal/cluster"
	"github.com/quantum-shield/quantum-shield-go/pkg/api"
	"github.com/quantum-shield/quantum-shield-go/pkg/logger"
)

// version and buildTime are stamped by the release pipeline via -ldflags.
var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	log := logger.New()

	// ── TLS configuration ────────────────────────────────────────────────────
	certFile   := os.Getenv("TLS_CERT_FILE")
	keyFile    := os.Getenv("TLS_KEY_FILE")
	autoSigned := os.Getenv("TLS_AUTO_SELF_SIGNED") == "true"
	clientCA   := os.Getenv("TLS_CLIENT_CA_FILE")
	tlsEnabled := (certFile != "" && keyFile != "") || autoSigned

	// ── Listen address ───────────────────────────────────────────────────────
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		if tlsEnabled {
			addr = ":8443"
		} else {
			addr = ":8080"
		}
	}

	// ── Raft cluster (optional) ──────────────────────────────────────────────
	var (
		clusterNode     *cluster.Node
		clusterHTTPAddr string
	)
	if os.Getenv("QS_CLUSTER_ENABLED") == "true" {
		var err error
		clusterNode, clusterHTTPAddr, err = startCluster(log)
		if err != nil {
			log.Error("cluster init failed", "err", err)
			os.Exit(1)
		}
	}

	// ── API server ───────────────────────────────────────────────────────────
	var opts []api.Option
	if clusterNode != nil {
		opts = append(opts, api.WithClusterNode(clusterNode, clusterHTTPAddr))
	}

	srv, err := api.New(opts...)
	if err != nil {
		log.Error("failed to initialise server", "err", err)
		os.Exit(1)
	}

	handler := logger.RequestLogger(log)(srv.Handler())

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if tlsEnabled {
		tlsCfg, err := buildTLSConfig(certFile, keyFile, clientCA, autoSigned)
		if err != nil {
			log.Error("TLS configuration failed", "err", err)
			os.Exit(1)
		}
		httpSrv.TLSConfig = tlsCfg
	}

	// ── Graceful shutdown ────────────────────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		proto := "HTTP (plain — dev only)"
		if tlsEnabled {
			proto = "HTTPS · TLS " + tlsVersionLabel()
			if clientCA != "" { proto += " · mTLS" }
			if autoSigned { proto += " · self-signed" }
		}
		clusterMode := "standalone"
		if clusterNode != nil {
			clusterMode = fmt.Sprintf("cluster node=%s bind=%s",
				os.Getenv("QS_CLUSTER_NODE_ID"), os.Getenv("QS_CLUSTER_BIND_ADDR"))
		}

		fmt.Printf("QuantumShield %s  •  built %s\n", version, buildTime)
		fmt.Printf("Algorithms : ML-KEM-768 · ML-DSA-65 · SLH-DSA · AES-256-GCM\n")
		log.Info("server starting", "addr", addr, "proto", proto, "mode", clusterMode)

		var serveErr error
		if tlsEnabled {
			serveErr = httpSrv.ListenAndServeTLS("", "")
		} else {
			serveErr = httpSrv.ListenAndServe()
		}
		if !errors.Is(serveErr, http.ErrServerClosed) {
			log.Error("server failed", "err", serveErr)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	stop()

	log.Info("shutdown signal received — draining connections", "timeout_s", 30)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Error("HTTP drain failed", "err", err)
	}

	// Close HTTP → then cluster → then API resources.
	// Order matters: no request must touch cluster after it shuts down.
	if clusterNode != nil {
		if err := clusterNode.Shutdown(); err != nil {
			log.Error("cluster shutdown error", "err", err)
		}
	}
	srv.Close()
	log.Info("server stopped cleanly")
}

// ── Cluster initialisation ────────────────────────────────────────────────────

// startCluster creates and starts a Raft node from environment variables.
// Returns the node, this node's HTTP base URL, and any error.
func startCluster(log interface{ Error(string, ...any) }) (*cluster.Node, string, error) {
	nodeID   := os.Getenv("QS_CLUSTER_NODE_ID")
	bindAddr := os.Getenv("QS_CLUSTER_BIND_ADDR")
	dataDir  := os.Getenv("QS_CLUSTER_DATA_DIR")
	joinAddr := os.Getenv("QS_CLUSTER_JOIN_ADDR")
	httpAddr := os.Getenv("QS_CLUSTER_HTTP_ADDR")
	bootstrap := os.Getenv("QS_CLUSTER_BOOTSTRAP") == "true"

	if nodeID == "" {
		// Default: use hostname.
		h, _ := os.Hostname()
		nodeID = h
	}
	if bindAddr == "" {
		bindAddr = "127.0.0.1:7000"
	}
	if dataDir == "" {
		dataDir = "./data/raft"
	}

	fsm  := cluster.NewFSM()
	node, err := cluster.NewNode(cluster.Config{
		NodeID:   nodeID,
		BindAddr: bindAddr,
		DataDir:  dataDir,
	}, fsm)
	if err != nil {
		return nil, "", fmt.Errorf("create raft node: %w", err)
	}

	if bootstrap {
		// First node in a new cluster.
		if err := node.Bootstrap(); err != nil {
			node.Shutdown() //nolint:errcheck
			return nil, "", fmt.Errorf("bootstrap cluster: %w", err)
		}
		// Wait for this node to elect itself leader.
		if _, err := node.WaitForLeader(10 * time.Second); err != nil {
			node.Shutdown() //nolint:errcheck
			return nil, "", fmt.Errorf("wait for leader: %w", err)
		}
	} else if joinAddr != "" {
		// Joining an existing cluster: the node starts, then the leader
		// must call POST /cluster/join on our behalf.  In docker-compose
		// the leader's healthcheck must pass before this node starts.
		// For now we wait briefly for the Raft transport to be ready.
		time.Sleep(500 * time.Millisecond)
	}

	return node, httpAddr, nil
}

// ── TLS helpers ───────────────────────────────────────────────────────────────

func buildTLSConfig(certFile, keyFile, clientCAFile string, autoSelf bool) (*tls.Config, error) {
	minVersion := uint16(tls.VersionTLS13)
	if os.Getenv("TLS_MIN_VERSION") == "1.2" {
		minVersion = tls.VersionTLS12
	}
	cfg := &tls.Config{
		MinVersion: minVersion,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		PreferServerCipherSuites: true, //nolint:staticcheck
	}

	var cert tls.Certificate
	var err error
	switch {
	case certFile != "" && keyFile != "":
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS key pair: %w", err)
		}
	case autoSelf:
		cert, err = generateSelfSigned()
		if err != nil {
			return nil, fmt.Errorf("generate self-signed cert: %w", err)
		}
	default:
		return nil, errors.New("TLS enabled but no cert/key provided and TLS_AUTO_SELF_SIGNED != true")
	}
	cfg.Certificates = []tls.Certificate{cert}

	if clientCAFile != "" {
		caPEM, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA %q: %w", clientCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid certs in %q", clientCAFile)
		}
		cfg.ClientCAs  = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

func generateSelfSigned() (tls.Certificate, error) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "QuantumShield (dev self-signed)"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pk.PublicKey, pk)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	pkDER, _ := x509.MarshalECPrivateKey(pk)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pkDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func tlsVersionLabel() string {
	if os.Getenv("TLS_MIN_VERSION") == "1.2" {
		return "1.2+"
	}
	return "1.3"
}
