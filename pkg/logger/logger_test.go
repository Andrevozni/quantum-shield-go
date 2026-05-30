package logger_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quantum-shield/quantum-shield-go/pkg/logger"
)

// ── New ───────────────────────────────────────────────────────────────────────

func TestNew_ReturnsLogger(t *testing.T) {
	l := logger.New()
	if l == nil {
		t.Fatal("New() must not return nil")
	}
}

func TestNew_DefaultLevelInfo(t *testing.T) {
	// Without LOG_LEVEL set, default is INFO
	l := logger.New()
	if !l.Enabled(nil, slog.LevelInfo) {
		t.Error("INFO must be enabled by default")
	}
	if l.Enabled(nil, slog.LevelDebug) {
		t.Error("DEBUG must not be enabled at default INFO level")
	}
}

func TestNew_LevelDebug(t *testing.T) {
	t.Setenv("LOG_LEVEL", "DEBUG")
	l := logger.New()
	if !l.Enabled(nil, slog.LevelDebug) {
		t.Error("DEBUG must be enabled when LOG_LEVEL=DEBUG")
	}
}

func TestNew_LevelWarn(t *testing.T) {
	t.Setenv("LOG_LEVEL", "WARN")
	l := logger.New()
	if l.Enabled(nil, slog.LevelInfo) {
		t.Error("INFO must be disabled when LOG_LEVEL=WARN")
	}
	if !l.Enabled(nil, slog.LevelWarn) {
		t.Error("WARN must be enabled when LOG_LEVEL=WARN")
	}
}

func TestNew_LevelError(t *testing.T) {
	t.Setenv("LOG_LEVEL", "ERROR")
	l := logger.New()
	if l.Enabled(nil, slog.LevelWarn) {
		t.Error("WARN must be disabled when LOG_LEVEL=ERROR")
	}
	if !l.Enabled(nil, slog.LevelError) {
		t.Error("ERROR must be enabled when LOG_LEVEL=ERROR")
	}
}

// ── RequestLogger ─────────────────────────────────────────────────────────────

func loggerWithBuffer() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return l, &buf
}

func TestRequestLogger_LogsRequest(t *testing.T) {
	l, buf := loggerWithBuffer()
	h := logger.RequestLogger(l)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test-path", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	var entry map[string]any
	if err := json.NewDecoder(buf).Decode(&entry); err != nil {
		t.Fatalf("parse log entry: %v\nbody: %s", err, buf.String())
	}
	if entry["method"] != "GET" {
		t.Errorf("method: got %v", entry["method"])
	}
	if entry["path"] != "/test-path" {
		t.Errorf("path: got %v", entry["path"])
	}
	if entry["status"] == nil {
		t.Error("status must be logged")
	}
	if entry["latency_ms"] == nil {
		t.Error("latency_ms must be logged")
	}
	if entry["remote_ip"] != "10.0.0.1" {
		t.Errorf("remote_ip: got %v", entry["remote_ip"])
	}
}

func TestRequestLogger_LogsStatus(t *testing.T) {
	l, buf := loggerWithBuffer()
	h := logger.RequestLogger(l)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	var entry map[string]any
	json.NewDecoder(buf).Decode(&entry)
	if entry["status"].(float64) != 404 {
		t.Errorf("expected status 404, got %v", entry["status"])
	}
}

func TestRequestLogger_NoTokenInLog(t *testing.T) {
	l, buf := loggerWithBuffer()
	h := logger.RequestLogger(l)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/auth/token", strings.NewReader(`{"token":"super-secret-jwt"}`))
	req.Header.Set("Authorization", "Bearer very-secret-token-12345")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	logOutput := buf.String()
	if strings.Contains(logOutput, "super-secret") {
		t.Error("token must never appear in logs")
	}
	if strings.Contains(logOutput, "very-secret") {
		t.Error("Authorization header must never appear in logs")
	}
}

func TestRequestLogger_LogsBytesOut(t *testing.T) {
	l, buf := loggerWithBuffer()
	h := logger.RequestLogger(l)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("hello world")) // 11 bytes
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	var entry map[string]any
	json.NewDecoder(buf).Decode(&entry)
	if entry["bytes_out"].(float64) != 11 {
		t.Errorf("expected bytes_out=11, got %v", entry["bytes_out"])
	}
}

func TestRequestLogger_PostPassesThrough(t *testing.T) {
	l, _ := loggerWithBuffer()
	called := false
	h := logger.RequestLogger(l)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/resource", nil))
	if !called {
		t.Error("inner handler must be called")
	}
	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rr.Code)
	}
}
