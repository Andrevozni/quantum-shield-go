// Package logger provides a structured logger (log/slog) for QuantumShield.
// All sensitive fields are explicitly excluded — tokens and keys are NEVER logged.
package logger

import (
	"log/slog"
	"net/http"
	"os"
	"time"
)

// New creates a structured JSON logger that writes to stdout.
// Log level is controlled by the LOG_LEVEL environment variable:
//
//	LOG_LEVEL=DEBUG | INFO (default) | WARN | ERROR
func New() *slog.Logger {
	lvl := slog.LevelInfo
	switch os.Getenv("LOG_LEVEL") {
	case "DEBUG":
		lvl = slog.LevelDebug
	case "WARN":
		lvl = slog.LevelWarn
	case "ERROR":
		lvl = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
	}))
}

// RequestLogger is HTTP middleware that logs every request as a structured JSON line.
// Fields logged: method, path, status, latency_ms, remote_ip, bytes_out.
// Fields NEVER logged: Authorization header, request body, query params.
func RequestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, code: http.StatusOK}
			next.ServeHTTP(rw, r)
			log.Info("request",
				"method",     r.Method,
				"path",       r.URL.Path,
				"status",     rw.code,
				"latency_ms", time.Since(start).Milliseconds(),
				"remote_ip",  remoteIP(r),
				"bytes_out",  rw.written,
			)
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	code    int
	written int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.code = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.written += n
	return n, err
}

func remoteIP(r *http.Request) string {
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
