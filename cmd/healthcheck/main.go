// healthcheck is a minimal HTTP probe compiled into the Docker image.
// It is called by Docker's HEALTHCHECK instruction instead of wget/curl
// (which don't exist in a scratch image).
//
// Usage (in Dockerfile HEALTHCHECK):
//
//	HEALTHCHECK CMD ["/healthcheck"]
//
// Environment variables:
//
//	HEALTH_URL   Full URL to probe (default "http://localhost:8080/health/live")
//	LISTEN_ADDR  Used to derive the port when HEALTH_URL is not set.
//	             e.g. ":8443" → probes "http://localhost:8443/health/live"
package main

import (
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	url := os.Getenv("HEALTH_URL")
	if url == "" {
		addr := os.Getenv("LISTEN_ADDR")
		port := "8080"
		if addr != "" {
			// ":8443" → "8443",  "0.0.0.0:8080" → "8080"
			parts := strings.Split(addr, ":")
			if p := parts[len(parts)-1]; p != "" {
				port = p
			}
		}
		url = "http://localhost:" + port + "/health/live"
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url) //nolint:noctx
	if err != nil {
		os.Exit(1)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
	os.Exit(0)
}
