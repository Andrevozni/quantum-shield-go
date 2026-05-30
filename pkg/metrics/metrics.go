// Package metrics provides lightweight Prometheus-compatible metrics for QuantumShield.
// Uses only stdlib (expvar + net/http) — no external dependencies.
//
// Exposed at GET /metrics in Prometheus text exposition format (0.0.4).
//
// Metric families:
//
//	Unlabeled:  Counter, Gauge, Histogram  — simple single-series metrics
//	Labeled:    CounterVec, HistogramVec   — multi-series families with label sets
package metrics

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ── Registry ──────────────────────────────────────────────────────────────────

// Registry holds all metrics for the process.
// All methods are safe for concurrent use.
type Registry struct {
	mu             sync.RWMutex
	counters       map[string]*Counter
	gauges         map[string]*Gauge
	histograms     map[string]*Histogram
	counterVecs    map[string]*CounterVec
	histogramVecs  map[string]*HistogramVec
	pathNormalizer func(string) string // normalizes request paths for the `path` label
	startTime      time.Time
}

// New creates a new metrics Registry.
func New() *Registry {
	r := &Registry{
		counters:      make(map[string]*Counter),
		gauges:        make(map[string]*Gauge),
		histograms:    make(map[string]*Histogram),
		counterVecs:   make(map[string]*CounterVec),
		histogramVecs: make(map[string]*HistogramVec),
		startTime:     time.Now(),
	}
	// Built-in: process start timestamp (enables uptime calculation in Grafana).
	r.MustGauge("qs_process_start_time_seconds", "Unix timestamp when the process started")
	r.Gauge("qs_process_start_time_seconds").Set(float64(r.startTime.Unix()))
	return r
}

// SetPathNormalizer registers a function that normalizes URL paths before they
// are used as label values in HTTP metrics. Without a normalizer, the raw
// request path (including path parameters like key IDs) is used — this leads
// to unbounded label cardinality. The normalizer should collapse path parameters
// to a fixed placeholder, e.g. "/keystore/abc123/rotate" → "/keystore/{id}/rotate".
func (r *Registry) SetPathNormalizer(fn func(string) string) {
	r.mu.Lock()
	r.pathNormalizer = fn
	r.mu.Unlock()
}

func (r *Registry) normalizePath(path string) string {
	r.mu.RLock()
	fn := r.pathNormalizer
	r.mu.RUnlock()
	if fn == nil {
		return path
	}
	return fn(path)
}

// ── Counter ───────────────────────────────────────────────────────────────────

// Counter is a monotonically increasing integer metric.
type Counter struct {
	name string
	help string
	val  atomic.Int64
}

func (c *Counter) Inc()         { c.val.Add(1) }
func (c *Counter) Add(n int64)  { c.val.Add(n) }
func (c *Counter) Value() int64 { return c.val.Load() }

// MustCounter registers and returns a named Counter. Panics on duplicate name.
func (r *Registry) MustCounter(name, help string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.counters[name]; ok {
		panic("metrics: duplicate counter " + name)
	}
	c := &Counter{name: name, help: help}
	r.counters[name] = c
	return c
}

// Counter returns an existing Counter by name. Panics if not found.
func (r *Registry) Counter(name string) *Counter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.counters[name]
	if !ok {
		panic("metrics: counter not registered: " + name)
	}
	return c
}

// ── CounterVec ────────────────────────────────────────────────────────────────

// CounterVec is a labeled counter family. Each unique combination of label
// values is a separate counter series. All series share the same HELP and
// TYPE metadata and are rendered together in the Prometheus output.
type CounterVec struct {
	name    string
	help    string
	mu      sync.RWMutex
	entries map[string]*cvEntry // canonicalKey(labels) → entry
}

type cvEntry struct {
	labelStr string // Prometheus formatted: {key="val",...}
	val      atomic.Int64
}

// With returns (or creates) the counter for the given label set.
// Safe for concurrent use — concurrent With calls for the same labels return
// the same underlying counter.
func (cv *CounterVec) With(labels map[string]string) *cvEntry {
	key := canonicalKey(labels)
	cv.mu.RLock()
	e, ok := cv.entries[key]
	cv.mu.RUnlock()
	if ok {
		return e
	}
	cv.mu.Lock()
	defer cv.mu.Unlock()
	if e, ok = cv.entries[key]; ok {
		return e
	}
	e = &cvEntry{labelStr: formatLabels(labels)}
	cv.entries[key] = e
	return e
}

func (e *cvEntry) Inc()        { e.val.Add(1) }
func (e *cvEntry) Add(n int64) { e.val.Add(n) }
func (e *cvEntry) Value() int64 { return e.val.Load() }

// Total returns the sum of all label combination values.
// Useful for tests that need a total without caring about individual labels.
func (cv *CounterVec) Total() int64 {
	cv.mu.RLock()
	defer cv.mu.RUnlock()
	var total int64
	for _, e := range cv.entries {
		total += e.val.Load()
	}
	return total
}

// MustCounterVec registers a labeled counter family. Panics on duplicate name.
func (r *Registry) MustCounterVec(name, help string) *CounterVec {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.counterVecs[name]; ok {
		panic("metrics: duplicate counter_vec " + name)
	}
	cv := &CounterVec{name: name, help: help, entries: make(map[string]*cvEntry)}
	r.counterVecs[name] = cv
	return cv
}

// CounterVec returns an existing labeled counter family. Panics if not found.
func (r *Registry) CounterVec(name string) *CounterVec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cv, ok := r.counterVecs[name]
	if !ok {
		panic("metrics: counter_vec not registered: " + name)
	}
	return cv
}

// ── Gauge ─────────────────────────────────────────────────────────────────────

// Gauge is an arbitrary float64 metric that can go up or down.
type Gauge struct {
	name string
	help string
	mu   sync.Mutex
	val  float64
}

func (g *Gauge) Set(v float64)  { g.mu.Lock(); g.val = v; g.mu.Unlock() }
func (g *Gauge) Inc()           { g.mu.Lock(); g.val++; g.mu.Unlock() }
func (g *Gauge) Dec()           { g.mu.Lock(); g.val--; g.mu.Unlock() }
func (g *Gauge) Add(v float64)  { g.mu.Lock(); g.val += v; g.mu.Unlock() }
func (g *Gauge) Value() float64 { g.mu.Lock(); defer g.mu.Unlock(); return g.val }

// MustGauge registers and returns a named Gauge.
func (r *Registry) MustGauge(name, help string) *Gauge {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.gauges[name]; ok {
		panic("metrics: duplicate gauge " + name)
	}
	g := &Gauge{name: name, help: help}
	r.gauges[name] = g
	return g
}

// Gauge returns an existing Gauge by name.
func (r *Registry) Gauge(name string) *Gauge {
	r.mu.RLock()
	defer r.mu.RUnlock()
	g, ok := r.gauges[name]
	if !ok {
		panic("metrics: gauge not registered: " + name)
	}
	return g
}

// ── Histogram ─────────────────────────────────────────────────────────────────

// Histogram tracks the distribution of observed float64 values (e.g. latency in ms).
// Buckets follow Prometheus conventions (upper bounds, +Inf always included).
type Histogram struct {
	name    string
	help    string
	buckets []float64 // sorted upper bounds
	mu      sync.Mutex
	counts  []int64 // counts[i] = observations ≤ buckets[i]
	sum     float64
	total   int64
}

// DefaultLatencyBuckets are suitable for HTTP request latency in milliseconds
// (retained for backward compatibility with existing histograms).
var DefaultLatencyBuckets = []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}

// DefaultDurationBuckets are suitable for HTTP request latency in seconds
// (used by the labeled qs_http_request_duration_seconds metric).
// Upper bounds cover fast crypto (< 1 ms) through slow SLH-DSA-128s (≈ 20 ms)
// and up to 5 s for outliers.
var DefaultDurationBuckets = []float64{
	0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0,
}

// Observe records one observation.
func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sum += v
	h.total++
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i]++
		}
	}
}

// MustHistogram registers and returns a named Histogram with the given bucket upper bounds.
func (r *Registry) MustHistogram(name, help string, buckets []float64) *Histogram {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.histograms[name]; ok {
		panic("metrics: duplicate histogram " + name)
	}
	sorted := make([]float64, len(buckets))
	copy(sorted, buckets)
	sort.Float64s(sorted)
	h := &Histogram{
		name:    name,
		help:    help,
		buckets: sorted,
		counts:  make([]int64, len(sorted)),
	}
	r.histograms[name] = h
	return h
}

// Histogram returns an existing Histogram by name.
func (r *Registry) Histogram(name string) *Histogram {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.histograms[name]
	if !ok {
		panic("metrics: histogram not registered: " + name)
	}
	return h
}

// ── HistogramVec ──────────────────────────────────────────────────────────────

// HistogramVec is a labeled histogram family. Each unique label combination
// is a separate histogram series.
type HistogramVec struct {
	name    string
	help    string
	buckets []float64 // shared (read-only after construction)
	mu      sync.RWMutex
	entries map[string]*hvEntry
}

type hvEntry struct {
	labelStr string    // Prometheus formatted: {key="val",...}
	buckets  []float64 // pointer to parent's buckets (read-only)
	mu       sync.Mutex
	counts   []int64
	sum      float64
	total    int64
}

// With returns (or creates) the histogram for the given label set.
func (hv *HistogramVec) With(labels map[string]string) *hvEntry {
	key := canonicalKey(labels)
	hv.mu.RLock()
	e, ok := hv.entries[key]
	hv.mu.RUnlock()
	if ok {
		return e
	}
	hv.mu.Lock()
	defer hv.mu.Unlock()
	if e, ok = hv.entries[key]; ok {
		return e
	}
	e = &hvEntry{
		labelStr: formatLabels(labels),
		buckets:  hv.buckets,
		counts:   make([]int64, len(hv.buckets)),
	}
	hv.entries[key] = e
	return e
}

// Observe records one observation for this label combination.
func (e *hvEntry) Observe(v float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sum += v
	e.total++
	for i, b := range e.buckets {
		if v <= b {
			e.counts[i]++
		}
	}
}

// MustHistogramVec registers a labeled histogram family. Panics on duplicate name.
func (r *Registry) MustHistogramVec(name, help string, buckets []float64) *HistogramVec {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.histogramVecs[name]; ok {
		panic("metrics: duplicate histogram_vec " + name)
	}
	sorted := make([]float64, len(buckets))
	copy(sorted, buckets)
	sort.Float64s(sorted)
	hv := &HistogramVec{
		name:    name,
		help:    help,
		buckets: sorted,
		entries: make(map[string]*hvEntry),
	}
	r.histogramVecs[name] = hv
	return hv
}

// HistogramVec returns an existing labeled histogram family. Panics if not found.
func (r *Registry) HistogramVec(name string) *HistogramVec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	hv, ok := r.histogramVecs[name]
	if !ok {
		panic("metrics: histogram_vec not registered: " + name)
	}
	return hv
}

// ── HTTP Handler ──────────────────────────────────────────────────────────────

// Handler returns an http.Handler that serves metrics in Prometheus text format.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		var sb strings.Builder
		r.mu.RLock()
		defer r.mu.RUnlock()

		// Unlabeled Counters
		for _, c := range sortedValues(r.counters) {
			fmt.Fprintf(&sb, "# HELP %s %s\n", c.name, c.help)
			fmt.Fprintf(&sb, "# TYPE %s counter\n", c.name)
			fmt.Fprintf(&sb, "%s %d\n", c.name, c.val.Load())
		}

		// Labeled CounterVecs
		for _, cv := range sortedValues(r.counterVecs) {
			fmt.Fprintf(&sb, "# HELP %s %s\n", cv.name, cv.help)
			fmt.Fprintf(&sb, "# TYPE %s counter\n", cv.name)
			cv.mu.RLock()
			for _, e := range sortedEntries(cv.entries) {
				fmt.Fprintf(&sb, "%s%s %d\n", cv.name, e.labelStr, e.val.Load())
			}
			cv.mu.RUnlock()
		}

		// Unlabeled Gauges
		for _, g := range sortedValues(r.gauges) {
			fmt.Fprintf(&sb, "# HELP %s %s\n", g.name, g.help)
			fmt.Fprintf(&sb, "# TYPE %s gauge\n", g.name)
			g.mu.Lock()
			v := g.val
			g.mu.Unlock()
			fmt.Fprintf(&sb, "%s %s\n", g.name, formatFloat(v))
		}

		// Unlabeled Histograms
		for _, h := range sortedValues(r.histograms) {
			fmt.Fprintf(&sb, "# HELP %s %s\n", h.name, h.help)
			fmt.Fprintf(&sb, "# TYPE %s histogram\n", h.name)
			h.mu.Lock()
			for i, b := range h.buckets {
				fmt.Fprintf(&sb, "%s_bucket{le=\"%s\"} %d\n",
					h.name, formatFloat(b), h.counts[i])
			}
			fmt.Fprintf(&sb, "%s_bucket{le=\"+Inf\"} %d\n", h.name, h.total)
			fmt.Fprintf(&sb, "%s_sum %s\n", h.name, formatFloat(h.sum))
			fmt.Fprintf(&sb, "%s_count %d\n", h.name, h.total)
			h.mu.Unlock()
		}

		// Labeled HistogramVecs
		for _, hv := range sortedValues(r.histogramVecs) {
			fmt.Fprintf(&sb, "# HELP %s %s\n", hv.name, hv.help)
			fmt.Fprintf(&sb, "# TYPE %s histogram\n", hv.name)
			hv.mu.RLock()
			for _, e := range sortedEntries(hv.entries) {
				e.mu.Lock()
				// All bucket lines for this label set
				for i, b := range hv.buckets {
					// Insert le label into the label string
					le := fmt.Sprintf(",le=\"%s\"}", formatFloat(b))
					lbls := strings.TrimSuffix(e.labelStr, "}") + le
					fmt.Fprintf(&sb, "%s_bucket%s %d\n", hv.name, lbls, e.counts[i])
				}
				le := `,le="+Inf"}`
				lbls := strings.TrimSuffix(e.labelStr, "}") + le
				fmt.Fprintf(&sb, "%s_bucket%s %d\n", hv.name, lbls, e.total)
				fmt.Fprintf(&sb, "%s_sum%s %s\n", hv.name, e.labelStr, formatFloat(e.sum))
				fmt.Fprintf(&sb, "%s_count%s %d\n", hv.name, e.labelStr, e.total)
				e.mu.Unlock()
			}
			hv.mu.RUnlock()
		}

		fmt.Fprint(w, sb.String())
	})
}

// ── Middleware ────────────────────────────────────────────────────────────────

// HTTPMiddleware returns middleware that records per-route request count and
// latency using the labeled metrics families:
//
//   - qs_http_requests_total{method, path, status}   — counter
//   - qs_http_request_duration_seconds{method, path} — histogram
//
// The `path` label is normalized via the Registry's path normalizer (set with
// SetPathNormalizer) to prevent unbounded label cardinality from path params.
// Both metrics must be pre-registered via RegisterHTTPMetrics.
func (r *Registry) HTTPMiddleware(next http.Handler) http.Handler {
	reqTotal := r.CounterVec("qs_http_requests_total")
	reqDur := r.HistogramVec("qs_http_request_duration_seconds")

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		rw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rw, req)

		method := req.Method
		path := r.normalizePath(req.URL.Path)
		status := strconv.Itoa(rw.code)
		dur := time.Since(start).Seconds()

		reqTotal.With(map[string]string{
			"method": method,
			"path":   path,
			"status": status,
		}).Inc()
		reqDur.With(map[string]string{
			"method": method,
			"path":   path,
		}).Observe(dur)
	})
}

// RegisterHTTPMetrics pre-registers the standard HTTP metrics on r.
// Must be called before HTTPMiddleware.
func RegisterHTTPMetrics(r *Registry) {
	r.MustCounterVec(
		"qs_http_requests_total",
		"Total HTTP requests by method, path, and status code",
	)
	r.MustHistogramVec(
		"qs_http_request_duration_seconds",
		"HTTP request latency in seconds by method and path",
		DefaultDurationBuckets,
	)
}

// RegisterCryptoMetrics pre-registers per-operation crypto counters.
func RegisterCryptoMetrics(r *Registry) {
	ops := []string{
		"qs_crypto_keygen_total",
		"qs_crypto_encrypt_total",
		"qs_crypto_decrypt_total",
		"qs_crypto_sign_total",
		"qs_crypto_verify_total",
		"qs_crypto_vault_split_total",
		"qs_crypto_vault_reconstruct_total",
		"qs_crypto_token_issue_total",
		"qs_crypto_token_verify_total",
		"qs_crypto_token_revoke_total",
		"qs_crypto_channel_handshake_total",
		"qs_crypto_threshold_partial_total",
		"qs_crypto_threshold_authorised_total",
		"qs_crypto_errors_total",
	}
	for _, op := range ops {
		r.MustCounter(op, "Total "+strings.TrimPrefix(strings.TrimPrefix(op, "qs_crypto_"), "qs_")+" operations")
	}
	r.MustGauge("qs_audit_log_entries", "Current number of entries in the audit log")
	r.MustGauge("qs_keystore_keys_total", "Total number of keys in the key store")
}

// ── helpers ───────────────────────────────────────────────────────────────────

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.code = code
	sw.ResponseWriter.WriteHeader(code)
}

// canonicalKey returns a stable, deduplicated string key for a label map.
// Keys are sorted alphabetically so the same label set always produces the
// same key regardless of map iteration order.
func canonicalKey(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('\x00') // null byte separator — safe since label values can't contain it
		}
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(labels[k])
	}
	return sb.String()
}

// formatLabels formats a label map in Prometheus text syntax: {key="val",...}
// with keys sorted alphabetically.
func formatLabels(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(k)
		sb.WriteString(`="`)
		sb.WriteString(labels[k])
		sb.WriteByte('"')
	}
	sb.WriteByte('}')
	return sb.String()
}

// sortedValues returns the values of a string-keyed map sorted by key.
func sortedValues[T any](m map[string]T) []T {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]T, len(keys))
	for i, k := range keys {
		out[i] = m[k]
	}
	return out
}

// sortedEntries sorts a label-keyed entry map by the canonical key string for
// deterministic Prometheus output (required by the exposition format spec).
type labeledEntry interface {
	getKey() string
}

func sortedEntries[T interface{ getLabelStr() string }](m map[string]T) []T {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]T, len(keys))
	for i, k := range keys {
		out[i] = m[k]
	}
	return out
}

func (e *cvEntry) getLabelStr() string  { return e.labelStr }
func (e *hvEntry) getLabelStr() string  { return e.labelStr }

func formatFloat(v float64) string {
	if math.IsInf(v, 1) {
		return "+Inf"
	}
	if math.IsInf(v, -1) {
		return "-Inf"
	}
	if math.IsNaN(v) {
		return "NaN"
	}
	return fmt.Sprintf("%g", v)
}
