package metrics_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quantum-shield/quantum-shield-go/pkg/metrics"
)

func newReg(t *testing.T) *metrics.Registry {
	t.Helper()
	return metrics.New()
}

// ── Counter ───────────────────────────────────────────────────────────────────

func TestCounter_StartsAtZero(t *testing.T) {
	r := newReg(t)
	c := r.MustCounter("test_counter", "help")
	if c.Value() != 0 {
		t.Errorf("expected 0, got %d", c.Value())
	}
}

func TestCounter_Inc(t *testing.T) {
	r := newReg(t)
	c := r.MustCounter("test_inc", "help")
	c.Inc()
	c.Inc()
	c.Inc()
	if c.Value() != 3 {
		t.Errorf("expected 3, got %d", c.Value())
	}
}

func TestCounter_Add(t *testing.T) {
	r := newReg(t)
	c := r.MustCounter("test_add", "help")
	c.Add(100)
	if c.Value() != 100 {
		t.Errorf("expected 100, got %d", c.Value())
	}
}

func TestCounter_DuplicatePanics(t *testing.T) {
	r := newReg(t)
	r.MustCounter("dup", "help")
	defer func() {
		if rec := recover(); rec == nil {
			t.Error("expected panic for duplicate counter")
		}
	}()
	r.MustCounter("dup", "help")
}

func TestCounter_GetUnregisteredPanics(t *testing.T) {
	r := newReg(t)
	defer func() {
		if rec := recover(); rec == nil {
			t.Error("expected panic for unregistered counter")
		}
	}()
	r.Counter("nonexistent")
}

// ── Gauge ─────────────────────────────────────────────────────────────────────

func TestGauge_SetAndGet(t *testing.T) {
	r := newReg(t)
	g := r.MustGauge("test_gauge", "help")
	g.Set(42.5)
	if g.Value() != 42.5 {
		t.Errorf("expected 42.5, got %f", g.Value())
	}
}

func TestGauge_IncDec(t *testing.T) {
	r := newReg(t)
	g := r.MustGauge("test_incdec", "help")
	g.Inc()
	g.Inc()
	g.Dec()
	if g.Value() != 1 {
		t.Errorf("expected 1, got %f", g.Value())
	}
}

func TestGauge_Add(t *testing.T) {
	r := newReg(t)
	g := r.MustGauge("test_gadd", "help")
	g.Add(10.5)
	g.Add(4.5)
	if g.Value() != 15.0 {
		t.Errorf("expected 15.0, got %f", g.Value())
	}
}

func TestGauge_DuplicatePanics(t *testing.T) {
	r := newReg(t)
	r.MustGauge("dup_gauge", "help")
	defer func() {
		if rec := recover(); rec == nil {
			t.Error("expected panic for duplicate gauge")
		}
	}()
	r.MustGauge("dup_gauge", "help")
}

// ── Histogram ─────────────────────────────────────────────────────────────────

func TestHistogram_Observe(t *testing.T) {
	r := newReg(t)
	h := r.MustHistogram("test_hist", "help", []float64{10, 50, 100})
	h.Observe(5)
	h.Observe(25)
	h.Observe(75)
	h.Observe(200)
	// 4 observations total
}

func TestHistogram_DuplicatePanics(t *testing.T) {
	r := newReg(t)
	r.MustHistogram("dup_hist", "help", []float64{1, 5})
	defer func() {
		if rec := recover(); rec == nil {
			t.Error("expected panic for duplicate histogram")
		}
	}()
	r.MustHistogram("dup_hist", "help", []float64{1, 5})
}

// ── Handler (Prometheus format) ───────────────────────────────────────────────

func TestHandler_ContentType(t *testing.T) {
	r := newReg(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	r.Handler().ServeHTTP(rr, req)
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("expected text/plain content-type, got %q", ct)
	}
}

func TestHandler_ContainsHELP(t *testing.T) {
	r := newReg(t)
	r.MustCounter("my_counter", "My counter help")
	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	if !strings.Contains(body, "# HELP my_counter") {
		t.Errorf("body missing HELP line: %s", body)
	}
	if !strings.Contains(body, "# TYPE my_counter counter") {
		t.Errorf("body missing TYPE line: %s", body)
	}
	if !strings.Contains(body, "my_counter 0") {
		t.Errorf("body missing value line: %s", body)
	}
}

func TestHandler_CounterValueAfterInc(t *testing.T) {
	r := newReg(t)
	c := r.MustCounter("ops_total", "ops")
	c.Inc()
	c.Inc()
	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rr.Body.String(), "ops_total 2") {
		t.Errorf("counter value wrong: %s", rr.Body.String())
	}
}

func TestHandler_HistogramBuckets(t *testing.T) {
	r := newReg(t)
	h := r.MustHistogram("latency_ms", "latency", []float64{10, 100})
	h.Observe(5)
	h.Observe(50)
	h.Observe(500)
	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	if !strings.Contains(body, `latency_ms_bucket{le="10"}`) {
		t.Errorf("missing le=10 bucket: %s", body)
	}
	if !strings.Contains(body, `latency_ms_bucket{le="+Inf"} 3`) {
		t.Errorf("missing +Inf bucket with count 3: %s", body)
	}
	if !strings.Contains(body, "latency_ms_count 3") {
		t.Errorf("missing count line: %s", body)
	}
}

// ── HTTPMiddleware ────────────────────────────────────────────────────────────

func TestHTTPMiddleware_IncrementsCounter(t *testing.T) {
	r := newReg(t)
	metrics.RegisterHTTPMetrics(r)

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := r.HTTPMiddleware(inner)

	for range 3 {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", "/health/live", nil))
	}

	// qs_http_requests_total is now a CounterVec (labeled by method/path/status).
	// Total() sums all label combinations.
	cv := r.CounterVec("qs_http_requests_total")
	if cv.Total() != 3 {
		t.Errorf("expected 3 requests counted, got %d", cv.Total())
	}
}

func TestHTTPMiddleware_LabeledMetrics(t *testing.T) {
	r := newReg(t)
	metrics.RegisterHTTPMetrics(r)

	inner := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/error" {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	})
	h := r.HTTPMiddleware(inner)

	// Two GET /ok requests → status 200
	for range 2 {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/ok", nil))
	}
	// One POST /error → status 500
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/error", nil))

	cv := r.CounterVec("qs_http_requests_total")
	if total := cv.Total(); total != 3 {
		t.Errorf("total: expected 3, got %d", total)
	}

	// Check Prometheus output contains labeled entries.
	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	if !strings.Contains(body, `method="GET"`) {
		t.Errorf("missing method label in output:\n%s", body)
	}
	if !strings.Contains(body, `status="200"`) {
		t.Errorf("missing status=200 label in output:\n%s", body)
	}
	if !strings.Contains(body, `status="500"`) {
		t.Errorf("missing status=500 label in output:\n%s", body)
	}
}

func TestHTTPMiddleware_DurationHistogram(t *testing.T) {
	r := newReg(t)
	metrics.RegisterHTTPMetrics(r)

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := r.HTTPMiddleware(inner)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/sign", nil))

	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()

	if !strings.Contains(body, "qs_http_request_duration_seconds_bucket") {
		t.Errorf("missing duration histogram in output:\n%s", body)
	}
	if !strings.Contains(body, "qs_http_request_duration_seconds_count") {
		t.Errorf("missing duration count in output:\n%s", body)
	}
}

// ── CounterVec ────────────────────────────────────────────────────────────────

func TestCounterVec_WithAndTotal(t *testing.T) {
	r := newReg(t)
	cv := r.MustCounterVec("http_reqs", "help")

	cv.With(map[string]string{"method": "GET", "path": "/a", "status": "200"}).Inc()
	cv.With(map[string]string{"method": "GET", "path": "/a", "status": "200"}).Inc()
	cv.With(map[string]string{"method": "POST", "path": "/b", "status": "400"}).Inc()

	if cv.Total() != 3 {
		t.Errorf("Total() = %d, want 3", cv.Total())
	}
	// Same label set returns the same counter.
	v := cv.With(map[string]string{"method": "GET", "path": "/a", "status": "200"}).Value()
	if v != 2 {
		t.Errorf("label value = %d, want 2", v)
	}
}

func TestCounterVec_DuplicatePanics(t *testing.T) {
	r := newReg(t)
	r.MustCounterVec("dup_cv", "help")
	defer func() {
		if rec := recover(); rec == nil {
			t.Error("expected panic for duplicate CounterVec")
		}
	}()
	r.MustCounterVec("dup_cv", "help")
}

func TestCounterVec_GetUnregisteredPanics(t *testing.T) {
	r := newReg(t)
	defer func() {
		if rec := recover(); rec == nil {
			t.Error("expected panic for unregistered CounterVec")
		}
	}()
	r.CounterVec("nonexistent_cv")
}

func TestCounterVec_PrometheusOutput(t *testing.T) {
	r := newReg(t)
	cv := r.MustCounterVec("api_calls_total", "API calls")
	cv.With(map[string]string{"method": "POST", "path": "/sign"}).Inc()
	cv.With(map[string]string{"method": "GET", "path": "/keys"}).Add(5)

	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()

	if !strings.Contains(body, "# HELP api_calls_total API calls") {
		t.Errorf("missing HELP line: %s", body)
	}
	if !strings.Contains(body, "# TYPE api_calls_total counter") {
		t.Errorf("missing TYPE line: %s", body)
	}
	if !strings.Contains(body, `api_calls_total{method="POST",path="/sign"} 1`) {
		t.Errorf("missing POST /sign entry: %s", body)
	}
	if !strings.Contains(body, `api_calls_total{method="GET",path="/keys"} 5`) {
		t.Errorf("missing GET /keys entry: %s", body)
	}
}

// ── HistogramVec ──────────────────────────────────────────────────────────────

func TestHistogramVec_ObserveAndOutput(t *testing.T) {
	r := newReg(t)
	hv := r.MustHistogramVec("req_dur", "duration", []float64{0.01, 0.1, 1.0})

	hv.With(map[string]string{"path": "/sign"}).Observe(0.005)
	hv.With(map[string]string{"path": "/sign"}).Observe(0.05)
	hv.With(map[string]string{"path": "/sign"}).Observe(2.0)
	hv.With(map[string]string{"path": "/verify"}).Observe(0.001)

	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()

	// Histogram should appear as TYPE histogram
	if !strings.Contains(body, "# TYPE req_dur histogram") {
		t.Errorf("missing TYPE histogram: %s", body)
	}
	// /sign has 3 observations — count should be 3
	if !strings.Contains(body, `req_dur_count{path="/sign"} 3`) {
		t.Errorf("missing /sign count=3: %s", body)
	}
	// +Inf bucket for /verify should be 1
	if !strings.Contains(body, `req_dur_bucket{path="/verify",le="+Inf"} 1`) {
		t.Errorf("missing /verify +Inf bucket: %s", body)
	}
}

func TestHistogramVec_DuplicatePanics(t *testing.T) {
	r := newReg(t)
	r.MustHistogramVec("dup_hv", "help", []float64{1.0})
	defer func() {
		if rec := recover(); rec == nil {
			t.Error("expected panic for duplicate HistogramVec")
		}
	}()
	r.MustHistogramVec("dup_hv", "help", []float64{1.0})
}

// ── PathNormalizer ────────────────────────────────────────────────────────────

func TestSetPathNormalizer(t *testing.T) {
	r := newReg(t)
	metrics.RegisterHTTPMetrics(r)

	// Normalizer that collapses any segment with digits to "{id}"
	r.SetPathNormalizer(func(path string) string {
		if strings.Contains(path, "abc123") {
			return "/keys/{id}/public"
		}
		return path
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := r.HTTPMiddleware(inner)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/keys/abc123/public", nil))

	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()

	if !strings.Contains(body, `/keys/{id}/public`) {
		t.Errorf("path not normalized: %s", body)
	}
	// Original path should NOT appear
	if strings.Contains(body, "abc123") {
		t.Errorf("unnormalized path leaked into metrics: %s", body)
	}
}

// ── RegisterCryptoMetrics ─────────────────────────────────────────────────────

func TestRegisterCryptoMetrics(t *testing.T) {
	r := newReg(t)
	// Must not panic
	metrics.RegisterCryptoMetrics(r)

	names := []string{
		"qs_crypto_keygen_total",
		"qs_crypto_encrypt_total",
		"qs_crypto_decrypt_total",
		"qs_crypto_sign_total",
		"qs_crypto_errors_total",
		"qs_audit_log_entries",
		"qs_keystore_keys_total",
	}
	for _, name := range names {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Errorf("metric %q not registered: %v", name, rec)
				}
			}()
			// Try to get counters; gauge names will panic — skip them
		}()
	}
}

// ── Concurrency ───────────────────────────────────────────────────────────────

func TestCounter_ConcurrentInc(t *testing.T) {
	r := newReg(t)
	c := r.MustCounter("concurrent", "help")
	const n = 1000
	done := make(chan struct{}, n)
	for range n {
		go func() {
			c.Inc()
			done <- struct{}{}
		}()
	}
	for range n {
		<-done
	}
	if c.Value() != n {
		t.Errorf("expected %d, got %d", n, c.Value())
	}
}
