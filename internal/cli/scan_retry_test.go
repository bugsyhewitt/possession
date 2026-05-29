package cli

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// TestScanRetryReplay_MutuallyExclusive verifies --retry-inconclusive and
// --replay can't both be set (replay fires no requests, so there is nothing to
// retry).
func TestScanRetryReplay_MutuallyExclusive(t *testing.T) {
	_, err := runScanCmd(t,
		"../../testdata/har/ecommerce.har",
		"--matrix", "../../testdata/matrix/example.yaml",
		"--retry-inconclusive",
		"--replay", t.TempDir(),
	)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}
}

// TestScanRetry_RecoversTransientFailures runs against a server that serves the
// baseline phase cleanly, fails exactly ONE variant-phase request once with a
// 500, then serves 200 again. The transient 500 would land as an inconclusive
// verdict; --retry-inconclusive re-issues it and recovers a usable response.
// The retry notice on stderr proves the pass ran and re-issued the failure.
func TestScanRetry_RecoversTransientFailures(t *testing.T) {
	var hits atomic.Int64
	var failedOne atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		// n==1 is the single baseline sample (must succeed for a clean
		// baseline). The first request after it fails once; everything else,
		// including the retry, succeeds.
		if n == 2 && failedOne.CompareAndSwap(false, true) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Leaks alice's email to every caller ⇒ IDOR signal for bob.
		_, _ = w.Write([]byte(`{"email":"alice@example.com"}`))
	}))
	defer srv.Close()

	harPath := writeHARForServer(t, srv.URL)
	matrixPath := writeMatrixForServer(t, srv.URL)
	outJSON := filepath.Join(t.TempDir(), "out.json")

	stderr, err := runScanCmd(t,
		harPath,
		"--matrix", matrixPath,
		"--report", "json",
		"--out", outJSON,
		// Single baseline sample so request #1 is the only baseline call and
		// request #2 is the first variant — the one we fail transiently.
		"--baseline-samples", "1",
		// Single in-flight request so the baseline/variant ordering above holds.
		"--concurrency", "1",
		"--retry-inconclusive",
		"--exit-zero",
	)
	if err != nil {
		t.Fatalf("retry run failed: %v\noutput: %s", err, stderr)
	}
	if !strings.Contains(stderr, "--retry-inconclusive: re-issued") {
		t.Errorf("expected a retry notice on stderr, got: %s", stderr)
	}
	if got := findingCountFile(t, outJSON); got == 0 {
		t.Errorf("expected findings from the leaky server after retry, got 0")
	}
}

// TestScanRetry_NoTransientFailuresNoop verifies that against a healthy server
// the retry pass finds nothing to re-issue and says so, leaving findings intact.
func TestScanRetry_NoTransientFailuresNoop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"email":"alice@example.com"}`))
	}))
	defer srv.Close()

	harPath := writeHARForServer(t, srv.URL)
	matrixPath := writeMatrixForServer(t, srv.URL)
	outJSON := filepath.Join(t.TempDir(), "out.json")

	stderr, err := runScanCmd(t,
		harPath,
		"--matrix", matrixPath,
		"--report", "json",
		"--out", outJSON,
		"--retry-inconclusive",
		"--exit-zero",
	)
	if err != nil {
		t.Fatalf("retry run failed: %v\noutput: %s", err, stderr)
	}
	if !strings.Contains(stderr, "no transiently-failed variants to retry") {
		t.Errorf("expected the no-op retry notice on stderr, got: %s", stderr)
	}
	if got := findingCountFile(t, outJSON); got == 0 {
		t.Errorf("expected findings from the leaky server, got 0")
	}
}
