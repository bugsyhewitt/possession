package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bugsyhewitt/possession/internal/record"
)

// TestScanRecordReplay_MutuallyExclusive verifies --record and --replay can't
// both be set.
func TestScanRecordReplay_MutuallyExclusive(t *testing.T) {
	_, err := runScanCmd(t,
		"../../testdata/har/ecommerce.har",
		"--matrix", "../../testdata/matrix/example.yaml",
		"--record", t.TempDir(),
		"--replay", t.TempDir(),
	)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}
}

// TestScanReplay_DryRunRejected verifies --replay and --dry-run can't combine.
func TestScanReplay_DryRunRejected(t *testing.T) {
	_, err := runScanCmd(t,
		"../../testdata/har/ecommerce.har",
		"--matrix", "../../testdata/matrix/example.yaml",
		"--replay", t.TempDir(),
		"--dry-run",
	)
	if err == nil || !strings.Contains(err.Error(), "dry-run") {
		t.Fatalf("expected replay+dry-run error, got %v", err)
	}
}

// TestScanReplay_MissingRecording errors clearly when the recording is absent.
func TestScanReplay_MissingRecording(t *testing.T) {
	_, err := runScanCmd(t,
		"../../testdata/har/ecommerce.har",
		"--matrix", "../../testdata/matrix/example.yaml",
		"--replay", t.TempDir(), // empty dir, no recording.json
	)
	if err == nil {
		t.Fatal("expected error replaying from dir with no recording")
	}
}

// writeHARForServer writes a minimal single-request HAR targeting baseURL and
// returns its path. The path /api/users/1001 with alice's session/api-key
// matches the example matrix's alice identity.
func writeHARForServer(t *testing.T, baseURL string) string {
	t.Helper()
	har := map[string]any{
		"log": map[string]any{
			"version": "1.2",
			"entries": []any{
				map[string]any{
					"request": map[string]any{
						"method": "GET",
						"url":    baseURL + "/api/users/1001",
						"headers": []any{
							map[string]any{"name": "X-Api-Key", "value": "alice-key-xyz"},
							map[string]any{"name": "Cookie", "value": "session=s%3Aalice-session-abc123"},
						},
						"queryString": []any{},
						"cookies":     []any{},
					},
					"response": map[string]any{
						"status":      200,
						"headers":     []any{},
						"content":     map[string]any{"text": `{"email":"alice@example.com"}`},
						"cookies":     []any{},
						"redirectURL": "",
					},
				},
			},
		},
	}
	data, err := json.Marshal(har)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "capture.har")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeMatrixForServer writes a matrix whose target base_url matches baseURL so
// the replay base-url sanity check passes, with two identities (alice, bob) so
// swap-identity variants are generated.
func writeMatrixForServer(t *testing.T, baseURL string) string {
	t.Helper()
	yaml := fmt.Sprintf(`version: "1"
target:
  base_url: "%s"
identities:
  - name: alice
    role: standard-user
    rank: 10
    creds:
      cookies:
        session: "s%%3Aalice-session-abc123"
      headers:
        X-Api-Key: "alice-key-xyz"
    markers:
      - "alice@example.com"
  - name: bob
    role: standard-user
    rank: 10
    creds:
      cookies:
        session: "s%%3Abob-session-def456"
      headers:
        X-Api-Key: "bob-key-uvw"
settings:
  rate_per_host: 100
  concurrency: 5
  timeout: 15s
  follow_redirects: false
`, baseURL)
	p := filepath.Join(t.TempDir(), "matrix.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestScanRecordThenReplay_RoundTrip is the end-to-end Item 7 test: record a
// live scan against a test server, then replay the recording (no network) and
// assert the recording is written, the replay fires no requests, and detection
// produces identical JSON findings.
func TestScanRecordThenReplay_RoundTrip(t *testing.T) {
	// hits is mutated from the httptest server's per-connection goroutines and
	// read from the test goroutine. possession's replay engine fans variants out
	// across `concurrency` goroutines, so the handler runs concurrently — use an
	// atomic counter to keep the increments and reads race-free under -race.
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		// Server leaks alice's email regardless of caller ⇒ IDOR signal for bob.
		fmt.Fprint(w, `{"email":"alice@example.com"}`)
	}))
	defer srv.Close()

	harPath := writeHARForServer(t, srv.URL)
	matrixPath := writeMatrixForServer(t, srv.URL)
	recDir := t.TempDir()
	recJSON := filepath.Join(t.TempDir(), "record.json")
	replayJSON := filepath.Join(t.TempDir(), "replay.json")

	// 1. Record a live scan. JSON goes to a file (--out) so stderr noise like
	//    "recording written: ..." doesn't pollute the parsed report. Findings
	//    present ⇒ ExitError(3); --exit-zero keeps it from being a hard error.
	recStderr, err := runScanCmd(t,
		harPath,
		"--matrix", matrixPath,
		"--report", "json",
		"--out", recJSON,
		"--record", recDir,
		"--exit-zero",
	)
	if err != nil {
		t.Fatalf("record run failed: %v\noutput: %s", err, recStderr)
	}
	if !strings.Contains(recStderr, "recording written") {
		t.Errorf("expected 'recording written' notice on stderr, got: %s", recStderr)
	}
	if hits.Load() == 0 {
		t.Fatal("record run never hit the server")
	}
	if _, err := os.Stat(filepath.Join(recDir, record.Filename)); err != nil {
		t.Fatalf("recording not written: %v", err)
	}

	// 2. Replay the recording. Stop the server first to PROVE no network is hit.
	srv.Close()
	hitsBeforeReplay := hits.Load()

	replayStderr, err := runScanCmd(t,
		harPath,
		"--matrix", matrixPath,
		"--report", "json",
		"--out", replayJSON,
		"--replay", recDir,
		"--exit-zero",
	)
	if err != nil {
		t.Fatalf("replay run failed: %v\noutput: %s", err, replayStderr)
	}
	if got := hits.Load(); got != hitsBeforeReplay {
		t.Errorf("replay fired %d network request(s); expected 0", got-hitsBeforeReplay)
	}

	// 3. Findings must match between the live run and the offline replay.
	recFindings := findingCountFile(t, recJSON)
	replayFindings := findingCountFile(t, replayJSON)
	if recFindings != replayFindings {
		t.Errorf("finding count mismatch: record=%d replay=%d", recFindings, replayFindings)
	}
	if recFindings == 0 {
		t.Error("expected at least one finding from the leaky test server")
	}
}

// findingCountFile parses a JSON scan report file and returns len(findings).
func findingCountFile(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report %s: %v", path, err)
	}
	var doc struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("could not parse JSON report %s: %v\n%s", path, err, data)
	}
	return len(doc.Findings)
}
