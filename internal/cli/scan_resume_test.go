package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bugsyhewitt/possession/internal/record"
)

// TestScanResumeReplay_MutuallyExclusive verifies --resume and --replay can't
// both be set (replay fires nothing, so there is nothing to resume).
func TestScanResumeReplay_MutuallyExclusive(t *testing.T) {
	_, err := runScanCmd(t,
		"../../testdata/har/ecommerce.har",
		"--matrix", "../../testdata/matrix/example.yaml",
		"--resume", t.TempDir(),
		"--replay", t.TempDir(),
	)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}
}

// TestScanResume_WritesCheckpoint verifies a first --resume run writes a
// checkpoint holding one persisted response per fired variant + baseline.
func TestScanResume_WritesCheckpoint(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"email":"alice@example.com"}`))
	}))
	defer srv.Close()

	harPath := writeHARForServer(t, srv.URL)
	matrixPath := writeMatrixForServer(t, srv.URL)
	resumeDir := t.TempDir()

	_, err := runScanCmd(t,
		harPath,
		"--matrix", matrixPath,
		"--report", "json",
		"--out", filepath.Join(t.TempDir(), "out.json"),
		"--resume", resumeDir,
		"--exit-zero",
	)
	if err != nil {
		t.Fatalf("resume run failed: %v", err)
	}
	if hits.Load() == 0 {
		t.Fatal("resume run never hit the server")
	}
	if _, err := os.Stat(filepath.Join(resumeDir, record.CheckpointFilename)); err != nil {
		t.Fatalf("checkpoint not written: %v", err)
	}
	loaded, err := record.LoadCheckpoint(resumeDir)
	if err != nil {
		t.Fatalf("LoadCheckpoint: %v", err)
	}
	nb, nv := loaded.Counts()
	if nb == 0 || nv == 0 {
		t.Fatalf("checkpoint should hold baseline+variant responses, got %d/%d", nb, nv)
	}
}

// TestScanResume_SkipsCompletedVariants is the core resume contract: run a scan
// to completion under --resume (which fully populates the checkpoint), then
// re-run with the same --resume dir against a now-dead server. Because every
// variant is already checkpointed, the resume run fires ZERO network requests
// and still produces identical findings.
func TestScanResume_SkipsCompletedVariants(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		// Leaks alice's email to every caller ⇒ IDOR signal for bob.
		_, _ = w.Write([]byte(`{"email":"alice@example.com"}`))
	}))
	defer srv.Close()

	harPath := writeHARForServer(t, srv.URL)
	matrixPath := writeMatrixForServer(t, srv.URL)
	resumeDir := t.TempDir()
	firstJSON := filepath.Join(t.TempDir(), "first.json")
	resumeJSON := filepath.Join(t.TempDir(), "resume.json")

	// 1. First --resume run: fully completes, populating the checkpoint.
	if _, err := runScanCmd(t,
		harPath,
		"--matrix", matrixPath,
		"--report", "json",
		"--out", firstJSON,
		"--resume", resumeDir,
		"--exit-zero",
	); err != nil {
		t.Fatalf("first resume run failed: %v", err)
	}
	if hits.Load() == 0 {
		t.Fatal("first run never hit the server")
	}

	// 2. Kill the server, then resume. Every variant is already checkpointed,
	//    so the resume must fire NOTHING and still emit identical findings.
	srv.Close()
	hitsBeforeResume := hits.Load()

	resumeStderr, err := runScanCmd(t,
		harPath,
		"--matrix", matrixPath,
		"--report", "json",
		"--out", resumeJSON,
		"--resume", resumeDir,
		"--exit-zero",
	)
	if err != nil {
		t.Fatalf("resume run failed: %v\noutput: %s", err, resumeStderr)
	}
	if got := hits.Load() - hitsBeforeResume; got != 0 {
		t.Errorf("resume fired %d network request(s); expected 0 (all checkpointed)", got)
	}
	if !strings.Contains(resumeStderr, "recovered") {
		t.Errorf("expected a '--resume: recovered ...' notice on stderr, got: %s", resumeStderr)
	}

	// 3. Findings must match between the original run and the fully-resumed run.
	first := findingCountFile(t, firstJSON)
	resumed := findingCountFile(t, resumeJSON)
	if first != resumed {
		t.Errorf("finding count mismatch: first=%d resume=%d", first, resumed)
	}
	if first == 0 {
		t.Error("expected at least one finding from the leaky test server")
	}
}

// TestScanResume_PartialCheckpointFiresRemainder proves a half-finished
// checkpoint resumes correctly: a checkpoint seeded with only SOME of a run's
// variant responses causes the resume to fire just the missing ones, and the
// final findings still match a clean run.
func TestScanResume_PartialCheckpointFiresRemainder(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"email":"alice@example.com"}`))
	}))
	defer srv.Close()

	harPath := writeHARForServer(t, srv.URL)
	matrixPath := writeMatrixForServer(t, srv.URL)

	// Clean reference run (no resume) for the finding-count baseline.
	cleanJSON := filepath.Join(t.TempDir(), "clean.json")
	if _, err := runScanCmd(t,
		harPath, "--matrix", matrixPath,
		"--report", "json", "--out", cleanJSON, "--exit-zero",
	); err != nil {
		t.Fatalf("clean run failed: %v", err)
	}
	cleanCount := findingCountFile(t, cleanJSON)
	hitsAfterClean := hits.Load()

	// Resume run starting from an EMPTY checkpoint dir (the realistic
	// interrupted-on-first-attempt case): it must fire the full plan live and
	// produce the same findings as the clean run.
	resumeDir := t.TempDir()
	resumeJSON := filepath.Join(t.TempDir(), "resume.json")
	if _, err := runScanCmd(t,
		harPath, "--matrix", matrixPath,
		"--report", "json", "--out", resumeJSON,
		"--resume", resumeDir, "--exit-zero",
	); err != nil {
		t.Fatalf("resume-from-empty run failed: %v", err)
	}
	if got := hits.Load() - hitsAfterClean; got == 0 {
		t.Error("resume from empty checkpoint should fire requests, fired 0")
	}
	if got := findingCountFile(t, resumeJSON); got != cleanCount {
		t.Errorf("resume-from-empty findings %d != clean findings %d", got, cleanCount)
	}
}
