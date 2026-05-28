package record

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

func sampleRecording() *Recording {
	baseIDs := []string{"baseline-alice-0-r1", "baseline-alice-1-r1"}
	baseResps := []model.Response{
		{VariantID: "baseline-alice-0-r1", Status: 200, Body: []byte(`{"id":1}`)},
		{VariantID: "baseline-alice-1-r1", Status: 200, Body: []byte(`{"id":1}`)},
	}
	varIDs := []string{"swap-bob-r1", "strip-r1"}
	varResps := []model.Response{
		{VariantID: "swap-bob-r1", Status: 200, Body: []byte(`{"id":2}`)},
		{VariantID: "strip-r1", Status: 401},
	}
	return New("possession/test", "https://api.example.com", baseIDs, baseResps, varIDs, varResps)
}

// TestNew_KeysByVariantID verifies responses are keyed by their stamped VariantID.
func TestNew_KeysByVariantID(t *testing.T) {
	r := sampleRecording()
	b, v := r.Counts()
	if b != 2 || v != 2 {
		t.Fatalf("counts: got baseline=%d variants=%d, want 2/2", b, v)
	}
	if got := r.Variants["swap-bob-r1"].Status; got != 200 {
		t.Errorf("swap-bob-r1 status: got %d want 200", got)
	}
	if got := r.Baseline["baseline-alice-0-r1"].Status; got != 200 {
		t.Errorf("baseline status: got %d want 200", got)
	}
}

// TestNew_FallsBackToPlanID covers a response whose VariantID is empty (e.g. a
// transport error before the engine stamped it): the plan-derived id is used.
func TestNew_FallsBackToPlanID(t *testing.T) {
	ids := []string{"plan-id-1"}
	resps := []model.Response{{Status: 0, Err: "dial timeout"}} // VariantID empty
	r := New("t", "", nil, nil, ids, resps)
	if _, ok := r.Variants["plan-id-1"]; !ok {
		t.Fatalf("expected response keyed by plan id, got keys %v", r.Variants)
	}
}

// TestSaveLoad_RoundTrip verifies an atomic save then load reproduces the data.
func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := sampleRecording()
	if err := Save(dir, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, Filename)); err != nil {
		t.Fatalf("recording file not written: %v", err)
	}
	// No leftover temp file.
	if _, err := os.Stat(filepath.Join(dir, Filename+".tmp")); !os.IsNotExist(err) {
		t.Errorf("temp file should be removed after atomic rename")
	}

	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Version != Version {
		t.Errorf("version: got %q want %q", got.Version, Version)
	}
	if got.BaseURL != want.BaseURL {
		t.Errorf("base_url: got %q want %q", got.BaseURL, want.BaseURL)
	}
	gb, gv := got.Counts()
	if gb != 2 || gv != 2 {
		t.Fatalf("loaded counts: got baseline=%d variants=%d want 2/2", gb, gv)
	}
	if string(got.Variants["swap-bob-r1"].Body) != `{"id":2}` {
		t.Errorf("body not round-tripped: %q", got.Variants["swap-bob-r1"].Body)
	}
}

// TestSave_CreatesDir verifies Save creates a missing --record directory.
func TestSave_CreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "rec")
	if err := Save(dir, sampleRecording()); err != nil {
		t.Fatalf("Save into missing dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, Filename)); err != nil {
		t.Errorf("recording not written into created dir: %v", err)
	}
}

// TestLoad_RejectsBadVersion verifies an unknown schema version is rejected.
func TestLoad_RejectsBadVersion(t *testing.T) {
	dir := t.TempDir()
	bad := `{"version":"999","baseline":{},"variants":{}}`
	if err := os.WriteFile(filepath.Join(dir, Filename), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("expected error loading unsupported version")
	}
}

// TestLoad_MissingFile errors clearly.
func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("expected error loading from dir with no recording")
	}
}

// TestResponsesFor_OrderAndMissing verifies responses come back in the same
// order as the requested ids, and that ids absent from the recording yield an
// inconclusive placeholder and are reported as missing.
func TestResponsesFor_OrderAndMissing(t *testing.T) {
	r := sampleRecording()
	ids := []string{"strip-r1", "swap-bob-r1", "never-recorded"}
	resps, missing := r.ResponsesFor(ids, false)

	if len(resps) != 3 {
		t.Fatalf("want 3 responses, got %d", len(resps))
	}
	if resps[0].VariantID != "strip-r1" || resps[0].Status != 401 {
		t.Errorf("order/lookup wrong at 0: %+v", resps[0])
	}
	if resps[1].VariantID != "swap-bob-r1" || resps[1].Status != 200 {
		t.Errorf("order/lookup wrong at 1: %+v", resps[1])
	}
	// Missing id: placeholder, inconclusive, id preserved.
	if resps[2].VariantID != "never-recorded" || !resps[2].Inconclusive {
		t.Errorf("missing id should be inconclusive placeholder: %+v", resps[2])
	}
	if len(missing) != 1 || missing[0] != "never-recorded" {
		t.Errorf("missing slice wrong: %v", missing)
	}
}

// TestResponsesFor_Baseline selects from the baseline map when baseline=true.
func TestResponsesFor_Baseline(t *testing.T) {
	r := sampleRecording()
	resps, missing := r.ResponsesFor([]string{"baseline-alice-0-r1"}, true)
	if len(missing) != 0 {
		t.Fatalf("unexpected missing: %v", missing)
	}
	if resps[0].Status != 200 {
		t.Errorf("baseline lookup failed: %+v", resps[0])
	}
}
