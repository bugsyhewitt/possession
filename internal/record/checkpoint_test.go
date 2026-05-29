package record

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// TestCheckpoint_RecordThenLoad writes a handful of responses through a
// Checkpoint and verifies LoadCheckpoint recovers them, routed to the correct
// baseline/variant set and keyed by VariantID.
func TestCheckpoint_RecordThenLoad(t *testing.T) {
	dir := t.TempDir()
	ck, err := OpenCheckpoint(dir)
	if err != nil {
		t.Fatalf("OpenCheckpoint: %v", err)
	}
	ck.Record(model.Response{VariantID: "base-1", Status: 200, Body: []byte(`{"id":1}`)}, true)
	ck.Record(model.Response{VariantID: "var-1", Status: 403}, false)
	ck.Record(model.Response{VariantID: "var-2", Status: 200, Body: []byte(`{"id":2}`)}, false)
	if err := ck.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	loaded, err := LoadCheckpoint(dir)
	if err != nil {
		t.Fatalf("LoadCheckpoint: %v", err)
	}
	nb, nv := loaded.Counts()
	if nb != 1 || nv != 2 {
		t.Fatalf("counts: got baseline=%d variants=%d, want 1/2", nb, nv)
	}
	if loaded.Baseline["base-1"].Status != 200 {
		t.Errorf("base-1 status: got %d want 200", loaded.Baseline["base-1"].Status)
	}
	if loaded.Variants["var-1"].Status != 403 {
		t.Errorf("var-1 status: got %d want 403", loaded.Variants["var-1"].Status)
	}
	if string(loaded.Variants["var-2"].Body) != `{"id":2}` {
		t.Errorf("var-2 body not round-tripped: %q", loaded.Variants["var-2"].Body)
	}
}

// TestCheckpoint_AppendsAcrossOpens proves the resume contract: a second
// OpenCheckpoint on the same dir keeps the first run's records and adds to them,
// rather than truncating. This is what lets an interrupted scan resume.
func TestCheckpoint_AppendsAcrossOpens(t *testing.T) {
	dir := t.TempDir()

	ck1, err := OpenCheckpoint(dir)
	if err != nil {
		t.Fatalf("OpenCheckpoint #1: %v", err)
	}
	ck1.Record(model.Response{VariantID: "var-1", Status: 200}, false)
	if err := ck1.Close(); err != nil {
		t.Fatalf("Close #1: %v", err)
	}

	ck2, err := OpenCheckpoint(dir)
	if err != nil {
		t.Fatalf("OpenCheckpoint #2: %v", err)
	}
	ck2.Record(model.Response{VariantID: "var-2", Status: 201}, false)
	if err := ck2.Close(); err != nil {
		t.Fatalf("Close #2: %v", err)
	}

	loaded, err := LoadCheckpoint(dir)
	if err != nil {
		t.Fatalf("LoadCheckpoint: %v", err)
	}
	if _, ok := loaded.Variants["var-1"]; !ok {
		t.Error("var-1 from first open was lost; checkpoint truncated instead of appending")
	}
	if _, ok := loaded.Variants["var-2"]; !ok {
		t.Error("var-2 from second open missing")
	}
}

// TestCheckpoint_SkipsEmptyVariantID verifies responses with no VariantID are
// not persisted — they can't be matched back to a plan variant on resume.
func TestCheckpoint_SkipsEmptyVariantID(t *testing.T) {
	dir := t.TempDir()
	ck, err := OpenCheckpoint(dir)
	if err != nil {
		t.Fatalf("OpenCheckpoint: %v", err)
	}
	ck.Record(model.Response{VariantID: "", Status: 500, Err: "dial timeout"}, false)
	ck.Record(model.Response{VariantID: "var-1", Status: 200}, false)
	_ = ck.Close()

	loaded, err := LoadCheckpoint(dir)
	if err != nil {
		t.Fatalf("LoadCheckpoint: %v", err)
	}
	if _, nv := loaded.Counts(); nv != 1 {
		t.Fatalf("want 1 persisted variant (empty-ID skipped), got %d", nv)
	}
}

// TestLoadCheckpoint_MissingFileIsEmpty verifies a missing checkpoint is not an
// error — the first --resume run has nothing to recover and behaves like a
// fresh scan that happens to be checkpointing.
func TestLoadCheckpoint_MissingFileIsEmpty(t *testing.T) {
	loaded, err := LoadCheckpoint(t.TempDir())
	if err != nil {
		t.Fatalf("LoadCheckpoint on empty dir should not error, got %v", err)
	}
	if nb, nv := loaded.Counts(); nb != 0 || nv != 0 {
		t.Fatalf("empty dir should yield 0/0, got %d/%d", nb, nv)
	}
}

// TestLoadCheckpoint_SkipsTornLine verifies a malformed trailing line (the
// signature of a crash mid-append) is skipped rather than aborting the load, so
// every well-formed record before it is still recovered.
func TestLoadCheckpoint_SkipsTornLine(t *testing.T) {
	dir := t.TempDir()
	ck, err := OpenCheckpoint(dir)
	if err != nil {
		t.Fatalf("OpenCheckpoint: %v", err)
	}
	ck.Record(model.Response{VariantID: "var-1", Status: 200}, false)
	_ = ck.Close()

	// Simulate a crash mid-append: a half-written JSON object with no newline.
	path := filepath.Join(dir, CheckpointFilename)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"baseline":false,"response":{"variant_id":"var-2","sta`); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	loaded, err := LoadCheckpoint(dir)
	if err != nil {
		t.Fatalf("LoadCheckpoint with torn tail should not error, got %v", err)
	}
	if _, ok := loaded.Variants["var-1"]; !ok {
		t.Error("well-formed var-1 before the torn line was lost")
	}
	if _, ok := loaded.Variants["var-2"]; ok {
		t.Error("torn var-2 line should have been skipped")
	}
}

// TestLoadCheckpoint_LastWriteWins verifies that when a VariantID appears twice
// (a re-fired variant whose first response didn't flush before a crash), the
// later, fresher response is kept.
func TestLoadCheckpoint_LastWriteWins(t *testing.T) {
	dir := t.TempDir()
	ck, err := OpenCheckpoint(dir)
	if err != nil {
		t.Fatalf("OpenCheckpoint: %v", err)
	}
	ck.Record(model.Response{VariantID: "var-1", Status: 500}, false)
	ck.Record(model.Response{VariantID: "var-1", Status: 200}, false)
	_ = ck.Close()

	loaded, err := LoadCheckpoint(dir)
	if err != nil {
		t.Fatalf("LoadCheckpoint: %v", err)
	}
	if got := loaded.Variants["var-1"].Status; got != 200 {
		t.Errorf("last write should win: got status %d, want 200", got)
	}
}
