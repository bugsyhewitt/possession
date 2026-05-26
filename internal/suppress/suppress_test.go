package suppress_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
	"github.com/bugsyhewitt/possession/internal/suppress"
)

// sampleFindings returns a small slice of findings for use in tests.
func sampleFindings() []model.Finding {
	return []model.Finding{
		{ID: "aaaa1111bbbb2222", Class: "idor", Verdict: "bypass", Severity: "high"},
		{ID: "cccc3333dddd4444", Class: "privesc", Verdict: "suspected", Severity: "medium"},
		{ID: "eeee5555ffff6666", Class: "authn-bypass", Verdict: "bypass", Severity: "critical"},
	}
}

// ---- Load ----

func TestLoad_Empty(t *testing.T) {
	al, err := suppress.Load(nil)
	if err != nil {
		t.Fatalf("Load(nil): %v", err)
	}
	if len(al.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(al.Entries))
	}
}

func TestLoad_Valid(t *testing.T) {
	yaml := `
version: "1"
description: "test allowlist"
entries:
  - id: "aaaa1111bbbb2222"
    added_at: "2026-05-26T00:00:00Z"
    added_by: "alice"
    note: "known finding"
  - id: "cccc3333dddd4444"
`
	al, err := suppress.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if al.Version != "1" {
		t.Errorf("version: got %q, want %q", al.Version, "1")
	}
	if al.Description != "test allowlist" {
		t.Errorf("description: got %q", al.Description)
	}
	if len(al.Entries) != 2 {
		t.Fatalf("entries: got %d, want 2", len(al.Entries))
	}
	if al.Entries[0].ID != "aaaa1111bbbb2222" {
		t.Errorf("entries[0].ID: got %q", al.Entries[0].ID)
	}
	if al.Entries[0].Note != "known finding" {
		t.Errorf("entries[0].Note: got %q", al.Entries[0].Note)
	}
}

func TestLoad_DedupDuplicateIDs(t *testing.T) {
	yaml := `
version: "1"
entries:
  - id: "aaaa1111bbbb2222"
    note: "first"
  - id: "aaaa1111bbbb2222"
    note: "second"
`
	al, err := suppress.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(al.Entries) != 1 {
		t.Errorf("expected 1 entry after dedup, got %d", len(al.Entries))
	}
	if al.Entries[0].Note != "first" {
		t.Errorf("first declaration should win, got note=%q", al.Entries[0].Note)
	}
}

func TestLoad_MissingVersion(t *testing.T) {
	yaml := `entries:
  - id: "aaaa1111bbbb2222"
`
	al, err := suppress.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if al.Version != "1" {
		t.Errorf("missing version should default to '1', got %q", al.Version)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	_, err := suppress.Load([]byte(":\t bad yaml\x00"))
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

// ---- LoadFile ----

func TestLoadFile_NotExist(t *testing.T) {
	al, err := suppress.LoadFile("/nonexistent/path/possession.allowlist")
	if err != nil {
		t.Fatalf("LoadFile on missing file should not error: %v", err)
	}
	if len(al.Entries) != 0 {
		t.Errorf("expected empty allowlist, got %d entries", len(al.Entries))
	}
}

func TestLoadFile_ValidFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "test.allowlist")
	content := `version: "1"
entries:
  - id: "aaaa1111bbbb2222"
`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	al, err := suppress.LoadFile(p)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(al.Entries) != 1 || al.Entries[0].ID != "aaaa1111bbbb2222" {
		t.Errorf("unexpected entries: %+v", al.Entries)
	}
}

// ---- Apply ----

func TestApply_NilAllowlist(t *testing.T) {
	findings := sampleFindings()
	retained, suppressed := suppress.Apply(findings, nil)
	if len(retained) != 3 {
		t.Errorf("nil allowlist: expected 3 retained, got %d", len(retained))
	}
	if suppressed != 0 {
		t.Errorf("nil allowlist: expected 0 suppressed, got %d", suppressed)
	}
}

func TestApply_EmptyAllowlist(t *testing.T) {
	findings := sampleFindings()
	al := &suppress.Allowlist{Version: "1"}
	retained, suppressed := suppress.Apply(findings, al)
	if len(retained) != 3 {
		t.Errorf("empty allowlist: expected 3 retained, got %d", len(retained))
	}
	if suppressed != 0 {
		t.Errorf("empty allowlist: expected 0 suppressed, got %d", suppressed)
	}
}

func TestApply_SuppressOne(t *testing.T) {
	findings := sampleFindings()
	al := &suppress.Allowlist{
		Version: "1",
		Entries: []suppress.Entry{{ID: "aaaa1111bbbb2222"}},
	}
	retained, suppressed := suppress.Apply(findings, al)
	if len(retained) != 2 {
		t.Errorf("expected 2 retained, got %d", len(retained))
	}
	if suppressed != 1 {
		t.Errorf("expected 1 suppressed, got %d", suppressed)
	}
	// Ensure the right finding was removed.
	for _, f := range retained {
		if f.ID == "aaaa1111bbbb2222" {
			t.Error("suppressed finding still present in retained")
		}
	}
}

func TestApply_SuppressAll(t *testing.T) {
	findings := sampleFindings()
	al := &suppress.Allowlist{
		Version: "1",
		Entries: []suppress.Entry{
			{ID: "aaaa1111bbbb2222"},
			{ID: "cccc3333dddd4444"},
			{ID: "eeee5555ffff6666"},
		},
	}
	retained, suppressed := suppress.Apply(findings, al)
	if len(retained) != 0 {
		t.Errorf("expected 0 retained, got %d", len(retained))
	}
	if suppressed != 3 {
		t.Errorf("expected 3 suppressed, got %d", suppressed)
	}
}

func TestApply_UnknownIDsIgnored(t *testing.T) {
	findings := sampleFindings()
	al := &suppress.Allowlist{
		Version: "1",
		Entries: []suppress.Entry{{ID: "deadbeefdeadbeef"}},
	}
	retained, suppressed := suppress.Apply(findings, al)
	if len(retained) != 3 {
		t.Errorf("expected 3 retained, got %d", len(retained))
	}
	if suppressed != 0 {
		t.Errorf("expected 0 suppressed, got %d", suppressed)
	}
}

// ---- FromFindings ----

func TestFromFindings_Basic(t *testing.T) {
	findings := sampleFindings()
	al := suppress.FromFindings(findings, "alice", "rotation-1 suppression")
	if len(al.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(al.Entries))
	}
	for i, f := range findings {
		if al.Entries[i].ID != f.ID {
			t.Errorf("entries[%d].ID: got %q, want %q", i, al.Entries[i].ID, f.ID)
		}
		if al.Entries[i].AddedBy != "alice" {
			t.Errorf("entries[%d].AddedBy: got %q", i, al.Entries[i].AddedBy)
		}
		if al.Entries[i].Note != "rotation-1 suppression" {
			t.Errorf("entries[%d].Note: got %q", i, al.Entries[i].Note)
		}
		if al.Entries[i].AddedAt == "" {
			t.Errorf("entries[%d].AddedAt should be set", i)
		}
	}
}

func TestFromFindings_DedupDuplicateFindings(t *testing.T) {
	findings := []model.Finding{
		{ID: "aaaa1111bbbb2222"},
		{ID: "aaaa1111bbbb2222"}, // duplicate
	}
	al := suppress.FromFindings(findings, "", "")
	if len(al.Entries) != 1 {
		t.Errorf("expected 1 entry after dedup, got %d", len(al.Entries))
	}
}

func TestFromFindings_EmptyFindings(t *testing.T) {
	al := suppress.FromFindings(nil, "ci", "")
	if len(al.Entries) != 0 {
		t.Errorf("expected 0 entries for empty findings, got %d", len(al.Entries))
	}
}

// ---- Merge ----

func TestMerge_ExistingWins(t *testing.T) {
	existing := &suppress.Allowlist{
		Version:     "1",
		Description: "existing",
		Entries:     []suppress.Entry{{ID: "aaaa1111bbbb2222", Note: "existing note"}},
	}
	incoming := &suppress.Allowlist{
		Version: "1",
		Entries: []suppress.Entry{
			{ID: "aaaa1111bbbb2222", Note: "incoming note"},
			{ID: "cccc3333dddd4444", Note: "new finding"},
		},
	}
	merged := suppress.Merge(existing, incoming)
	if len(merged.Entries) != 2 {
		t.Fatalf("expected 2 merged entries, got %d", len(merged.Entries))
	}
	// First entry should be the existing one.
	if merged.Entries[0].Note != "existing note" {
		t.Errorf("existing entry should win: got note=%q", merged.Entries[0].Note)
	}
	if merged.Entries[1].ID != "cccc3333dddd4444" {
		t.Errorf("new entry should be appended: got ID=%q", merged.Entries[1].ID)
	}
	if merged.Description != "existing" {
		t.Errorf("description should come from existing: got %q", merged.Description)
	}
}

func TestMerge_NilExisting(t *testing.T) {
	incoming := &suppress.Allowlist{
		Version: "1",
		Entries: []suppress.Entry{{ID: "aaaa1111bbbb2222"}},
	}
	merged := suppress.Merge(nil, incoming)
	if len(merged.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(merged.Entries))
	}
}

func TestMerge_NilIncoming(t *testing.T) {
	existing := &suppress.Allowlist{
		Version: "1",
		Entries: []suppress.Entry{{ID: "aaaa1111bbbb2222"}},
	}
	merged := suppress.Merge(existing, nil)
	if len(merged.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(merged.Entries))
	}
}

func TestMerge_DescriptionFallback(t *testing.T) {
	existing := &suppress.Allowlist{Version: "1"} // no description
	incoming := &suppress.Allowlist{Version: "1", Description: "from incoming"}
	merged := suppress.Merge(existing, incoming)
	if merged.Description != "from incoming" {
		t.Errorf("description should fall back to incoming: got %q", merged.Description)
	}
}

// ---- Marshal / WriteFile round-trip ----

func TestMarshal_RoundTrip(t *testing.T) {
	original := &suppress.Allowlist{
		Version:     "1",
		Description: "round-trip test",
		Entries: []suppress.Entry{
			{ID: "aaaa1111bbbb2222", AddedBy: "alice", Note: "test note"},
			{ID: "cccc3333dddd4444"},
		},
	}
	data, err := suppress.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	loaded, err := suppress.Load(data)
	if err != nil {
		t.Fatalf("Load after Marshal: %v", err)
	}
	if loaded.Description != original.Description {
		t.Errorf("description mismatch: got %q, want %q", loaded.Description, original.Description)
	}
	if len(loaded.Entries) != 2 {
		t.Fatalf("entries: got %d, want 2", len(loaded.Entries))
	}
	if loaded.Entries[0].ID != "aaaa1111bbbb2222" {
		t.Errorf("entries[0].ID mismatch")
	}
	if loaded.Entries[0].Note != "test note" {
		t.Errorf("entries[0].Note mismatch")
	}
}

func TestWriteFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "possession.allowlist")

	original := &suppress.Allowlist{
		Version: "1",
		Entries: []suppress.Entry{
			{ID: "aaaa1111bbbb2222", AddedBy: "ci"},
		},
	}
	if err := suppress.WriteFile(p, original); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Verify tmp file was cleaned up.
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Error("tmp file should not exist after WriteFile")
	}
	loaded, err := suppress.LoadFile(p)
	if err != nil {
		t.Fatalf("LoadFile after WriteFile: %v", err)
	}
	if len(loaded.Entries) != 1 || loaded.Entries[0].ID != "aaaa1111bbbb2222" {
		t.Errorf("round-trip mismatch: %+v", loaded.Entries)
	}
}

// ---- Integration: FromFindings → WriteFile → LoadFile → Apply ----

func TestIntegration_WriteAndApply(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "possession.allowlist")

	findings := sampleFindings()

	// Write all findings to allowlist.
	al := suppress.FromFindings(findings, "test-worker", "rotation-1")
	if err := suppress.WriteFile(p, al); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Load it back.
	loaded, err := suppress.LoadFile(p)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	// Apply: all findings should be suppressed.
	retained, suppressed := suppress.Apply(findings, loaded)
	if len(retained) != 0 {
		t.Errorf("expected all suppressed, got %d retained", len(retained))
	}
	if suppressed != 3 {
		t.Errorf("expected 3 suppressed, got %d", suppressed)
	}

	// Add one new finding that wasn't in the allowlist.
	newFinding := model.Finding{ID: "9999aaaabbbbcccc", Class: "idor", Verdict: "bypass"}
	allFindings := append(findings, newFinding)
	retained, suppressed = suppress.Apply(allFindings, loaded)
	if len(retained) != 1 {
		t.Errorf("expected 1 retained (the new finding), got %d", len(retained))
	}
	if retained[0].ID != "9999aaaabbbbcccc" {
		t.Errorf("wrong finding retained: %q", retained[0].ID)
	}
	if suppressed != 3 {
		t.Errorf("expected 3 suppressed, got %d", suppressed)
	}
}
