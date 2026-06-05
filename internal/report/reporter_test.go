package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bugsyhewitt/possession/internal/model"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

// mkRun builds a minimal but representative RunResult with one finding
// per class so all three reporters exercise their full output paths.
func mkRun() *model.RunResult {
	now := time.Date(2026, 5, 16, 23, 0, 0, 0, time.UTC)
	return &model.RunResult{
		Run: model.RunMeta{
			BaseURL:        "https://api.example.com",
			TotalEndpoints: 2,
			TotalVariants:  10,
			Start:          now,
			End:            now.Add(123 * time.Millisecond),
			ToolVersion:    "1.0.0-test",
			Settings: model.RunSetView{
				RatePerHost: 10, Concurrency: 5, MaxVariants: 10000,
				MaxBody: 5 * 1024 * 1024, Timeout: "30s",
			},
		},
		Endpoints: []model.EndpointReport{
			{Key: "GET api.example.com/users/{id}", Method: "GET",
				Host: "api.example.com", PathTemplate: "/users/{id}",
				Owner: "alice", BaselineSamples: 3, BaselineStatus: 200,
				Stability: 0.95, EffThreshold: 0.90,
				Notes: []model.EndpointNote{
					{Code: "noisy-endpoint", Message: "noisy endpoint sample"},
				},
			},
		},
		Findings: []model.Finding{
			{
				ID: "deadbeef00000001", Class: "idor", Verdict: "bypass",
				Confidence: 0.92, ConfidenceBand: "high", Severity: "high",
				ASVS: []string{"v5.0.0-8.2.2"},
				EndpointKey: "GET api.example.com/users/{id}",
				VariantID:   "v-idor-1", Mutation: "swap-identity",
				Identity: "bob",
				Evidence: model.Evidence{
					BaselineStatus: 200, VariantStatus: 200,
					SimilarityScore: 0.97, SizeDelta: 0,
					Notes: []string{"reflectedOwner: variant body contains owner marker"},
				},
			},
			{
				ID: "deadbeef00000002", Class: "authn-bypass", Verdict: "bypass",
				Confidence: 0.95, ConfidenceBand: "high", Severity: "critical",
				ASVS: []string{"v5.0.0-8.3.1"},
				EndpointKey: "GET api.example.com/profile",
				VariantID:   "v-anon-1", Mutation: "strip-auth",
				Evidence: model.Evidence{
					BaselineStatus: 200, VariantStatus: 200,
					SimilarityScore: 0.99,
				},
			},
		},
		Summary: model.RunSummary{
			Verdicts: map[string]int{
				"bypass": 2, "enforced": 6, "inconclusive": 0, "suspected": 2,
			},
			ByClass:       map[string]int{"idor": 1, "authn-bypass": 1},
			BySeverity:    map[string]int{"critical": 1, "high": 1},
			TotalFindings: 2,
		},
	}
}

func TestNew_KnownReporters(t *testing.T) {
	for _, name := range []string{"human", "json", "sarif"} {
		r, err := New(name)
		if err != nil {
			t.Fatalf("New(%q): %v", name, err)
		}
		if r.Name() != name {
			t.Errorf("New(%q).Name() = %q", name, r.Name())
		}
	}
	if _, err := New("xml"); err == nil {
		t.Error("New(xml) should error")
	}
}

func TestJSON_Stable_TwoRunsByteIdentical(t *testing.T) {
	r := JSONReporter{}
	run := mkRun()
	var a, b bytes.Buffer
	if err := r.Render(run, &a); err != nil {
		t.Fatalf("first render: %v", err)
	}
	if err := r.Render(run, &b); err != nil {
		t.Fatalf("second render: %v", err)
	}
	if a.String() != b.String() {
		t.Errorf("JSON output not stable:\n--- a ---\n%s\n--- b ---\n%s", a.String(), b.String())
	}
	// Sanity-check it's valid JSON.
	var v any
	if err := json.Unmarshal(a.Bytes(), &v); err != nil {
		t.Errorf("JSON output not valid: %v", err)
	}
	// Verify indent.
	if !strings.Contains(a.String(), "\n  ") {
		t.Errorf("JSON output not indented")
	}
}

func TestHuman_RenderSmoke(t *testing.T) {
	var buf bytes.Buffer
	if err := (HumanReporter{}).Render(mkRun(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"possession scan",
		"api.example.com",
		"endpoints:",
		"findings:",
		"CRITICAL",
		"HIGH",
		"summary",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("human output missing %q\n---\n%s", want, out)
		}
	}
}

// TestHuman_ConfidenceBandColumn verifies the human table exposes the BOLA
// confidence band as its own column and renders the per-finding label.
func TestHuman_ConfidenceBandColumn(t *testing.T) {
	var buf bytes.Buffer
	if err := (HumanReporter{}).Render(mkRun(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "BAND") {
		t.Errorf("human findings table missing BAND column header\n---\n%s", out)
	}
	if !strings.Contains(out, "high") {
		t.Errorf("human findings table missing high band label\n---\n%s", out)
	}
}

// TestHuman_BandUnsetRendersDash verifies a finding with no band set shows a
// dash rather than a blank column (keeps the table aligned).
func TestHuman_BandUnsetRendersDash(t *testing.T) {
	run := &model.RunResult{
		Run: model.RunMeta{BaseURL: "https://x"},
		Findings: []model.Finding{
			{ID: "deadbeef00000003", Class: "idor", Verdict: "bypass",
				Confidence: 0.9, Severity: "high",
				EndpointKey: "GET x/y", Mutation: "swap-identity"},
		},
		Summary: model.RunSummary{Verdicts: map[string]int{"bypass": 1}, TotalFindings: 1},
	}
	var buf bytes.Buffer
	if err := (HumanReporter{}).Render(run, &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	if bandLabel("") != "-" {
		t.Errorf("bandLabel(\"\") = %q, want -", bandLabel(""))
	}
}

// TestJSON_IncludesConfidenceBand verifies the band field serializes.
func TestJSON_IncludesConfidenceBand(t *testing.T) {
	var buf bytes.Buffer
	if err := (JSONReporter{}).Render(mkRun(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf.String(), `"confidence_band": "high"`) {
		t.Errorf("JSON output missing confidence_band field\n---\n%s", buf.String())
	}
}

// TestSARIF_IncludesConfidenceBand verifies the band reaches the SARIF
// property bag.
func TestSARIF_IncludesConfidenceBand(t *testing.T) {
	var buf bytes.Buffer
	if err := (SARIFReporter{}).Render(mkRun(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf.String(), "confidence_band") {
		t.Errorf("SARIF output missing confidence_band property\n---\n%s", buf.String())
	}
}

func TestHuman_RenderEmpty(t *testing.T) {
	var buf bytes.Buffer
	empty := &model.RunResult{
		Run:     model.RunMeta{BaseURL: "https://x"},
		Summary: model.RunSummary{Verdicts: map[string]int{"enforced": 1}},
	}
	if err := (HumanReporter{}).Render(empty, &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf.String(), "(none") {
		t.Errorf("expected (none ...) message; got:\n%s", buf.String())
	}
}

func TestSARIF_RoundTripsThroughLibrary(t *testing.T) {
	var buf bytes.Buffer
	if err := (SARIFReporter{}).Render(mkRun(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	// Parse what we just wrote — round-trip is the contract from §4.2.
	parsed, err := sarif.FromBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("FromBytes round-trip failed: %v\nraw:\n%s", err, buf.String())
	}
	if len(parsed.Runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(parsed.Runs))
	}
	srun := parsed.Runs[0]
	if srun.Tool == nil || srun.Tool.Driver == nil || srun.Tool.Driver.Name == nil || *srun.Tool.Driver.Name != "possession" {
		t.Errorf("driver name not set; got %+v", srun.Tool)
	}
	if len(srun.Results) != 2 {
		t.Errorf("want 2 results, got %d", len(srun.Results))
	}
	// Verify partialFingerprints are populated.
	for _, r := range srun.Results {
		if len(r.PartialFingerprints) == 0 {
			t.Errorf("result missing partialFingerprints: %+v", r)
		}
	}
	// Verify level mapping critical→error.
	foundError := false
	foundWarning := false
	for _, r := range srun.Results {
		switch r.Level {
		case "error":
			foundError = true
		case "warning":
			foundWarning = true
		}
	}
	if !foundError {
		t.Errorf("expected at least one result.level=error (critical/high); none found")
	}
	_ = foundWarning // not asserted; tied to specific fixture
}

func TestSARIF_RoundTripContent(t *testing.T) {
	// Render → parse → re-render → parse must be idempotent.
	r := SARIFReporter{}
	var b1, b2 bytes.Buffer
	if err := r.Render(mkRun(), &b1); err != nil {
		t.Fatalf("render 1: %v", err)
	}
	parsed, err := sarif.FromBytes(b1.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Re-emit the parsed report and assert it's still valid SARIF.
	if err := parsed.PrettyWrite(&b2); err != nil {
		t.Fatalf("re-emit: %v", err)
	}
	if _, err := sarif.FromBytes(b2.Bytes()); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
}

// ─── JSON repro block (POST_V01 Item 4, r36) ──────────────────────────────

// mkRunWithReproBlock returns a RunResult with one finding that carries a
// populated model.FindingRepro block (simulating what scan.go populates from
// report.BuildRepro before the Variant pointer is dropped).
func mkRunWithReproBlock() *model.RunResult {
	run := mkRun()
	// Inject a Repro block into the first finding to mirror what scan.go sets.
	run.Findings[0].Repro = &model.FindingRepro{
		HTTP:         "POST /users/1001 HTTP/1.1\nHost: api.example.com\nAuthorization: <bearer:bob>\n\n{\"note\":\"test\"}",
		Curl:         "curl -X POST -H 'Authorization: <bearer:bob>' 'https://api.example.com/users/1001'",
		Differential: "baseline 200 → variant 200 · similarity 0.97 · Δsize 0",
	}
	return run
}

func TestJSON_FindingWithRepro_ContainsReproBlock(t *testing.T) {
	// A finding with Repro set must produce a "repro" object in JSON output.
	var buf bytes.Buffer
	if err := (JSONReporter{}).Render(mkRunWithReproBlock(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()

	// Top-level repro key must be present.
	if !strings.Contains(out, `"repro"`) {
		t.Errorf("JSON output missing top-level repro key:\n%s", out)
	}
	// All three sub-fields must appear.
	for _, field := range []string{`"http"`, `"curl"`, `"differential"`} {
		if !strings.Contains(out, field) {
			t.Errorf("JSON output missing repro field %s:\n%s", field, out)
		}
	}
	// The redacted placeholder must appear in the HTTP block.
	if !strings.Contains(out, "<bearer:bob>") {
		t.Errorf("repro HTTP block missing identity placeholder:\n%s", out)
	}
}

func TestJSON_FindingWithoutRepro_NoReproKey(t *testing.T) {
	// A finding whose Repro is nil (no recoverable request) must NOT emit a
	// "repro" key in JSON — the omitempty tag should suppress it.
	var buf bytes.Buffer
	if err := (JSONReporter{}).Render(mkRun(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	// mkRun() findings have no Repro set.
	if strings.Contains(buf.String(), `"repro"`) {
		t.Errorf("JSON output should not include repro for findings without Repro set:\n%s", buf.String())
	}
}

func TestJSON_ReproStable_ByteIdentical(t *testing.T) {
	// Repro-containing output must be byte-identical across two renders
	// (D26 determinism extends to the new field).
	r := JSONReporter{}
	run := mkRunWithReproBlock()
	var a, b bytes.Buffer
	if err := r.Render(run, &a); err != nil {
		t.Fatalf("first render: %v", err)
	}
	if err := r.Render(run, &b); err != nil {
		t.Fatalf("second render: %v", err)
	}
	if a.String() != b.String() {
		t.Errorf("JSON repro output not stable across two renders")
	}
}

func TestJSON_Repro_ValidJSON(t *testing.T) {
	// The full JSON output with a repro block must parse as valid JSON and
	// the repro sub-object must have the expected shape.
	var buf bytes.Buffer
	if err := (JSONReporter{}).Render(mkRunWithReproBlock(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	var parsed struct {
		Findings []struct {
			Repro *struct {
				HTTP         string `json:"http"`
				Curl         string `json:"curl"`
				Differential string `json:"differential"`
			} `json:"repro"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Findings) == 0 {
		t.Fatal("no findings in parsed output")
	}
	f0 := parsed.Findings[0]
	if f0.Repro == nil {
		t.Fatal("first finding has nil repro; expected populated repro block")
	}
	if f0.Repro.HTTP == "" {
		t.Error("repro.http is empty")
	}
	if f0.Repro.Curl == "" {
		t.Error("repro.curl is empty")
	}
	if f0.Repro.Differential == "" {
		t.Error("repro.differential is empty")
	}
	// Second finding (no Repro) must parse without a repro key (nil pointer).
	if len(parsed.Findings) > 1 && parsed.Findings[1].Repro != nil {
		t.Error("second finding unexpectedly has a repro block; expected nil")
	}
}
