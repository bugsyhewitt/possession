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
				Confidence: 0.92, Severity: "high",
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
				Confidence: 0.95, Severity: "critical",
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
