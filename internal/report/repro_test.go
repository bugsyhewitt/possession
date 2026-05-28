package report

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// mkReproFinding builds a finding with a fully-populated mutated request so
// the repro builder and markdown reporter exercise their full output paths.
func mkReproFinding() model.Finding {
	u, _ := url.Parse("https://api.example.com/users/1001?account_id=1001")
	req := &model.CapturedRequest{
		Method: "POST",
		URL:    u,
		Headers: http.Header{
			"Authorization": {"Bearer SECRET-bob-token"},
			"X-Api-Key":     {"live-key-12345"},
			"Content-Type":  {"application/json"},
			"User-Agent":    {"possession/test"},
		},
		Cookies: []*http.Cookie{
			{Name: "session", Value: "bob-session-cookie"},
		},
		Body:        []byte(`{"note":"o'brien"}`),
		ContentType: "application/json",
	}
	return model.Finding{
		ID: "deadbeef00000099", Class: "idor", Verdict: "bypass",
		Confidence: 0.92, ConfidenceBand: "high", Severity: "high",
		ASVS:        []string{"v5.0.0-8.2.2"},
		EndpointKey: "POST api.example.com/users/{id}",
		VariantID:   "v-idor-9", Mutation: "swap-identity", Identity: "bob",
		Variant: &model.Variant{ID: "v-idor-9", Base: req},
		Evidence: model.Evidence{
			BaselineStatus: 200, VariantStatus: 200,
			SimilarityScore: 0.97, SizeDelta: 4,
			Notes: []string{"reflectedOwner: variant body contains owner marker"},
		},
	}
}

func TestBuildRepro_RedactsCredentialsByDefault(t *testing.T) {
	repro, ok := BuildRepro(mkReproFinding(), ReproOptions{})
	if !ok {
		t.Fatal("BuildRepro returned ok=false for a finding with a request")
	}
	for _, secret := range []string{"SECRET-bob-token", "live-key-12345", "bob-session-cookie"} {
		if strings.Contains(repro.HTTP, secret) {
			t.Errorf("HTTP repro leaked secret %q:\n%s", secret, repro.HTTP)
		}
		if strings.Contains(repro.Curl, secret) {
			t.Errorf("curl repro leaked secret %q:\n%s", secret, repro.Curl)
		}
	}
	// Identity-tagged placeholder must appear in place of the redacted token.
	if !strings.Contains(repro.HTTP, "<bearer:bob>") {
		t.Errorf("HTTP repro missing identity placeholder:\n%s", repro.HTTP)
	}
}

func TestBuildRepro_ShowCredsEmitsLiveValues(t *testing.T) {
	repro, ok := BuildRepro(mkReproFinding(), ReproOptions{ShowCreds: true})
	if !ok {
		t.Fatal("BuildRepro returned ok=false")
	}
	for _, secret := range []string{"SECRET-bob-token", "live-key-12345", "bob-session-cookie"} {
		if !strings.Contains(repro.HTTP, secret) {
			t.Errorf("HTTP repro missing %q with ShowCreds:\n%s", secret, repro.HTTP)
		}
	}
}

func TestBuildRepro_HTTPRequestLineAndBody(t *testing.T) {
	repro, _ := BuildRepro(mkReproFinding(), ReproOptions{})
	if !strings.HasPrefix(repro.HTTP, "POST /users/1001?account_id=1001 HTTP/1.1") {
		t.Errorf("HTTP request line wrong:\n%s", repro.HTTP)
	}
	if !strings.Contains(repro.HTTP, "Host: api.example.com") {
		t.Errorf("HTTP repro missing Host header:\n%s", repro.HTTP)
	}
	if !strings.Contains(repro.HTTP, `{"note":"o'brien"}`) {
		t.Errorf("HTTP repro missing body:\n%s", repro.HTTP)
	}
}

func TestBuildRepro_CurlShellQuotesBodyWithApostrophe(t *testing.T) {
	repro, _ := BuildRepro(mkReproFinding(), ReproOptions{})
	if !strings.HasPrefix(repro.Curl, "curl -X POST ") {
		t.Errorf("curl missing method:\n%s", repro.Curl)
	}
	// The body contains a single quote (o'brien); shellQuote must escape it
	// the POSIX way ('\'') so the command is a single safe word.
	if !strings.Contains(repro.Curl, `'\''`) {
		t.Errorf("curl did not POSIX-escape the embedded apostrophe:\n%s", repro.Curl)
	}
	if !strings.Contains(repro.Curl, "'https://api.example.com/users/1001?account_id=1001'") {
		t.Errorf("curl missing quoted URL:\n%s", repro.Curl)
	}
}

func TestBuildRepro_Differential(t *testing.T) {
	repro, _ := BuildRepro(mkReproFinding(), ReproOptions{})
	for _, want := range []string{"baseline 200 → variant 200", "similarity 0.97", "Δsize 4"} {
		if !strings.Contains(repro.Differential, want) {
			t.Errorf("differential missing %q: %q", want, repro.Differential)
		}
	}
}

func TestBuildRepro_NoVariantReturnsFalse(t *testing.T) {
	// A finding from deserialized JSON has Variant == nil; repro must be
	// gracefully skipped rather than panicking.
	f := model.Finding{ID: "x", Class: "idor", EndpointKey: "GET x/y"}
	if _, ok := BuildRepro(f, ReproOptions{}); ok {
		t.Error("BuildRepro should return ok=false when Variant is nil")
	}
}

func TestNew_MarkdownReporter(t *testing.T) {
	r, err := New("markdown")
	if err != nil {
		t.Fatalf("New(markdown): %v", err)
	}
	if r.Name() != "markdown" {
		t.Errorf("Name() = %q, want markdown", r.Name())
	}
}

func TestMarkdown_RenderIncludesReproBlocks(t *testing.T) {
	run := mkRun()
	run.Findings = append(run.Findings, mkReproFinding())
	var buf bytes.Buffer
	if err := (MarkdownReporter{}).Render(run, &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"# possession scan",
		"## Findings",
		"<details><summary>Reproduction</summary>",
		"```http",
		"```sh",
		"curl -X POST",
		"**Differential:**",
		"## Summary",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown output missing %q\n---\n%s", want, out)
		}
	}
	// Default markdown must not leak credentials.
	if strings.Contains(out, "SECRET-bob-token") {
		t.Errorf("markdown leaked credential:\n%s", out)
	}
}

func TestMarkdown_ShowCredsLeaksByDesign(t *testing.T) {
	run := mkRun()
	run.Findings = []model.Finding{mkReproFinding()}
	var buf bytes.Buffer
	rep := MarkdownReporter{ReproOpts: ReproOptions{ShowCreds: true}}
	if err := rep.Render(run, &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf.String(), "SECRET-bob-token") {
		t.Errorf("markdown with --repro-creds should emit live token:\n%s", buf.String())
	}
}

func TestMarkdown_RenderEmpty(t *testing.T) {
	var buf bytes.Buffer
	empty := &model.RunResult{
		Run:     model.RunMeta{BaseURL: "https://x"},
		Summary: model.RunSummary{Verdicts: map[string]int{"enforced": 1}},
	}
	if err := (MarkdownReporter{}).Render(empty, &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf.String(), "_(none") {
		t.Errorf("expected (none ...) message; got:\n%s", buf.String())
	}
}
