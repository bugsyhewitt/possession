package report

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// mkRunWithRepro extends the shared fixture with a Variant on the first
// finding so the repro path (and credential redaction) is exercised.
func mkRunWithRepro() *model.RunResult {
	run := mkRun()
	u, _ := url.Parse("https://api.example.com/users/1001")
	run.Findings[0].Variant = &model.Variant{
		Base: &model.CapturedRequest{
			Method: "GET",
			URL:    u,
			Headers: http.Header{
				"Authorization": []string{"Bearer super-secret-token"},
				"Accept":        []string{"application/json"},
			},
		},
	}
	return run
}

func TestNew_HTMLReporter(t *testing.T) {
	r, err := New("html")
	if err != nil {
		t.Fatalf("New(html): %v", err)
	}
	if r.Name() != "html" {
		t.Errorf("New(html).Name() = %q, want html", r.Name())
	}
}

// TestHTML_RenderSmoke verifies the document is well-formed-ish and carries
// the expected sections, severity badges, and self-contained guarantee.
func TestHTML_RenderSmoke(t *testing.T) {
	var buf bytes.Buffer
	if err := (HTMLReporter{}).Render(mkRunWithRepro(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"<!doctype html>",
		"<title>possession scan</title>",
		"possession scan",
		"api.example.com",
		"Findings",
		"Summary",
		"data-sev=\"critical\"",
		"data-sev=\"high\"",
		"Reproduction",
		"</html>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("html output missing %q\n---\n%s", want, out)
		}
	}
}

// TestHTML_SelfContained asserts the report loads no external resources — the
// core promise of the offline interactive view.
func TestHTML_SelfContained(t *testing.T) {
	var buf bytes.Buffer
	if err := (HTMLReporter{}).Render(mkRunWithRepro(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	for _, bad := range []string{"http://", "src=", "<link", "cdn"} {
		if strings.Contains(out, bad) {
			t.Errorf("html output references an external resource (%q); must be self-contained\n---\n%s", bad, out)
		}
	}
	// https:// is allowed only inside escaped finding/target data, not as a
	// resource link. Confirm no stylesheet/script element pulls a URL.
	if strings.Contains(out, "https://") && !strings.Contains(out, "api.example.com") {
		t.Errorf("unexpected https:// reference outside finding data\n---\n%s", out)
	}
}

// TestHTML_RedactsCredentialsByDefault verifies live tokens never leak into
// the default report.
func TestHTML_RedactsCredentialsByDefault(t *testing.T) {
	var buf bytes.Buffer
	if err := (HTMLReporter{}).Render(mkRunWithRepro(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "super-secret-token") {
		t.Errorf("html leaked a live credential in default (redacted) mode\n---\n%s", out)
	}
	if !strings.Contains(out, "&lt;bearer:bob&gt;") {
		t.Errorf("html missing identity-tagged redaction placeholder\n---\n%s", out)
	}
}

// TestHTML_ShowCredsEmitsLiveToken verifies --repro-creds passes through.
func TestHTML_ShowCredsEmitsLiveToken(t *testing.T) {
	var buf bytes.Buffer
	r := HTMLReporter{ReproOpts: ReproOptions{ShowCreds: true}}
	if err := r.Render(mkRunWithRepro(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf.String(), "super-secret-token") {
		t.Errorf("html with ShowCreds did not emit the live credential\n---\n%s", buf.String())
	}
}

// TestHTML_EscapesFindingData guards against HTML injection from response data
// that lands in finding fields (endpoint keys, markers, etc.).
func TestHTML_EscapesFindingData(t *testing.T) {
	run := mkRun()
	run.Findings[0].EndpointKey = `GET x/<script>alert(1)</script>`
	run.Findings[0].Evidence.Notes = []string{`note <img src=x onerror=alert(1)>`}
	var buf bytes.Buffer
	if err := (HTMLReporter{}).Render(run, &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Errorf("html did not escape an endpoint key — XSS risk\n---\n%s", out)
	}
	if strings.Contains(out, "<img src=x onerror=alert(1)>") {
		t.Errorf("html did not escape a signal note — XSS risk\n---\n%s", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("html missing escaped form of injected markup\n---\n%s", out)
	}
}

// TestHTML_Stable_TwoRunsByteIdentical mirrors the JSON stability contract:
// the same run renders byte-for-byte identically.
func TestHTML_Stable_TwoRunsByteIdentical(t *testing.T) {
	r := HTMLReporter{}
	run := mkRunWithRepro()
	var a, b bytes.Buffer
	if err := r.Render(run, &a); err != nil {
		t.Fatalf("first render: %v", err)
	}
	if err := r.Render(run, &b); err != nil {
		t.Fatalf("second render: %v", err)
	}
	if a.String() != b.String() {
		t.Errorf("html output not stable across renders")
	}
}

// TestHTML_RenderEmpty verifies a no-findings run renders the (none) message
// rather than empty markup.
func TestHTML_RenderEmpty(t *testing.T) {
	var buf bytes.Buffer
	empty := &model.RunResult{
		Run:     model.RunMeta{BaseURL: "https://x"},
		Summary: model.RunSummary{Verdicts: map[string]int{"enforced": 1}},
	}
	if err := (HTMLReporter{}).Render(empty, &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf.String(), "(none") {
		t.Errorf("expected (none ...) message; got:\n%s", buf.String())
	}
}

// TestHTML_RenderNil handles a nil run without panicking.
func TestHTML_RenderNil(t *testing.T) {
	var buf bytes.Buffer
	if err := (HTMLReporter{}).Render(nil, &buf); err != nil {
		t.Fatalf("render nil: %v", err)
	}
	if !strings.Contains(buf.String(), "empty run") {
		t.Errorf("nil run should render an empty-run document; got:\n%s", buf.String())
	}
}
