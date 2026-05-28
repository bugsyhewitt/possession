package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// runCmd resets command flags and runs the root command with the given
// args, returning stdout and any error. We rebuild the root each time to
// avoid persisted flag state between tests.
func runCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// Reset package-level flag state set by previous runs.
	parseFormat = "auto"
	parseScope = ""
	parseJSON = false

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	return out.String(), err
}

func TestParseCommandTableOutput(t *testing.T) {
	out, err := runCmd(t, "parse", "../../testdata/har/ecommerce.har")
	if err != nil {
		t.Fatalf("parse: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "METHOD") || !strings.Contains(out, "PATH-TEMPLATE") {
		t.Errorf("missing table header in output:\n%s", out)
	}
	if !strings.Contains(out, "/api/users/{id}/profile") {
		t.Errorf("expected templated path in output:\n%s", out)
	}
	if strings.Contains(out, ".js") || strings.Contains(out, "google-analytics") {
		t.Errorf("static asset / analytics leaked into output:\n%s", out)
	}
}

func TestParseCommandJSONOutput(t *testing.T) {
	out, err := runCmd(t, "parse", "../../testdata/har/ecommerce.har", "--json")
	if err != nil {
		t.Fatalf("parse: %v\noutput:\n%s", err, out)
	}
	var arr []map[string]any
	if err := json.Unmarshal([]byte(out), &arr); err != nil {
		t.Fatalf("invalid JSON: %v\noutput:\n%s", err, out)
	}
	if len(arr) == 0 {
		t.Fatal("expected at least one endpoint in JSON output")
	}
	for _, e := range arr {
		if _, ok := e["method"]; !ok {
			t.Errorf("missing method field: %+v", e)
		}
		if _, ok := e["path_template"]; !ok {
			t.Errorf("missing path_template field: %+v", e)
		}
	}
}

func TestParseCommandCurlFormat(t *testing.T) {
	out, err := runCmd(t, "parse", "../../testdata/curl/sample.txt", "--format", "curl")
	if err != nil {
		t.Fatalf("parse: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "/api/users/{id}/orders") {
		t.Errorf("expected templated curl path in output:\n%s", out)
	}
}

func TestParseCommandOpenAPIExplicit(t *testing.T) {
	out, err := runCmd(t, "parse", "../../testdata/openapi/petstore.json", "--format", "openapi")
	if err != nil {
		t.Fatalf("parse: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "/v1/users") {
		t.Errorf("expected synthesized OpenAPI endpoint in output:\n%s", out)
	}
	// The numeric path param should template back to {id}.
	if !strings.Contains(out, "/orders/") {
		t.Errorf("expected orders endpoint in output:\n%s", out)
	}
}

func TestParseCommandOpenAPIAutoDetectJSON(t *testing.T) {
	// petstore.json starts with '{' like a HAR — auto-detect must use the
	// "openapi" key to disambiguate.
	out, err := runCmd(t, "parse", "../../testdata/openapi/petstore.json")
	if err != nil {
		t.Fatalf("parse auto: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "/v1/users") {
		t.Errorf("auto-detect failed to route JSON spec to openapi:\n%s", out)
	}
}

func TestParseCommandOpenAPIAutoDetectYAML(t *testing.T) {
	out, err := runCmd(t, "parse", "../../testdata/openapi/minimal.yaml")
	if err != nil {
		t.Fatalf("parse auto yaml: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "/health") {
		t.Errorf("auto-detect failed for YAML spec:\n%s", out)
	}
}

func TestDetectFormatOpenAPI(t *testing.T) {
	cases := []struct {
		path, requested, want string
	}{
		{"../../testdata/openapi/petstore.json", "auto", "openapi"},
		{"../../testdata/openapi/minimal.yaml", "auto", "openapi"},
		{"../../testdata/har/ecommerce.har", "auto", "har"},
		{"x", "openapi", "openapi"},
	}
	for _, c := range cases {
		got, err := detectFormat(c.path, c.requested)
		if err != nil {
			t.Errorf("detectFormat(%q,%q): %v", c.path, c.requested, err)
			continue
		}
		if got != c.want {
			t.Errorf("detectFormat(%q,%q) = %q, want %q", c.path, c.requested, got, c.want)
		}
	}
}

func TestScanStubFails(t *testing.T) {
	_, err := runCmd(t, "scan")
	if err == nil {
		t.Fatal("expected scan to return non-nil error (stub)")
	}
}
