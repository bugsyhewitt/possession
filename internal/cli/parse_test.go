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

func TestParseCommandPostmanExplicit(t *testing.T) {
	out, err := runCmd(t, "parse", "../../testdata/postman/shop.postman_collection.json", "--format", "postman")
	if err != nil {
		t.Fatalf("parse: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "/accounts/{id}") {
		t.Errorf("expected templated Postman endpoint in output:\n%s", out)
	}
	if !strings.Contains(out, "/health") {
		t.Errorf("expected /health endpoint in output:\n%s", out)
	}
}

func TestParseCommandPostmanAutoDetect(t *testing.T) {
	// The collection starts with '{' like a HAR — auto-detect must use the
	// Postman schema marker to disambiguate.
	out, err := runCmd(t, "parse", "../../testdata/postman/shop.postman_collection.json")
	if err != nil {
		t.Fatalf("parse auto: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "/accounts/{id}") {
		t.Errorf("auto-detect failed to route collection to postman:\n%s", out)
	}
}

func TestParseCommandMitmproxyExplicit(t *testing.T) {
	out, err := runCmd(t, "parse", "../../testdata/mitmproxy/shop.flows.json", "--format", "mitmproxy")
	if err != nil {
		t.Fatalf("parse: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "/api/users/{id}/profile") {
		t.Errorf("expected templated mitmproxy endpoint in output:\n%s", out)
	}
	if !strings.Contains(out, "/api/cart/items") {
		t.Errorf("expected POST cart endpoint in output:\n%s", out)
	}
	// Static asset, css, and analytics host must be filtered out.
	if strings.Contains(out, "app.js") || strings.Contains(out, "google-analytics") || strings.Contains(out, "/api/styles/main") {
		t.Errorf("filtered traffic leaked into output:\n%s", out)
	}
}

func TestParseCommandMitmproxyAutoDetectArray(t *testing.T) {
	// A JSON array is the unambiguous mitmproxy dump shape.
	out, err := runCmd(t, "parse", "../../testdata/mitmproxy/shop.flows.json")
	if err != nil {
		t.Fatalf("parse auto: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "/api/users/{id}/profile") {
		t.Errorf("auto-detect failed to route JSON array to mitmproxy:\n%s", out)
	}
}

func TestParseCommandMitmproxyAutoDetectJSONL(t *testing.T) {
	out, err := runCmd(t, "parse", "../../testdata/mitmproxy/stream.flows.jsonl")
	if err != nil {
		t.Fatalf("parse auto jsonl: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "/v1/accounts/{id}") {
		t.Errorf("auto-detect failed for JSON-lines mitmproxy dump:\n%s", out)
	}
}

func TestDetectFormatOpenAPI(t *testing.T) {
	cases := []struct {
		path, requested, want string
	}{
		{"../../testdata/openapi/petstore.json", "auto", "openapi"},
		{"../../testdata/openapi/minimal.yaml", "auto", "openapi"},
		{"../../testdata/har/ecommerce.har", "auto", "har"},
		{"../../testdata/postman/shop.postman_collection.json", "auto", "postman"},
		{"../../testdata/mitmproxy/shop.flows.json", "auto", "mitmproxy"},
		{"../../testdata/mitmproxy/stream.flows.jsonl", "auto", "mitmproxy"},
		{"x", "openapi", "openapi"},
		{"x", "postman", "postman"},
		{"x", "mitmproxy", "mitmproxy"},
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
