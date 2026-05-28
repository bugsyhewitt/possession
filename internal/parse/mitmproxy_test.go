package parse

import (
	"strings"
	"testing"
)

// parseMitmFixture parses a mitmproxy JSON-dump fixture into the shared
// requestView shape used by the parser tests.
func parseMitmFixture(t *testing.T, path string) []*requestView {
	t.Helper()
	f, err := openFixture(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reqs, err := Mitmproxy(f)
	if err != nil {
		t.Fatalf("Mitmproxy(%s): %v", path, err)
	}
	out := make([]*requestView, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, &requestView{
			method: r.Method,
			path:   r.URL.Path,
			rawURL: r.URL.String(),
			query:  r.URL.Query(),
			header: r.Headers,
			body:   r.Body,
			ct:     r.ContentType,
			source: r.Source,
		})
	}
	return out
}

func TestMitmproxyArrayDump(t *testing.T) {
	reqs := parseMitmFixture(t, "../../testdata/mitmproxy/shop.flows.json")
	byKey := reqsByKey(reqs)

	// Static asset (.js), text/css response, the google-analytics host, and the
	// non-HTTP tcp flow must all be filtered out → 4 API requests survive.
	if len(reqs) != 4 {
		t.Fatalf("expected 4 requests after filtering, got %d (keys=%v)", len(reqs), keysOf(byKey))
	}

	// 1. Structured host/scheme/path with query + cookie parsing. Default
	//    https port 443 must not appear in the host.
	prof, ok := byKey["GET /api/users/8821/profile"]
	if !ok {
		t.Fatalf("missing GET /api/users/8821/profile; keys=%v", keysOf(byKey))
	}
	if want := "https://api.shop.example.com/api/users/8821/profile?expand=true"; prof.rawURL != want {
		t.Errorf("profile url = %q, want %q", prof.rawURL, want)
	}
	if got := prof.query["expand"]; len(got) != 1 || got[0] != "true" {
		t.Errorf("expand query = %v, want [true]", got)
	}
	if got := prof.header["Cookie"]; len(got) != 1 || got[0] != "session=alice" {
		t.Errorf("cookie header = %v", got)
	}

	// 2. Bearer header carried through.
	ord, ok := byKey["GET /api/orders/9001"]
	if !ok {
		t.Fatal("missing GET /api/orders/9001")
	}
	if got := ord.header["Authorization"]; len(got) != 1 || got[0] != "Bearer tok_alice" {
		t.Errorf("auth header = %v, want [Bearer tok_alice]", got)
	}

	// 3. JSON body + content-type captured.
	cart, ok := byKey["POST /api/cart/items"]
	if !ok {
		t.Fatal("missing POST /api/cart/items")
	}
	if string(cart.body) != `{"sku":"x"}` {
		t.Errorf("cart body = %q", cart.body)
	}
	if cart.ct != "application/json" {
		t.Errorf("cart content-type = %q, want application/json", cart.ct)
	}

	// 4. Non-default port 8443 must appear in the host; object-form header
	//    ({"name","value"}) must also be honored.
	rep, ok := byKey["GET /api/reports/sales"]
	if !ok {
		t.Fatalf("missing GET /api/reports/sales; keys=%v", keysOf(byKey))
	}
	if want := "https://admin.shop.example.com:8443/api/reports/sales"; rep.rawURL != want {
		t.Errorf("report url = %q, want %q", rep.rawURL, want)
	}
	if got := rep.header["X-Admin"]; len(got) != 1 || got[0] != "1" {
		t.Errorf("object-form header X-Admin = %v, want [1]", got)
	}

	// Provenance.
	if !strings.HasPrefix(prof.source, "mitmproxy:flows[") {
		t.Errorf("source = %q, want mitmproxy:flows[...] prefix", prof.source)
	}
}

func TestMitmproxyJSONLinesDump(t *testing.T) {
	reqs := parseMitmFixture(t, "../../testdata/mitmproxy/stream.flows.jsonl")
	byKey := reqsByKey(reqs)

	// 3 valid lines; the one corrupt line is skipped, not fatal.
	if len(reqs) != 3 {
		t.Fatalf("expected 3 requests (corrupt line skipped), got %d (keys=%v)", len(reqs), keysOf(byKey))
	}

	// Default http port 80 must be elided from the host.
	acct, ok := byKey["GET /v1/accounts/1001"]
	if !ok {
		t.Fatalf("missing GET /v1/accounts/1001; keys=%v", keysOf(byKey))
	}
	if want := "http://api.dev.example.com/v1/accounts/1001"; acct.rawURL != want {
		t.Errorf("account url = %q, want %q", acct.rawURL, want)
	}

	// Multi-cookie header parses into multiple cookies on the request.
	del, ok := byKey["DELETE /v1/accounts/1001/sessions"]
	if !ok {
		t.Fatal("missing DELETE /v1/accounts/1001/sessions")
	}
	if got := del.header["Cookie"]; len(got) != 1 || got[0] != "sid=bob; theme=dark" {
		t.Errorf("cookie header = %v", got)
	}

	// PUT with a JSON body.
	put, ok := byKey["PUT /v1/accounts/1001"]
	if !ok {
		t.Fatal("missing PUT /v1/accounts/1001")
	}
	if string(put.body) != `{"name":"bob"}` {
		t.Errorf("put body = %q", put.body)
	}
}

func TestMitmproxyEmptyAndMalformed(t *testing.T) {
	// Empty array → no requests, no error.
	reqs, err := Mitmproxy(strings.NewReader("[]"))
	if err != nil {
		t.Fatalf("empty array: unexpected error %v", err)
	}
	if len(reqs) != 0 {
		t.Fatalf("empty array: expected 0 requests, got %d", len(reqs))
	}

	// Empty input → descriptive error.
	if _, err := Mitmproxy(strings.NewReader("   \n  ")); err == nil {
		t.Error("empty input: expected error, got nil")
	}

	// Not a flow dump (bare string) → error.
	if _, err := Mitmproxy(strings.NewReader(`"hello"`)); err == nil {
		t.Error("bare string: expected error, got nil")
	}

	// JSON-lines with no decodable flows → error.
	if _, err := Mitmproxy(strings.NewReader("{not json}\n{also bad}\n")); err == nil {
		t.Error("undecodable jsonl: expected error, got nil")
	}
}

func TestMitmproxyAbsoluteFormFallback(t *testing.T) {
	// A flow with no structured host but an absolute-form path (proxy capture
	// of "GET http://h/p") must reconstruct the URL from the path.
	in := `{"request":{"method":"GET","path":"http://legacy.example.com/api/thing","headers":[]}}`
	reqs, err := Mitmproxy(strings.NewReader(in))
	if err != nil {
		t.Fatalf("absolute-form: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("absolute-form: expected 1 request, got %d", len(reqs))
	}
	if got := reqs[0].URL.String(); got != "http://legacy.example.com/api/thing" {
		t.Errorf("absolute-form url = %q", got)
	}
}
