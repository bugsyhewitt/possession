package parse

import (
	"strings"
	"testing"
)

// parseBurpFixture parses a Burp items XML fixture into the shared requestView
// shape used by the parser tests.
func parseBurpFixture(t *testing.T, path string) []*requestView {
	t.Helper()
	f, err := openFixture(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reqs, err := Burp(f)
	if err != nil {
		t.Fatalf("Burp(%s): %v", path, err)
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

func TestBurpItemsExport(t *testing.T) {
	reqs := parseBurpFixture(t, "../../testdata/burp/shop.items.xml")
	byKey := reqsByKey(reqs)

	// The .js static asset and the google-analytics host must be filtered out →
	// 4 API requests survive.
	if len(reqs) != 4 {
		t.Fatalf("expected 4 requests after filtering, got %d (keys=%v)", len(reqs), keysOf(byKey))
	}

	// 1. base64 raw request: method/headers/cookie pulled from the raw request;
	//    query preserved from the structured URL; default https port 443 elided.
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
	if got := prof.header["Accept"]; len(got) != 1 || got[0] != "application/json" {
		t.Errorf("accept header = %v", got)
	}

	// 2. Bearer header carried through from the raw request.
	ord, ok := byKey["GET /api/orders/9001"]
	if !ok {
		t.Fatal("missing GET /api/orders/9001")
	}
	if got := ord.header["Authorization"]; len(got) != 1 || got[0] != "Bearer tok_alice" {
		t.Errorf("auth header = %v, want [Bearer tok_alice]", got)
	}

	// 3. POST with JSON body + content-type parsed out of the raw request body.
	cart, ok := byKey["POST /api/cart/items"]
	if !ok {
		t.Fatal("missing POST /api/cart/items")
	}
	if string(cart.body) != `{"sku":"x"}` {
		t.Errorf("cart body = %q, want {\"sku\":\"x\"}", cart.body)
	}
	if cart.ct != "application/json" {
		t.Errorf("cart content-type = %q, want application/json", cart.ct)
	}

	// 4. Non-default port 8443 must appear in the host.
	rep, ok := byKey["GET /api/reports/sales"]
	if !ok {
		t.Fatalf("missing GET /api/reports/sales; keys=%v", keysOf(byKey))
	}
	if want := "https://admin.shop.example.com:8443/api/reports/sales"; rep.rawURL != want {
		t.Errorf("report url = %q, want %q", rep.rawURL, want)
	}

	// Provenance.
	if !strings.HasPrefix(prof.source, "burp:items[") {
		t.Errorf("source = %q, want burp:items[...] prefix", prof.source)
	}
}

func TestBurpPlaintextRawRequest(t *testing.T) {
	// base64="false" request body is taken verbatim (LF-only line endings too).
	in := `<?xml version="1.0"?>
<items>
  <item>
    <url><![CDATA[https://api.example.com/v1/widgets/77]]></url>
    <host>api.example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/v1/widgets/77</path>
    <request base64="false">GET /v1/widgets/77 HTTP/1.1
Host: api.example.com
X-Api-Key: k-bob

</request>
  </item>
</items>`
	reqs, err := Burp(strings.NewReader(in))
	if err != nil {
		t.Fatalf("plaintext raw: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("plaintext raw: expected 1 request, got %d", len(reqs))
	}
	r := reqs[0]
	if r.Method != "GET" {
		t.Errorf("method = %q, want GET", r.Method)
	}
	if got := r.Headers.Get("X-Api-Key"); got != "k-bob" {
		t.Errorf("X-Api-Key = %q, want k-bob", got)
	}
	if r.URL.String() != "https://api.example.com/v1/widgets/77" {
		t.Errorf("url = %q", r.URL.String())
	}
}

func TestBurpStructuredFallbackNoRequest(t *testing.T) {
	// An item with no <request> element falls back to the structured fields:
	// method from <method>, URL assembled from protocol/host/port/path.
	in := `<?xml version="1.0"?>
<items>
  <item>
    <host>api.example.com</host>
    <port>8080</port>
    <protocol>http</protocol>
    <method>DELETE</method>
    <path>/v1/accounts/1001</path>
  </item>
</items>`
	reqs, err := Burp(strings.NewReader(in))
	if err != nil {
		t.Fatalf("structured fallback: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("structured fallback: expected 1 request, got %d", len(reqs))
	}
	r := reqs[0]
	if r.Method != "DELETE" {
		t.Errorf("method = %q, want DELETE", r.Method)
	}
	// Non-default http port 8080 must appear in the host.
	if want := "http://api.example.com:8080/v1/accounts/1001"; r.URL.String() != want {
		t.Errorf("url = %q, want %q", r.URL.String(), want)
	}
}

func TestBurpEmptyAndMalformed(t *testing.T) {
	// Empty <items> → no requests, no error.
	reqs, err := Burp(strings.NewReader(`<?xml version="1.0"?><items></items>`))
	if err != nil {
		t.Fatalf("empty items: unexpected error %v", err)
	}
	if len(reqs) != 0 {
		t.Fatalf("empty items: expected 0 requests, got %d", len(reqs))
	}

	// Wrong root element → descriptive error.
	if _, err := Burp(strings.NewReader(`<?xml version="1.0"?><log></log>`)); err == nil {
		t.Error("wrong root: expected error, got nil")
	}

	// Not XML at all → error.
	if _, err := Burp(strings.NewReader(`{"not":"xml"}`)); err == nil {
		t.Error("non-xml: expected error, got nil")
	}

	// An item with an undecodable base64 request still yields a request via the
	// structured fallback (the bad raw request is skipped, not fatal).
	in := `<?xml version="1.0"?>
<items>
  <item>
    <host>api.example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/ok</path>
    <request base64="true">!!!not-base64!!!</request>
  </item>
</items>`
	reqs, err = Burp(strings.NewReader(in))
	if err != nil {
		t.Fatalf("bad base64: unexpected error %v", err)
	}
	if len(reqs) != 1 || reqs[0].Method != "GET" {
		t.Fatalf("bad base64: expected 1 GET via fallback, got %d", len(reqs))
	}
}
