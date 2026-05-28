package parse

import (
	"strings"
	"testing"
)

// parsePostmanFixture parses a Postman collection fixture into the shared
// requestView shape used by the parser tests.
func parsePostmanFixture(t *testing.T, path string) []*requestView {
	t.Helper()
	f, err := openFixture(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reqs, err := Postman(f)
	if err != nil {
		t.Fatalf("Postman(%s): %v", path, err)
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

func TestPostmanShopCollection(t *testing.T) {
	reqs := parsePostmanFixture(t, "../../testdata/postman/shop.postman_collection.json")
	byKey := reqsByKey(reqs)

	if len(reqs) != 5 {
		t.Fatalf("expected 5 requests, got %d", len(reqs))
	}

	// 1. Health: structured URL + collection variables resolved.
	health, ok := byKey["GET /health"]
	if !ok {
		t.Fatal("missing GET /health")
	}
	if want := "https://api.example.com/health"; health.rawURL != want {
		t.Errorf("health url = %q, want %q", health.rawURL, want)
	}

	// 2. Get account: path variable, header, enabled query kept, disabled
	//    header + query dropped.
	get, ok := byKey["GET /accounts/1001"]
	if !ok {
		t.Fatalf("missing GET /accounts/1001; keys=%v", keysOf(byKey))
	}
	if got := get.header["Authorization"]; len(got) != 1 || got[0] != "Bearer tok_alice" {
		t.Errorf("auth header = %v, want [Bearer tok_alice]", got)
	}
	if _, present := get.header["X-Skip"]; present {
		t.Error("disabled header X-Skip should have been dropped")
	}
	if got := get.query["expand"]; len(got) != 1 || got[0] != "true" {
		t.Errorf("expand query = %v, want [true]", got)
	}
	if _, present := get.query["drop"]; present {
		t.Error("disabled query param drop should have been dropped")
	}

	// 3. Create account: raw JSON body with variable substituted + content type
	//    from options.raw.language.
	create, ok := byKey["POST /accounts"]
	if !ok {
		t.Fatal("missing POST /accounts")
	}
	if !strings.Contains(string(create.body), `"owner":"1001"`) {
		t.Errorf("create body did not substitute account_id: %q", create.body)
	}
	if create.ct != "application/json" {
		t.Errorf("create content-type = %q, want application/json", create.ct)
	}

	// 4. Login form: urlencoded body, disabled field dropped.
	login, ok := byKey["POST /login"]
	if !ok {
		t.Fatal("missing POST /login")
	}
	if login.ct != "application/x-www-form-urlencoded" {
		t.Errorf("login content-type = %q", login.ct)
	}
	bs := string(login.body)
	if !strings.Contains(bs, "user=alice") || !strings.Contains(bs, "pass=secret") {
		t.Errorf("login body missing fields: %q", bs)
	}
	if strings.Contains(bs, "ignored") {
		t.Errorf("login body kept a disabled field: %q", bs)
	}

	// 5. Bare string URL form with a query-embedded variable.
	ping, ok := byKey["GET /v1/ping"]
	if !ok {
		t.Fatalf("missing GET /v1/ping; keys=%v", keysOf(byKey))
	}
	if got := ping.query["token"]; len(got) != 1 || got[0] != "tok_alice" {
		t.Errorf("ping token query = %v, want [tok_alice]", got)
	}

	// Source provenance carries the folder breadcrumb.
	if !strings.HasPrefix(get.source, "postman:Accounts/") {
		t.Errorf("get source = %q, want postman:Accounts/ prefix", get.source)
	}
}

// TestPostmanFolderVariableScope verifies inner (folder) scope wins over the
// collection-level default.
func TestPostmanFolderVariableScope(t *testing.T) {
	reqs := parsePostmanFixture(t, "../../testdata/postman/scopes.postman_collection.json")
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	want := "https://svc.example.com/t/aaa/whoami"
	if reqs[0].rawURL != want {
		t.Errorf("scoped url = %q, want %q (folder var should override default)", reqs[0].rawURL, want)
	}
}

func TestPostmanRejectsNonCollection(t *testing.T) {
	cases := map[string]string{
		"har-like":   `{"log":{"version":"1.2","entries":[]}}`,
		"v1":         `{"info":{"schema":"https://schema.getpostman.com/json/collection/v1.0.0/collection.json"},"item":[]}`,
		"no-items":   `{"info":{"name":"x","schema":"foo"}}`,
		"bad-json":   `{not json`,
		"empty-doc":  `{}`,
		"empty-coll": `{"info":{"name":"x","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},"item":[]}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Postman(strings.NewReader(doc)); err == nil {
				t.Errorf("expected error for %s, got nil", name)
			}
		})
	}
}

// TestPostmanUnknownVariableLeftLiteral ensures missing variables remain
// visible rather than silently blanked.
func TestPostmanUnknownVariableLeftLiteral(t *testing.T) {
	doc := `{
      "info": {"name":"x","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
      "item": [{
        "name":"r",
        "request":{"method":"GET","header":[],"url":{"host":["example.com"],"path":["x","{{missing}}"]}}
      }]
    }`
	reqs, err := Postman(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 {
		t.Fatalf("got %d requests", len(reqs))
	}
	if !strings.Contains(reqs[0].URL.Path, "{{missing}}") {
		t.Errorf("unknown var should be left literal, path = %q", reqs[0].URL.Path)
	}
}
