package parse

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// reqsByKey indexes parsed requests by "METHOD path" for assertion convenience.
func reqsByKey(reqs []*requestView) map[string]*requestView {
	m := map[string]*requestView{}
	for _, r := range reqs {
		m[r.key()] = r
	}
	return m
}

type requestView struct {
	method string
	path   string
	rawURL string
	query  map[string][]string
	header map[string][]string
	body   []byte
	ct     string
	source string
}

func (r *requestView) key() string { return r.method + " " + r.path }

func parseFixture(t *testing.T, path string) []*requestView {
	t.Helper()
	f, err := openFixture(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reqs, err := OpenAPI(f)
	if err != nil {
		t.Fatalf("OpenAPI(%s): %v", path, err)
	}
	out := make([]*requestView, 0, len(reqs))
	for _, r := range reqs {
		rv := &requestView{
			method: r.Method,
			path:   r.URL.Path,
			rawURL: r.URL.String(),
			query:  r.URL.Query(),
			header: r.Headers,
			body:   r.Body,
			ct:     r.ContentType,
			source: r.Source,
		}
		out = append(out, rv)
	}
	return out
}

func TestOpenAPIPetstoreJSON(t *testing.T) {
	reqs := parseFixture(t, "../../testdata/openapi/petstore.json")
	if len(reqs) != 3 {
		var keys []string
		for _, r := range reqs {
			keys = append(keys, r.key())
		}
		sort.Strings(keys)
		t.Fatalf("got %d requests (%v), want 3", len(reqs), keys)
	}
	by := reqsByKey(reqs)

	// GET /users with required query + header, server-variable base path.
	get := by["GET /v1/users"]
	if get == nil {
		t.Fatalf("missing GET /v1/users; got %v", keysOf(by))
	}
	if get.rawURL[:8] != "https://" || !strings.Contains(get.rawURL, "api.example.com/v1/users") {
		t.Errorf("base URL not applied: %s", get.rawURL)
	}
	if got := get.query["limit"]; len(got) != 1 || got[0] != "25" {
		t.Errorf("limit query = %v, want [25]", got)
	}
	if h := get.header["X-Trace"]; len(h) != 1 || h[0] == "" {
		t.Errorf("required header X-Trace missing: %v", get.header)
	}

	// POST /users synthesizes a JSON body from the $ref'd User schema.
	post := by["POST /v1/users"]
	if post == nil {
		t.Fatalf("missing POST /v1/users")
	}
	if post.ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", post.ct)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(post.body, &body); err != nil {
		t.Fatalf("body not valid JSON: %v (%s)", err, post.body)
	}
	if body["name"] != "alice" {
		t.Errorf("body.name = %v, want alice", body["name"])
	}
	if body["email"] != "user@example.com" {
		t.Errorf("body.email format placeholder = %v", body["email"])
	}
	if body["active"] != true {
		t.Errorf("body.active default = %v, want true", body["active"])
	}

	// Path params from both path-level and operation-level definitions.
	order := by["GET /v1/users/1001/orders/ord-7"]
	if order == nil {
		t.Fatalf("missing GET /v1/users/1001/orders/ord-7; got %v", keysOf(by))
	}
	if !strings.HasPrefix(order.source, "openapi:GET ") {
		t.Errorf("source = %q", order.source)
	}
}

func TestOpenAPIMinimalYAML(t *testing.T) {
	reqs := parseFixture(t, "../../testdata/openapi/minimal.yaml")
	by := reqsByKey(reqs)
	if len(reqs) != 2 {
		t.Fatalf("got %d, want 2: %v", len(reqs), keysOf(by))
	}
	// No servers: relative URL.
	if h := by["GET /health"]; h == nil || h.path != "/health" {
		t.Fatalf("GET /health missing or wrong path: %v", keysOf(by))
	}
	// Integer path param with no example falls back to "1".
	del := by["DELETE /accounts/1"]
	if del == nil {
		t.Fatalf("DELETE /accounts/1 missing (id fallback failed): %v", keysOf(by))
	}
}

func TestOpenAPIStableID(t *testing.T) {
	a := parseFixture(t, "../../testdata/openapi/petstore.json")
	b := parseFixture(t, "../../testdata/openapi/petstore.json")
	if len(a) != len(b) {
		t.Fatalf("len mismatch %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].key() != b[i].key() {
			t.Fatalf("order not deterministic at %d: %q vs %q", i, a[i].key(), b[i].key())
		}
	}
}

func TestOpenAPIRejectsSwagger2(t *testing.T) {
	_, err := OpenAPI(strings.NewReader(`{"swagger":"2.0","paths":{}}`))
	if err == nil || !strings.Contains(err.Error(), "Swagger 2.0") {
		t.Fatalf("want Swagger 2.0 rejection, got %v", err)
	}
}

func TestOpenAPIRejectsUnsupportedVersion(t *testing.T) {
	_, err := OpenAPI(strings.NewReader(`{"openapi":"4.0.0","paths":{"/x":{"get":{}}}}`))
	if err == nil || !strings.Contains(err.Error(), "unsupported version") {
		t.Fatalf("want unsupported-version error, got %v", err)
	}
}

func TestOpenAPIEmptyPaths(t *testing.T) {
	_, err := OpenAPI(strings.NewReader(`{"openapi":"3.0.0","paths":{}}`))
	if err == nil {
		t.Fatal("want error for empty paths")
	}
}

func TestOpenAPIYAMLAndJSONInputAccepted(t *testing.T) {
	jsonSpec := `{"openapi":"3.0.0","paths":{"/ping":{"get":{}}}}`
	reqs, err := OpenAPI(strings.NewReader(jsonSpec))
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(reqs) != 1 || reqs[0].Method != "GET" {
		t.Fatalf("json parse wrong: %+v", reqs)
	}

	yamlSpec := "openapi: 3.0.0\npaths:\n  /ping:\n    get: {}\n"
	reqs2, err := OpenAPI(strings.NewReader(yamlSpec))
	if err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if len(reqs2) != 1 || reqs2[0].Method != "GET" {
		t.Fatalf("yaml parse wrong: %+v", reqs2)
	}
	if reqs[0].ID != reqs2[0].ID {
		t.Errorf("JSON and YAML of same op should share stable ID: %s vs %s", reqs[0].ID, reqs2[0].ID)
	}
}

func TestOpenAPIAllOfMerge(t *testing.T) {
	spec := `{
	  "openapi":"3.0.0",
	  "paths":{"/x":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/C"}}}}}}},
	  "components":{"schemas":{
	    "A":{"type":"object","properties":{"a":{"type":"string","example":"av"}}},
	    "B":{"type":"object","properties":{"b":{"type":"integer","example":7}}},
	    "C":{"allOf":[{"$ref":"#/components/schemas/A"},{"$ref":"#/components/schemas/B"}]}
	  }}
	}`
	reqs, err := OpenAPI(strings.NewReader(spec))
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(reqs[0].Body, &body); err != nil {
		t.Fatalf("body: %v (%s)", err, reqs[0].Body)
	}
	if body["a"] != "av" {
		t.Errorf("allOf member A.a missing: %v", body)
	}
	if got, _ := body["b"].(float64); got != 7 {
		t.Errorf("allOf member B.b missing: %v", body)
	}
}

func keysOf(m map[string]*requestView) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
