package mutate

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// gqlReq returns a request authenticated as alice carrying the given body and
// content type against the given path.
func gqlReq(t *testing.T, path, contentType, body string) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com" + path)
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	return &model.CapturedRequest{
		ID:          "alice-gql",
		Method:      "POST",
		URL:         u,
		Headers:     h,
		ContentType: contentType,
		Body:        []byte(body),
	}
}

func TestGraphQL_DisabledByDefault(t *testing.T) {
	req := gqlReq(t, "/graphql", "application/json", `{"query":"{ me { id } }"}`)
	if vs := (GraphQL{}).Generate(req, nil); len(vs) != 0 {
		t.Fatalf("GraphQL must be off by default; got %d variants", len(vs))
	}
}

func TestGraphQL_EmitsOneVariantPerTechnique(t *testing.T) {
	req := gqlReq(t, "/graphql", "application/json", `{"query":"{ me { id name } }"}`)
	vs := GraphQL{Enabled: true}.Generate(req, nil)

	if len(vs) != len(graphqlTechniques) {
		t.Fatalf("want %d variants got %d", len(graphqlTechniques), len(vs))
	}
	for _, v := range vs {
		if v.Mutation.Type != "graphql" {
			t.Errorf("mutation type: want graphql got %q", v.Mutation.Type)
		}
		if v.Mutation.Class != "graphql-exposure" {
			t.Errorf("class: want graphql-exposure got %q", v.Mutation.Class)
		}
		// Credentials untouched: caller stays alice (Identity nil).
		if v.Identity != nil {
			t.Errorf("identity must be nil (caller unchanged); got %+v", v.Identity)
		}
		if v.Base == nil || len(v.Base.Body) == 0 {
			t.Fatalf("variant must carry a mutated body")
		}
	}
}

func TestGraphQL_IntrospectionVariant(t *testing.T) {
	req := gqlReq(t, "/graphql", "application/json", `{"query":"{ me { id } }"}`)
	vs := GraphQL{Enabled: true}.Generate(req, nil)

	var intro *model.Variant
	for i := range vs {
		if vs[i].Mutation.Detail["technique"] == "introspection" {
			intro = &vs[i]
		}
	}
	if intro == nil {
		t.Fatal("expected an introspection variant")
	}
	if intro.Mutation.Detail["graphql-signal"] != "introspection" {
		t.Errorf("introspection variant must carry graphql-signal=introspection; got %q",
			intro.Mutation.Detail["graphql-signal"])
	}
	canary := intro.Mutation.Detail["graphql-canary"]
	if canary == "" {
		t.Fatal("introspection variant must carry a graphql-canary detail")
	}
	if !strings.HasPrefix(canary, graphqlCanaryPrefix) {
		t.Errorf("canary must use the canary prefix; got %q", canary)
	}
	if !strings.Contains(canary, req.ID) {
		t.Errorf("canary must embed the base request ID; got %q", canary)
	}
	// The introspection query document must be in the rewritten body.
	if !strings.Contains(string(intro.Base.Body), "__schema") {
		t.Errorf("introspection variant body must carry the introspection query; got %q",
			string(intro.Base.Body))
	}
}

func TestGraphQL_MalformedVariantHasNoCanary(t *testing.T) {
	req := gqlReq(t, "/graphql", "application/json", `{"query":"{ me { id } }"}`)
	vs := GraphQL{Enabled: true}.Generate(req, nil)

	for _, v := range vs {
		if v.Mutation.Detail["technique"] == "malformed" {
			if _, ok := v.Mutation.Detail["graphql-canary"]; ok {
				t.Errorf("malformed variant must NOT carry a canary")
			}
			if v.Mutation.Detail["graphql-signal"] != "malformed" {
				t.Errorf("malformed variant must carry graphql-signal=malformed; got %q",
					v.Mutation.Detail["graphql-signal"])
			}
		}
	}
}

func TestGraphQL_JSONShapeReEncodesValidJSON(t *testing.T) {
	// Original carries operationName/variables that no longer match the probe;
	// the rewritten body must be valid JSON with just the probe query.
	req := gqlReq(t, "/graphql", "application/json",
		`{"query":"query Me { me { id } }","operationName":"Me","variables":{"x":1}}`)
	vs := GraphQL{Enabled: true}.Generate(req, nil)
	if len(vs) == 0 {
		t.Fatal("expected variants")
	}
	for _, v := range vs {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(v.Base.Body, &obj); err != nil {
			t.Fatalf("rewritten body must be valid JSON: %v (body=%q)", err, string(v.Base.Body))
		}
		if _, ok := obj["query"]; !ok {
			t.Errorf("rewritten JSON must carry a query field; got %q", string(v.Base.Body))
		}
		// stale operationName/variables must be dropped (they reference the old op).
		if _, ok := obj["operationName"]; ok {
			t.Errorf("rewritten JSON must drop stale operationName; got %q", string(v.Base.Body))
		}
	}
}

func TestGraphQL_RawDocumentShape(t *testing.T) {
	req := gqlReq(t, "/graphql", "application/graphql", `{ me { id } }`)
	vs := GraphQL{Enabled: true}.Generate(req, nil)
	if len(vs) != len(graphqlTechniques) {
		t.Fatalf("raw-document detection failed: want %d got %d", len(graphqlTechniques), len(vs))
	}
	for _, v := range vs {
		// Raw shape: the body IS the GraphQL document, not a JSON envelope.
		body := string(v.Base.Body)
		if strings.HasPrefix(strings.TrimSpace(body), "{\"query\"") {
			t.Errorf("raw-shape variant must not be JSON-wrapped; got %q", body)
		}
	}
}

func TestGraphQL_SkipsNonGraphQLBodies(t *testing.T) {
	cases := []struct {
		name string
		path string
		ct   string
		body string
	}{
		{"plain-json-no-query", "/api/orders", "application/json", `{"name":"alice","id":5}`},
		{"json-array", "/api/orders", "application/json", `[1,2,3]`},
		{"form-encoded", "/api/orders", "application/x-www-form-urlencoded", `id=5&name=alice`},
		{"xml", "/api/orders", "application/xml", `<order><id>5</id></order>`},
		{"empty-graphql-ct", "/graphql", "application/graphql", ``},
		{"query-not-a-string", "/graphql", "application/json", `{"query":123}`},
		{"empty-query", "/graphql", "application/json", `{"query":"   "}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := gqlReq(t, c.path, c.ct, c.body)
			if vs := (GraphQL{Enabled: true}).Generate(req, nil); len(vs) != 0 {
				t.Errorf("%s: want 0 variants got %d", c.name, len(vs))
			}
		})
	}
}

func TestGraphQL_DetectsByJSONQueryFieldWithoutGraphQLPath(t *testing.T) {
	// No /graphql in the path, but a JSON body with a query field ⇒ GraphQL.
	req := gqlReq(t, "/api/gateway", "application/json", `{"query":"mutation { delete(id:1) }"}`)
	vs := GraphQL{Enabled: true}.Generate(req, nil)
	if len(vs) != len(graphqlTechniques) {
		t.Fatalf("JSON query-field detection failed: want %d got %d", len(graphqlTechniques), len(vs))
	}
}

func TestGraphQL_DetectsMutationAliasField(t *testing.T) {
	req := gqlReq(t, "/graphql", "application/json", `{"mutation":"mutation { x }"}`)
	vs := GraphQL{Enabled: true}.Generate(req, nil)
	if len(vs) != len(graphqlTechniques) {
		t.Fatalf("mutation-alias detection failed: want %d got %d", len(graphqlTechniques), len(vs))
	}
}

func TestGraphQL_Deterministic(t *testing.T) {
	req := gqlReq(t, "/graphql", "application/json", `{"query":"{ me { id } }"}`)
	a := GraphQL{Enabled: true}.Generate(req, nil)
	b := GraphQL{Enabled: true}.Generate(req, nil)
	if len(a) != len(b) {
		t.Fatalf("variant count differs across runs: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if string(a[i].Base.Body) != string(b[i].Base.Body) {
			t.Errorf("variant %d body differs across runs", i)
		}
		if a[i].Mutation.Detail["technique"] != b[i].Mutation.Detail["technique"] {
			t.Errorf("variant %d technique order differs across runs", i)
		}
	}
}

func TestGraphQL_NilBaseSafe(t *testing.T) {
	if vs := (GraphQL{Enabled: true}).Generate(nil, nil); vs != nil {
		t.Errorf("nil base must yield nil variants; got %v", vs)
	}
}

func TestGraphQL_NotInDefaultRegistry(t *testing.T) {
	// GraphQL is gated and added only in buildRegistry; it must stay out of
	// DefaultRegistry so the canonical mutator order is unchanged.
	for _, n := range DefaultRegistry().Names() {
		if n == "graphql" {
			t.Fatalf("graphql must NOT be in DefaultRegistry()")
		}
	}
}
