package mutate

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// ppReq builds a captured GET request with two query parameters, authenticated
// as alice against a protected resource.
func ppReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/account?id=42&role=user")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	return &model.CapturedRequest{
		ID:      "alice-account",
		Method:  "GET",
		URL:     u,
		Headers: h,
	}
}

// ppFormReq builds a POST request with a urlencoded form body.
func ppFormReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/account")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	return &model.CapturedRequest{
		ID:          "alice-form",
		Method:      "POST",
		URL:         u,
		Headers:     h,
		Body:        []byte("id=42&role=user"),
		ContentType: "application/x-www-form-urlencoded",
	}
}

// ppTechniques indexes variants by technique string.
func ppTechniques(vs []model.Variant) map[string]model.Variant {
	out := make(map[string]model.Variant, len(vs))
	for _, v := range vs {
		out[v.Mutation.Detail["technique"]+"|"+v.Mutation.Detail["parameter"]] = v
	}
	return out
}

func TestParamPollution_DisabledByDefault(t *testing.T) {
	if vs := (ParamPollution{}).Generate(ppReq(t), nil); len(vs) != 0 {
		t.Fatalf("parameter-pollution must be off by default; got %d variants", len(vs))
	}
}

func TestParamPollution_NilBaseSafe(t *testing.T) {
	if vs := (ParamPollution{Enabled: true}).Generate(nil, nil); vs != nil {
		t.Errorf("nil base must yield nil variants; got %v", vs)
	}
}

// A request with no query and no body yields no variants — nothing to pollute.
func TestParamPollution_NoParamsNoVariants(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/account")
	req := &model.CapturedRequest{Method: "GET", URL: u, Headers: http.Header{}}
	if vs := (ParamPollution{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Errorf("no params must yield 0 variants; got %d", len(vs))
	}
}

// Two query params × two orderings (append/prepend) = 4 query variants.
func TestParamPollution_QueryVariantCount(t *testing.T) {
	vs := (ParamPollution{Enabled: true}).Generate(ppReq(t), nil)
	if len(vs) != 4 {
		t.Fatalf("query variant count = %d; want 4 (2 params × 2 orders)", len(vs))
	}
}

// Every variant must keep the caller's credentials (Identity == nil) and carry
// the correct Type/Class — this is a same-caller HPP probe, not an identity swap.
func TestParamPollution_KeepsCallerCredentials(t *testing.T) {
	vs := (ParamPollution{Enabled: true}).Generate(ppReq(t), nil)
	if len(vs) == 0 {
		t.Fatal("expected variants for an enabled mutator")
	}
	for _, v := range vs {
		if v.Identity != nil {
			t.Errorf("Identity must be nil (same caller); got %v", v.Identity)
		}
		if v.Base.Headers.Get("Authorization") != "Bearer alice-token" {
			t.Errorf("caller credentials altered; Authorization=%q", v.Base.Headers.Get("Authorization"))
		}
		if v.Mutation.Type != "parameter-pollution" {
			t.Errorf("Type = %q; want parameter-pollution", v.Mutation.Type)
		}
		if v.Mutation.Class != "authz-bypass" {
			t.Errorf("Class = %q; want authz-bypass", v.Mutation.Class)
		}
	}
}

// append ordering duplicates the parameter AFTER its original occurrence;
// prepend BEFORE. The original value is always preserved.
func TestParamPollution_QueryOrdering(t *testing.T) {
	vs := (ParamPollution{Enabled: true}).Generate(ppReq(t), nil)
	tech := ppTechniques(vs)

	app, ok := tech["query-pollute:append|role"]
	if !ok {
		t.Fatal("missing query-pollute:append for role")
	}
	// append: id=42&role=user&role=admin  → role=user precedes role=admin.
	gotApp := app.Base.URL.RawQuery
	wantApp := "id=42&role=user&role=admin"
	if gotApp != wantApp {
		t.Errorf("append RawQuery = %q; want %q", gotApp, wantApp)
	}

	pre, ok := tech["query-pollute:prepend|role"]
	if !ok {
		t.Fatal("missing query-pollute:prepend for role")
	}
	// prepend: id=42&role=admin&role=user → role=admin precedes role=user.
	gotPre := pre.Base.URL.RawQuery
	wantPre := "id=42&role=admin&role=user"
	if gotPre != wantPre {
		t.Errorf("prepend RawQuery = %q; want %q", gotPre, wantPre)
	}
}

// The configured TamperValue overrides the default.
func TestParamPollution_CustomTamperValue(t *testing.T) {
	vs := (ParamPollution{Enabled: true, TamperValue: "9999"}).Generate(ppReq(t), nil)
	found := false
	for _, v := range vs {
		if v.Mutation.Detail["parameter"] == "id" && v.Mutation.Detail["order"] == "append" {
			found = true
			if !strings.Contains(v.Base.URL.RawQuery, "id=9999") {
				t.Errorf("custom tamper value missing; RawQuery=%q", v.Base.URL.RawQuery)
			}
			if v.Mutation.Detail["tamper_value"] != "9999" {
				t.Errorf("tamper_value detail = %q; want 9999", v.Mutation.Detail["tamper_value"])
			}
		}
	}
	if !found {
		t.Fatal("no append variant for id found")
	}
}

// The default tamper value is used when none configured.
func TestParamPollution_DefaultTamperValue(t *testing.T) {
	vs := (ParamPollution{Enabled: true}).Generate(ppReq(t), nil)
	for _, v := range vs {
		if v.Mutation.Detail["tamper_value"] != defaultPollutionValue {
			t.Errorf("tamper_value = %q; want default %q", v.Mutation.Detail["tamper_value"], defaultPollutionValue)
		}
	}
}

// Mutating one variant must not alias the baseline URL (clone isolation).
func TestParamPollution_NoBaselineAliasing(t *testing.T) {
	base := ppReq(t)
	orig := base.URL.RawQuery
	_ = (ParamPollution{Enabled: true}).Generate(base, nil)
	if base.URL.RawQuery != orig {
		t.Errorf("baseline URL RawQuery mutated: %q (was %q)", base.URL.RawQuery, orig)
	}
}

// A urlencoded form body is polluted; the URL is untouched.
func TestParamPollution_FormBody(t *testing.T) {
	vs := (ParamPollution{Enabled: true}).Generate(ppFormReq(t), nil)
	// 2 body params × 2 orders = 4 body variants. No query (URL has no query).
	if len(vs) != 4 {
		t.Fatalf("form body variant count = %d; want 4", len(vs))
	}
	tech := ppTechniques(vs)
	app, ok := tech["body-pollute:append|role"]
	if !ok {
		t.Fatal("missing body-pollute:append for role")
	}
	if got := string(app.Base.Body); got != "id=42&role=user&role=admin" {
		t.Errorf("append body = %q; want id=42&role=user&role=admin", got)
	}
	if app.Mutation.Detail["surface"] != "body" {
		t.Errorf("surface = %q; want body", app.Mutation.Detail["surface"])
	}
}

// JSON bodies are not polluted (HPP does not apply to JSON).
func TestParamPollution_JSONBodyUntouched(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/account")
	req := &model.CapturedRequest{
		Method:      "POST",
		URL:         u,
		Headers:     http.Header{},
		Body:        []byte(`{"role":"user"}`),
		ContentType: "application/json",
	}
	if vs := (ParamPollution{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Errorf("JSON body must not be polluted; got %d variants", len(vs))
	}
}

// Both query and form body are polluted when both are present.
func TestParamPollution_QueryAndBody(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/account?id=42")
	req := &model.CapturedRequest{
		Method:      "POST",
		URL:         u,
		Headers:     http.Header{},
		Body:        []byte("role=user"),
		ContentType: "application/x-www-form-urlencoded; charset=utf-8",
	}
	vs := (ParamPollution{Enabled: true}).Generate(req, nil)
	// 1 query param × 2 + 1 body param × 2 = 4.
	if len(vs) != 4 {
		t.Fatalf("query+body variant count = %d; want 4", len(vs))
	}
	var sawQuery, sawBody bool
	for _, v := range vs {
		switch v.Mutation.Detail["surface"] {
		case "query":
			sawQuery = true
		case "body":
			sawBody = true
		}
	}
	if !sawQuery || !sawBody {
		t.Errorf("expected both query and body surfaces; sawQuery=%v sawBody=%v", sawQuery, sawBody)
	}
}

// Generate must be deterministic: identical input yields an identical variant
// slice (same techniques in the same order).
func TestParamPollution_Deterministic(t *testing.T) {
	a := (ParamPollution{Enabled: true}).Generate(ppReq(t), nil)
	b := (ParamPollution{Enabled: true}).Generate(ppReq(t), nil)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic length: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Mutation.Description != b[i].Mutation.Description {
			t.Errorf("pos %d: non-deterministic description %q vs %q",
				i, a[i].Mutation.Description, b[i].Mutation.Description)
		}
		if a[i].Base.URL.RawQuery != b[i].Base.URL.RawQuery {
			t.Errorf("pos %d: non-deterministic query %q vs %q",
				i, a[i].Base.URL.RawQuery, b[i].Base.URL.RawQuery)
		}
	}
}

// Parameters are processed in sorted name order regardless of input order.
func TestParamPollution_SortedParamOrder(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/x?zeta=1&alpha=2")
	req := &model.CapturedRequest{Method: "GET", URL: u, Headers: http.Header{}}
	vs := (ParamPollution{Enabled: true}).Generate(req, nil)
	var names []string
	last := ""
	for _, v := range vs {
		n := v.Mutation.Detail["parameter"]
		if n != last {
			names = append(names, n)
			last = n
		}
	}
	if len(names) != 2 || names[0] != "alpha" || names[1] != "zeta" {
		t.Errorf("param processing order = %v; want [alpha zeta]", names)
	}
}

// Name() is stable.
func TestParamPollution_Name(t *testing.T) {
	if got := (ParamPollution{}).Name(); got != "parameter-pollution" {
		t.Errorf("Name() = %q; want parameter-pollution", got)
	}
}
