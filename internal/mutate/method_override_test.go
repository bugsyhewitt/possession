package mutate

import (
	"net/http"
	"net/url"
	"sort"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// moReq builds a captured request with the given method, authenticated as
// alice, against a protected admin path.
func moReq(t *testing.T, method string) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/admin/users")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	return &model.CapturedRequest{
		ID:      "alice-admin",
		Method:  method,
		URL:     u,
		Headers: h,
	}
}

// moTechniques returns the set of technique strings present across variants.
func moTechniques(vs []model.Variant) map[string]model.Variant {
	out := make(map[string]model.Variant, len(vs))
	for _, v := range vs {
		out[v.Mutation.Detail["technique"]] = v
	}
	return out
}

func TestMethodOverride_DisabledByDefault(t *testing.T) {
	if vs := (MethodOverride{}).Generate(moReq(t, "GET"), nil); len(vs) != 0 {
		t.Fatalf("method-override must be off by default; got %d variants", len(vs))
	}
}

func TestMethodOverride_NilBaseSafe(t *testing.T) {
	if vs := (MethodOverride{Enabled: true}).Generate(nil, nil); vs != nil {
		t.Errorf("nil base must yield nil variants; got %v", vs)
	}
}

// All variants must keep the caller's own credentials (Identity == nil): this
// is a same-caller verb-tampering probe, NOT an identity swap.
func TestMethodOverride_KeepsCallerCredentials(t *testing.T) {
	vs := (MethodOverride{Enabled: true}).Generate(moReq(t, "GET"), nil)
	if len(vs) == 0 {
		t.Fatal("expected variants for an enabled method-override on GET")
	}
	for _, v := range vs {
		if v.Identity != nil {
			t.Errorf("technique %q: Identity must be nil (same caller); got %v",
				v.Mutation.Detail["technique"], v.Identity)
		}
		if v.Base.Headers.Get("Authorization") != "Bearer alice-token" {
			t.Errorf("technique %q: caller credentials altered; Authorization=%q",
				v.Mutation.Detail["technique"], v.Base.Headers.Get("Authorization"))
		}
		if v.Mutation.Type != "method-override" {
			t.Errorf("variant Type = %q; want method-override", v.Mutation.Type)
		}
		if v.Mutation.Class != "authz-bypass" {
			t.Errorf("technique %q: Class = %q; want authz-bypass",
				v.Mutation.Detail["technique"], v.Mutation.Class)
		}
	}
}

// Override-header variants set a method-override header naming the cross-boundary
// verb, while leaving the request-line method untouched.
func TestMethodOverride_HeaderVariants(t *testing.T) {
	vs := (MethodOverride{Enabled: true}).Generate(moReq(t, "GET"), nil)
	tech := moTechniques(vs)

	for _, hName := range []string{"X-HTTP-Method", "X-HTTP-Method-Override", "X-Method-Override"} {
		v, ok := tech["header:"+hName]
		if !ok {
			t.Fatalf("missing override-header variant for %s", hName)
		}
		// GET is a safe verb → override crosses to POST.
		if got := v.Base.Headers.Get(hName); got != "POST" {
			t.Errorf("%s value = %q; want POST", hName, got)
		}
		// Request-line method unchanged.
		if v.Base.Method != "GET" {
			t.Errorf("%s variant changed request-line method to %q; want GET kept", hName, v.Base.Method)
		}
	}
}

// A state-changing request (POST) has its override header set to GET (crosses
// into the safe band) and its verb-swap siblings drawn from the write family.
func TestMethodOverride_PostOverridesToGet(t *testing.T) {
	vs := (MethodOverride{Enabled: true}).Generate(moReq(t, "POST"), nil)
	tech := moTechniques(vs)
	v, ok := tech["header:X-HTTP-Method-Override"]
	if !ok {
		t.Fatal("missing X-HTTP-Method-Override variant for POST")
	}
	if got := v.Base.Headers.Get("X-HTTP-Method-Override"); got != "GET" {
		t.Errorf("POST override header value = %q; want GET", got)
	}
}

// Verb-swap variants change the request-line method to sibling verbs and never
// re-emit the original verb (no no-op swap).
func TestMethodOverride_VerbSwapVariants(t *testing.T) {
	vs := (MethodOverride{Enabled: true}).Generate(moReq(t, "GET"), nil)
	tech := moTechniques(vs)

	// GET siblings: HEAD, OPTIONS, POST (from methodSiblings["GET"]).
	for _, verb := range []string{"HEAD", "OPTIONS", "POST"} {
		v, ok := tech["verb-swap:"+verb]
		if !ok {
			t.Fatalf("missing verb-swap variant for %s", verb)
		}
		if v.Base.Method != verb {
			t.Errorf("verb-swap:%s set request method to %q; want %s", verb, v.Base.Method, verb)
		}
		if v.Mutation.Detail["method_from"] != "GET" {
			t.Errorf("verb-swap:%s method_from = %q; want GET", verb, v.Mutation.Detail["method_from"])
		}
	}
	// The original verb must never appear as a verb-swap target.
	if _, ok := tech["verb-swap:GET"]; ok {
		t.Error("verb-swap must not re-emit the original GET verb (no-op)")
	}
}

// Case-toggle variant flips the verb case for case-sensitive matchers.
func TestMethodOverride_CaseToggle(t *testing.T) {
	vs := (MethodOverride{Enabled: true}).Generate(moReq(t, "GET"), nil)
	tech := moTechniques(vs)
	v, ok := tech["case-toggle"]
	if !ok {
		t.Fatal("missing case-toggle variant")
	}
	if v.Base.Method != "get" {
		t.Errorf("case-toggle method = %q; want get", v.Base.Method)
	}
}

// An empty captured method is treated as GET (the net/http default) so the
// mutator produces the GET technique set, including a case-toggle to "get".
func TestMethodOverride_EmptyMethodTreatedAsGet(t *testing.T) {
	vs := (MethodOverride{Enabled: true}).Generate(moReq(t, ""), nil)
	tech := moTechniques(vs)
	if _, ok := tech["verb-swap:POST"]; !ok {
		t.Error("empty method should be treated as GET (expected verb-swap:POST)")
	}
	// Empty captured method defaults to GET, so the case-toggle is GET → get.
	if v, ok := tech["case-toggle"]; !ok || v.Base.Method != "get" {
		t.Errorf("empty method should case-toggle the GET default to get; got ok=%v method=%q", ok, v.Base.Method)
	}
}

// A non-standard verb falls back to the universal {GET, POST} sibling set and
// still toggles case.
func TestMethodOverride_UnknownVerbFallback(t *testing.T) {
	vs := (MethodOverride{Enabled: true}).Generate(moReq(t, "PURGE"), nil)
	tech := moTechniques(vs)
	for _, verb := range []string{"GET", "POST"} {
		if _, ok := tech["verb-swap:"+verb]; !ok {
			t.Errorf("unknown verb PURGE should fall back to verb-swap:%s", verb)
		}
	}
	if v, ok := tech["case-toggle"]; !ok || v.Base.Method != "purge" {
		t.Errorf("PURGE should case-toggle to purge; got ok=%v method=%q", ok, v.Base.Method)
	}
}

// Generate must be deterministic: identical input yields an identical variant
// slice (same techniques in the same order).
func TestMethodOverride_Deterministic(t *testing.T) {
	a := (MethodOverride{Enabled: true}).Generate(moReq(t, "GET"), nil)
	b := (MethodOverride{Enabled: true}).Generate(moReq(t, "GET"), nil)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic length: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Mutation.Description != b[i].Mutation.Description {
			t.Errorf("pos %d: non-deterministic description %q vs %q",
				i, a[i].Mutation.Description, b[i].Mutation.Description)
		}
	}
}

// Variant order within each family is sorted (headers by name, verbs by name),
// so generation order is stable without relying on map iteration.
func TestMethodOverride_SortedWithinFamilies(t *testing.T) {
	vs := (MethodOverride{Enabled: true}).Generate(moReq(t, "GET"), nil)

	var headers, verbs []string
	for _, v := range vs {
		switch v.Mutation.Detail["method-override"][:6] {
		case "header":
			headers = append(headers, v.Mutation.Detail["header"])
		case "verb-s":
			verbs = append(verbs, v.Mutation.Detail["method_to"])
		}
	}
	if !sort.StringsAreSorted(headers) {
		t.Errorf("override headers not sorted: %v", headers)
	}
	if !sort.StringsAreSorted(verbs) {
		t.Errorf("verb-swap verbs not sorted: %v", verbs)
	}
}

// toggleMethodCase returns "" for non-alphabetic input so a no-op never emits a
// variant.
func TestToggleMethodCase(t *testing.T) {
	cases := map[string]string{
		"GET":  "get",
		"get":  "GET",
		"Get":  "gET",
		"":     "",
		"1234": "",
	}
	for in, want := range cases {
		if got := toggleMethodCase(in); got != want {
			t.Errorf("toggleMethodCase(%q) = %q; want %q", in, got, want)
		}
	}
}
