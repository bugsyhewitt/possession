package mutate

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

func orQueryReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://target.example/login?next=%2Fdashboard&id=42")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	return &model.CapturedRequest{
		ID:      "alice-login",
		Method:  "GET",
		URL:     u,
		Headers: h,
	}
}

func orBodyReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://target.example/auth/callback")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	return &model.CapturedRequest{
		ID:          "alice-cb",
		Method:      "POST",
		URL:         u,
		Headers:     h,
		ContentType: "application/x-www-form-urlencoded",
		Body:        []byte("redirect_uri=%2Fhome&user=alice"),
	}
}

func orJSONReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://target.example/oauth/authorize")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	return &model.CapturedRequest{
		ID:          "alice-oauth",
		Method:      "POST",
		URL:         u,
		Headers:     h,
		ContentType: "application/json",
		Body:        []byte(`{"redirect_url":"/home","user":"alice"}`),
	}
}

func orRefererReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://target.example/action")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	h.Set("Referer", "https://target.example/previous")
	return &model.CapturedRequest{
		ID:      "alice-action",
		Method:  "POST",
		URL:     u,
		Headers: h,
	}
}

func orTechniqueKey(v model.Variant) string {
	return v.Mutation.Detail["surface"] + ":" +
		v.Mutation.Detail["parameter"] + ":" +
		v.Mutation.Detail["shape"]
}

func TestOpenRedirect_DisabledByDefault(t *testing.T) {
	if vs := (OpenRedirect{}).Generate(orQueryReq(t), nil); len(vs) != 0 {
		t.Fatalf("open-redirect must be off by default; got %d variants", len(vs))
	}
}

func TestOpenRedirect_NilBaseSafe(t *testing.T) {
	if vs := (OpenRedirect{Enabled: true}).Generate(nil, nil); vs != nil {
		t.Errorf("nil base must yield nil variants; got %v", vs)
	}
}

func TestOpenRedirect_Name(t *testing.T) {
	if got := (OpenRedirect{}).Name(); got != "open-redirect" {
		t.Errorf("Name() = %q; want open-redirect", got)
	}
}

func TestOpenRedirect_NotInDefaultRegistry(t *testing.T) {
	for _, n := range DefaultRegistry().Names() {
		if n == "open-redirect" {
			t.Fatalf("open-redirect must NOT be in DefaultRegistry() (off-by-default mutator)")
		}
	}
}

func TestOpenRedirect_NoEligibleParameters(t *testing.T) {
	u, _ := url.Parse("https://target.example/me?id=42&page=1")
	req := &model.CapturedRequest{Method: "GET", URL: u, Headers: http.Header{}}
	if vs := (OpenRedirect{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Errorf("non-redirect-shaped request must yield 0 variants; got %d", len(vs))
	}
}

func TestOpenRedirect_QueryEligibleByName(t *testing.T) {
	vs := (OpenRedirect{Enabled: true}).Generate(orQueryReq(t), nil)
	if len(vs) != len(openRedirectTechniques) {
		t.Fatalf("query: %d variants; want %d (one per technique)", len(vs), len(openRedirectTechniques))
	}
	for _, v := range vs {
		if v.Mutation.Type != "open-redirect" {
			t.Errorf("Type = %q; want open-redirect", v.Mutation.Type)
		}
		if v.Mutation.Class != "open-redirect" {
			t.Errorf("Class = %q; want open-redirect", v.Mutation.Class)
		}
		if v.Mutation.Detail["surface"] != "query" {
			t.Errorf("surface = %q; want query", v.Mutation.Detail["surface"])
		}
		if v.Mutation.Detail["parameter"] != "next" {
			t.Errorf("parameter = %q; want next", v.Mutation.Detail["parameter"])
		}
		if v.Identity != nil {
			t.Errorf("Identity must be nil (same caller); got %v", v.Identity)
		}
		if v.Base.Headers.Get("Authorization") != "Bearer alice-token" {
			t.Errorf("caller credentials altered: %q", v.Base.Headers.Get("Authorization"))
		}
	}
}

func TestOpenRedirect_QueryEligibleByValueShape(t *testing.T) {
	u, _ := url.Parse("https://target.example/x?input=https%3A%2F%2Fpartner.example%2Fa&id=1")
	req := &model.CapturedRequest{Method: "GET", URL: u, Headers: http.Header{}}
	vs := (OpenRedirect{Enabled: true}).Generate(req, nil)
	if len(vs) == 0 {
		t.Fatal("value-shape eligibility must produce variants")
	}
	for _, v := range vs {
		if v.Mutation.Detail["parameter"] != "input" {
			t.Errorf("expected parameter=input; got %q", v.Mutation.Detail["parameter"])
		}
	}
}

func TestOpenRedirect_BodyVariants(t *testing.T) {
	vs := (OpenRedirect{Enabled: true}).Generate(orBodyReq(t), nil)
	if len(vs) != len(openRedirectTechniques) {
		t.Fatalf("body: %d variants; want %d", len(vs), len(openRedirectTechniques))
	}
	for _, v := range vs {
		if v.Mutation.Detail["surface"] != "body" {
			t.Errorf("surface = %q; want body", v.Mutation.Detail["surface"])
		}
		if v.Mutation.Detail["parameter"] != "redirect_uri" {
			t.Errorf("parameter = %q; want redirect_uri", v.Mutation.Detail["parameter"])
		}
		bodyStr := string(v.Base.Body)
		if !strings.Contains(bodyStr, "user=alice") {
			t.Errorf("body lost untouched param: %q", bodyStr)
		}
	}
}

func TestOpenRedirect_JSONVariants(t *testing.T) {
	vs := (OpenRedirect{Enabled: true}).Generate(orJSONReq(t), nil)
	if len(vs) != len(openRedirectTechniques) {
		t.Fatalf("json: %d variants; want %d", len(vs), len(openRedirectTechniques))
	}
	for _, v := range vs {
		if v.Mutation.Detail["surface"] != "json" {
			t.Errorf("surface = %q; want json", v.Mutation.Detail["surface"])
		}
		if v.Mutation.Detail["parameter"] != "redirect_url" {
			t.Errorf("parameter = %q; want redirect_url", v.Mutation.Detail["parameter"])
		}
		if !strings.Contains(string(v.Base.Body), `"user":"alice"`) {
			t.Errorf("json body lost untouched key: %q", string(v.Base.Body))
		}
	}
}

// Referer surface fires only when a Referer is present, and emits the
// header-safe subset of techniques (excludes backslash-host / whitespace-
// prefix that net/http would mangle or reject).
func TestOpenRedirect_RefererVariants(t *testing.T) {
	vs := (OpenRedirect{Enabled: true}).Generate(orRefererReq(t), nil)
	if len(vs) == 0 {
		t.Fatal("referer-bearing request must produce variants")
	}
	var safeCount int
	for _, tech := range openRedirectTechniques {
		if openRedirectHeaderSafe(tech) {
			safeCount++
		}
	}
	if len(vs) != safeCount {
		t.Fatalf("referer: %d variants; want %d (header-safe subset)", len(vs), safeCount)
	}
	for _, v := range vs {
		if v.Mutation.Detail["surface"] != "header" {
			t.Errorf("surface = %q; want header", v.Mutation.Detail["surface"])
		}
		if v.Mutation.Detail["parameter"] != "Referer" {
			t.Errorf("parameter = %q; want Referer", v.Mutation.Detail["parameter"])
		}
		// The mutated Referer must actually carry the payload.
		want := v.Mutation.Detail["payload"]
		if got := v.Base.Headers.Get("Referer"); got != want {
			t.Errorf("Referer = %q; want %q", got, want)
		}
		// Unsafe techniques must never appear on the header surface.
		shape := v.Mutation.Detail["shape"]
		if !openRedirectHeaderSafe(shape) {
			t.Errorf("unsafe technique %q emitted on header surface", shape)
		}
	}
}

// A request with no Referer (and no eligible params) emits nothing from
// the referer branch.
func TestOpenRedirect_NoRefererNoHeaderVariants(t *testing.T) {
	u, _ := url.Parse("https://target.example/x")
	req := &model.CapturedRequest{
		Method:  "POST",
		URL:     u,
		Headers: http.Header{},
	}
	for _, v := range (OpenRedirect{Enabled: true}).Generate(req, nil) {
		if v.Mutation.Detail["surface"] == "header" {
			t.Errorf("no-referer request must not emit header variants; got %q", v.Mutation.Detail["technique"])
		}
	}
}

func TestOpenRedirect_AllTechniquesEmittedOnQuery(t *testing.T) {
	vs := (OpenRedirect{Enabled: true}).Generate(orQueryReq(t), nil)
	got := map[string]bool{}
	for _, v := range vs {
		got[orTechniqueKey(v)] = true
	}
	for _, t1 := range openRedirectTechniques {
		if !got["query:next:"+t1] {
			t.Errorf("missing technique variant %q", t1)
		}
	}
}

func TestOpenRedirect_JSONArrayIgnored(t *testing.T) {
	u, _ := url.Parse("https://target.example/x")
	req := &model.CapturedRequest{
		Method:      "POST",
		URL:         u,
		Headers:     http.Header{},
		ContentType: "application/json",
		Body:        []byte(`["/home","/away"]`),
	}
	if vs := (OpenRedirect{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Errorf("json array body must yield 0 variants; got %d", len(vs))
	}
}

func TestOpenRedirect_BodyMultipartIgnored(t *testing.T) {
	u, _ := url.Parse("https://target.example/x")
	req := &model.CapturedRequest{
		Method:      "POST",
		URL:         u,
		Headers:     http.Header{},
		ContentType: "multipart/form-data; boundary=zzz",
		Body:        []byte("--zzz\r\nContent-Disposition: form-data; name=\"redirect\"\r\n\r\n/home\r\n--zzz--\r\n"),
	}
	vs := (OpenRedirect{Enabled: true}).Generate(req, nil)
	for _, v := range vs {
		if v.Mutation.Detail["surface"] == "body" {
			t.Errorf("multipart body must not emit body-surface variants; got %q", v.Mutation.Detail["technique"])
		}
	}
}

func TestOpenRedirect_Deterministic(t *testing.T) {
	a := (OpenRedirect{Enabled: true}).Generate(orQueryReq(t), nil)
	b := (OpenRedirect{Enabled: true}).Generate(orQueryReq(t), nil)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic length: %d vs %d", len(a), len(b))
	}
	for i := range a {
		ta := openRedirectTechniqueOf(a[i].Mutation)
		tb := openRedirectTechniqueOf(b[i].Mutation)
		if ta != tb {
			t.Errorf("pos %d: %q vs %q", i, ta, tb)
		}
	}
}

func TestOpenRedirect_TechniquesSorted(t *testing.T) {
	vs := (OpenRedirect{Enabled: true}).Generate(orQueryReq(t), nil)
	var shapes []string
	for _, v := range vs {
		shapes = append(shapes, v.Mutation.Detail["shape"])
	}
	if !sort.StringsAreSorted(shapes) {
		t.Errorf("techniques emitted out of order: %v", shapes)
	}
}

func TestOpenRedirect_BaselineURLNotMutated(t *testing.T) {
	req := orQueryReq(t)
	origRawQuery := req.URL.RawQuery
	origPath := req.URL.Path
	_ = (OpenRedirect{Enabled: true}).Generate(req, nil)
	if req.URL.RawQuery != origRawQuery {
		t.Errorf("baseline RawQuery mutated: %q → %q", origRawQuery, req.URL.RawQuery)
	}
	if req.URL.Path != origPath {
		t.Errorf("baseline Path mutated: %q → %q", origPath, req.URL.Path)
	}
}

func TestOpenRedirect_BaselineBodyNotMutated(t *testing.T) {
	req := orBodyReq(t)
	orig := string(req.Body)
	_ = (OpenRedirect{Enabled: true}).Generate(req, nil)
	if string(req.Body) != orig {
		t.Errorf("baseline body mutated: %q → %q", orig, string(req.Body))
	}
}

func TestOpenRedirect_BaselineRefererNotMutated(t *testing.T) {
	req := orRefererReq(t)
	orig := req.Headers.Get("Referer")
	_ = (OpenRedirect{Enabled: true}).Generate(req, nil)
	if req.Headers.Get("Referer") != orig {
		t.Errorf("baseline Referer mutated: %q → %q", orig, req.Headers.Get("Referer"))
	}
}

// Open-redirect variants must NOT clash with ssrf-probe's Type — they are
// different vuln classes (server-side fetch vs. client-side redirect) with
// different fixes (URL allowlist + same-origin check vs. metadata-endpoint
// blocking + outbound URL allowlist).
func TestOpenRedirect_DisjointFromSSRFProbe(t *testing.T) {
	vs := (OpenRedirect{Enabled: true}).Generate(orQueryReq(t), nil)
	for _, v := range vs {
		if v.Mutation.Type == "ssrf-probe" {
			t.Errorf("open-redirect variant must not carry ssrf-probe Type")
		}
		if v.Mutation.Class == "ssrf" {
			t.Errorf("open-redirect variant must not carry ssrf Class")
		}
	}
}

func TestOpenRedirect_PayloadCoverage(t *testing.T) {
	vs := (OpenRedirect{Enabled: true}).Generate(orQueryReq(t), nil)
	byShape := map[string]model.Variant{}
	for _, v := range vs {
		byShape[v.Mutation.Detail["shape"]] = v
	}
	for name, want := range openRedirectPayloads {
		v, ok := byShape[name]
		if !ok {
			t.Fatalf("missing variant for technique %q", name)
		}
		// payload is recorded verbatim in Detail; query body carries an
		// url-encoded copy — decode and check.
		if v.Mutation.Detail["payload"] != want {
			t.Errorf("technique %q: Detail payload %q != want %q",
				name, v.Mutation.Detail["payload"], want)
		}
		decoded, _ := url.QueryUnescape(v.Base.URL.RawQuery)
		if !strings.Contains(decoded, want) {
			t.Errorf("technique %q: decoded query %q missing payload %q",
				name, decoded, want)
		}
		if !strings.Contains(decoded, "id=42") {
			t.Errorf("technique %q: lost untouched param id=42 in %q", name, decoded)
		}
	}
}

func TestOpenRedirect_NameMatchOverInclusive(t *testing.T) {
	for _, name := range []string{
		"next", "next_page", "redirect_uri", "REDIRECT_URL",
		"returnTo", "return_url", "ReturnUrl", "callback_url",
		"goto", "destination", "successUrl", "back_url",
	} {
		if !openRedirectNameMatches(name) {
			t.Errorf("openRedirectNameMatches(%q) = false; want true", name)
		}
	}
	for _, name := range []string{"id", "page", "name", "email", "color"} {
		if openRedirectNameMatches(name) {
			t.Errorf("openRedirectNameMatches(%q) = true; want false", name)
		}
	}
}

func TestOpenRedirect_HeaderSafeExcludesUnsafeShapes(t *testing.T) {
	if openRedirectHeaderSafe("backslash-host") {
		t.Errorf("backslash-host must be header-unsafe")
	}
	if openRedirectHeaderSafe("whitespace-prefix") {
		t.Errorf("whitespace-prefix must be header-unsafe")
	}
	if !openRedirectHeaderSafe("cross-origin") {
		t.Errorf("cross-origin must be header-safe")
	}
}

func TestOpenRedirect_KnownTechniqueMatchesTable(t *testing.T) {
	for _, name := range openRedirectTechniques {
		if !openRedirectKnownTechnique(name) {
			t.Errorf("technique %q listed but missing payload", name)
		}
	}
	if len(openRedirectPayloads) != len(openRedirectTechniques) {
		t.Errorf("payload count %d != technique count %d",
			len(openRedirectPayloads), len(openRedirectTechniques))
	}
}

// Param-name list must stay sorted (the order test pins the set).
func TestOpenRedirect_ParamNamesSorted(t *testing.T) {
	if !sort.StringsAreSorted(openRedirectParamNames) {
		t.Errorf("openRedirectParamNames not sorted: %v", openRedirectParamNames)
	}
}

// Technique list must stay sorted.
func TestOpenRedirect_TechniqueListSorted(t *testing.T) {
	if !sort.StringsAreSorted(openRedirectTechniques) {
		t.Errorf("openRedirectTechniques not sorted: %v", openRedirectTechniques)
	}
}
