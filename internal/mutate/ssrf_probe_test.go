package mutate

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// spQueryReq builds a captured GET with a URL-bearing query parameter
// (`url`). Used as the canonical query-surface input.
func spQueryReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/fetch?url=https%3A%2F%2Fpartner.example.com%2Fimg.png&id=42")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	return &model.CapturedRequest{
		ID:      "alice-fetch",
		Method:  "GET",
		URL:     u,
		Headers: h,
	}
}

// spBodyReq builds a captured POST with an urlencoded body containing a
// URL-bearing parameter (`callback_url`).
func spBodyReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/webhooks")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	return &model.CapturedRequest{
		ID:          "alice-webhook",
		Method:      "POST",
		URL:         u,
		Headers:     h,
		ContentType: "application/x-www-form-urlencoded",
		Body:        []byte("callback_url=https%3A%2F%2Fpartner.example.com%2Fhook&name=alice"),
	}
}

// spJSONReq builds a captured POST with a JSON body whose top-level
// field `webhook` carries a URL.
func spJSONReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/integrations")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	return &model.CapturedRequest{
		ID:          "alice-integration",
		Method:      "POST",
		URL:         u,
		Headers:     h,
		ContentType: "application/json",
		Body:        []byte(`{"webhook":"https://partner.example.com/hook","name":"alice"}`),
	}
}

// spTechniques indexes variants by their full technique string for
// assertion lookup. Mirrors ptTechniques from path_traversal_test.go.
func spTechniques(vs []model.Variant) map[string]model.Variant {
	out := make(map[string]model.Variant, len(vs))
	for _, v := range vs {
		key := v.Mutation.Detail["surface"] + ":" +
			v.Mutation.Detail["parameter"] + ":" +
			v.Mutation.Detail["shape"]
		out[key] = v
	}
	return out
}

func TestSSRFProbe_DisabledByDefault(t *testing.T) {
	if vs := (SSRFProbe{}).Generate(spQueryReq(t), nil); len(vs) != 0 {
		t.Fatalf("ssrf-probe must be off by default; got %d variants", len(vs))
	}
}

func TestSSRFProbe_NilBaseSafe(t *testing.T) {
	if vs := (SSRFProbe{Enabled: true}).Generate(nil, nil); vs != nil {
		t.Errorf("nil base must yield nil variants; got %v", vs)
	}
}

func TestSSRFProbe_Name(t *testing.T) {
	if got := (SSRFProbe{}).Name(); got != "ssrf-probe" {
		t.Errorf("Name() = %q; want ssrf-probe", got)
	}
}

// ssrf-probe must NOT be in DefaultRegistry — it is registered separately
// as an opt-in mutator.
func TestSSRFProbe_NotInDefaultRegistry(t *testing.T) {
	for _, n := range DefaultRegistry().Names() {
		if n == "ssrf-probe" {
			t.Fatalf("ssrf-probe must NOT be in DefaultRegistry() (off-by-default mutator)")
		}
	}
}

// A request with no SSRF-shaped query parameter, no body, emits zero
// variants — there is no signal to probe.
func TestSSRFProbe_NoEligibleParameters(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/me?id=42&page=1")
	req := &model.CapturedRequest{Method: "GET", URL: u, Headers: http.Header{}}
	if vs := (SSRFProbe{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Errorf("non-SSRF-shaped request must yield 0 variants; got %d", len(vs))
	}
}

// Query: eligible by name match.
func TestSSRFProbe_QueryEligibleByName(t *testing.T) {
	vs := (SSRFProbe{Enabled: true}).Generate(spQueryReq(t), nil)
	if len(vs) != len(ssrfTechniques) {
		t.Fatalf("query: %d variants; want %d (one per technique)", len(vs), len(ssrfTechniques))
	}
	for _, v := range vs {
		if v.Mutation.Type != "ssrf-probe" {
			t.Errorf("Type = %q; want ssrf-probe", v.Mutation.Type)
		}
		if v.Mutation.Class != "ssrf" {
			t.Errorf("Class = %q; want ssrf", v.Mutation.Class)
		}
		if v.Mutation.Detail["surface"] != "query" {
			t.Errorf("surface = %q; want query", v.Mutation.Detail["surface"])
		}
		if v.Mutation.Detail["parameter"] != "url" {
			t.Errorf("parameter = %q; want url", v.Mutation.Detail["parameter"])
		}
		if v.Identity != nil {
			t.Errorf("Identity must be nil (same caller); got %v", v.Identity)
		}
		if v.Base.Headers.Get("Authorization") != "Bearer alice-token" {
			t.Errorf("caller credentials altered: %q", v.Base.Headers.Get("Authorization"))
		}
	}
}

// Query: eligible by value-shape (parameter name does not match the
// SSRF token list, but its value parses as an absolute http URL).
func TestSSRFProbe_QueryEligibleByValueShape(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/x?input=https%3A%2F%2Fok.example.com%2Fa&id=1")
	req := &model.CapturedRequest{Method: "GET", URL: u, Headers: http.Header{}}
	vs := (SSRFProbe{Enabled: true}).Generate(req, nil)
	if len(vs) == 0 {
		t.Fatal("value-shape eligibility must produce variants")
	}
	for _, v := range vs {
		if v.Mutation.Detail["parameter"] != "input" {
			t.Errorf("expected parameter=input; got %q", v.Mutation.Detail["parameter"])
		}
	}
}

// Body (urlencoded): one variant per technique for each eligible parameter.
func TestSSRFProbe_BodyVariants(t *testing.T) {
	vs := (SSRFProbe{Enabled: true}).Generate(spBodyReq(t), nil)
	if len(vs) != len(ssrfTechniques) {
		t.Fatalf("body: %d variants; want %d", len(vs), len(ssrfTechniques))
	}
	for _, v := range vs {
		if v.Mutation.Detail["surface"] != "body" {
			t.Errorf("surface = %q; want body", v.Mutation.Detail["surface"])
		}
		if v.Mutation.Detail["parameter"] != "callback_url" {
			t.Errorf("parameter = %q; want callback_url", v.Mutation.Detail["parameter"])
		}
		bodyStr := string(v.Base.Body)
		if !strings.Contains(bodyStr, "name=alice") {
			t.Errorf("body lost untouched param: %q", bodyStr)
		}
		payload := v.Mutation.Detail["payload"]
		// The payload may be url-encoded in the wire body; check decoded form too.
		decoded, _ := url.QueryUnescape(bodyStr)
		if !strings.Contains(decoded, payload) {
			t.Errorf("decoded body %q missing payload %q", decoded, payload)
		}
	}
}

// JSON body: one variant per technique for each eligible top-level string
// field.
func TestSSRFProbe_JSONVariants(t *testing.T) {
	vs := (SSRFProbe{Enabled: true}).Generate(spJSONReq(t), nil)
	if len(vs) != len(ssrfTechniques) {
		t.Fatalf("json: %d variants; want %d", len(vs), len(ssrfTechniques))
	}
	for _, v := range vs {
		if v.Mutation.Detail["surface"] != "json" {
			t.Errorf("surface = %q; want json", v.Mutation.Detail["surface"])
		}
		if v.Mutation.Detail["parameter"] != "webhook" {
			t.Errorf("parameter = %q; want webhook", v.Mutation.Detail["parameter"])
		}
		bodyStr := string(v.Base.Body)
		if !strings.Contains(bodyStr, `"name":"alice"`) {
			t.Errorf("json body lost untouched key: %q", bodyStr)
		}
		payload := v.Mutation.Detail["payload"]
		if !strings.Contains(bodyStr, payload) {
			t.Errorf("json body %q missing payload %q", bodyStr, payload)
		}
	}
}

// Every supported technique must produce a variant for an eligible query
// parameter; pins the technique set against silent drift.
func TestSSRFProbe_AllTechniquesEmitted(t *testing.T) {
	vs := (SSRFProbe{Enabled: true}).Generate(spQueryReq(t), nil)
	tech := spTechniques(vs)
	for _, t1 := range ssrfTechniques {
		if _, ok := tech["query:url:"+t1]; !ok {
			t.Errorf("missing technique variant %q", t1)
		}
	}
}

// JSON arrays / scalars produce no variants — there is no named key.
func TestSSRFProbe_JSONArrayIgnored(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/x")
	req := &model.CapturedRequest{
		Method:      "POST",
		URL:         u,
		Headers:     http.Header{},
		ContentType: "application/json",
		Body:        []byte(`["https://x.example.com/a","b"]`),
	}
	if vs := (SSRFProbe{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Errorf("json array body must yield 0 variants; got %d", len(vs))
	}
}

// Non-urlencoded body (multipart, JSON when the JSON branch already ran) is
// not handled by the body branch.
func TestSSRFProbe_BodyMultipartIgnored(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/x")
	req := &model.CapturedRequest{
		Method:      "POST",
		URL:         u,
		Headers:     http.Header{},
		ContentType: "multipart/form-data; boundary=zzz",
		Body:        []byte("--zzz\r\nContent-Disposition: form-data; name=\"url\"\r\n\r\nhttps://x/\r\n--zzz--\r\n"),
	}
	vs := (SSRFProbe{Enabled: true}).Generate(req, nil)
	for _, v := range vs {
		if v.Mutation.Detail["surface"] == "body" {
			t.Errorf("multipart body must not emit body-surface variants; got %q", v.Mutation.Detail["technique"])
		}
	}
}

// Determinism: identical inputs yield identical variant slices.
func TestSSRFProbe_Deterministic(t *testing.T) {
	a := (SSRFProbe{Enabled: true}).Generate(spQueryReq(t), nil)
	b := (SSRFProbe{Enabled: true}).Generate(spQueryReq(t), nil)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic length: %d vs %d", len(a), len(b))
	}
	for i := range a {
		ta := ssrfProbeTechnique(a[i].Mutation)
		tb := ssrfProbeTechnique(b[i].Mutation)
		if ta != tb {
			t.Errorf("pos %d: %q vs %q", i, ta, tb)
		}
	}
}

// Techniques are emitted in sorted order within each parameter — pins the
// sorted-by-name emission contract.
func TestSSRFProbe_TechniquesSorted(t *testing.T) {
	vs := (SSRFProbe{Enabled: true}).Generate(spQueryReq(t), nil)
	var shapes []string
	for _, v := range vs {
		shapes = append(shapes, v.Mutation.Detail["shape"])
	}
	if !sort.StringsAreSorted(shapes) {
		t.Errorf("techniques emitted out of order: %v", shapes)
	}
}

// The baseline URL is NEVER mutated by Generate — every query variant gets
// its own URL via cloneURL.
func TestSSRFProbe_BaselineURLNotMutated(t *testing.T) {
	req := spQueryReq(t)
	origRawQuery := req.URL.RawQuery
	origPath := req.URL.Path
	_ = (SSRFProbe{Enabled: true}).Generate(req, nil)
	if req.URL.RawQuery != origRawQuery {
		t.Errorf("baseline RawQuery mutated: %q → %q", origRawQuery, req.URL.RawQuery)
	}
	if req.URL.Path != origPath {
		t.Errorf("baseline Path mutated: %q → %q", origPath, req.URL.Path)
	}
}

// The baseline body is NEVER mutated — every body variant clones first.
func TestSSRFProbe_BaselineBodyNotMutated(t *testing.T) {
	req := spBodyReq(t)
	orig := string(req.Body)
	_ = (SSRFProbe{Enabled: true}).Generate(req, nil)
	if string(req.Body) != orig {
		t.Errorf("baseline body mutated: %q → %q", orig, string(req.Body))
	}
}

// SSRF probe variants must NOT clash with the parameter-pollution mutator's
// Type — they are different vuln classes with different fixes.
func TestSSRFProbe_DisjointFromParamPollution(t *testing.T) {
	vs := (SSRFProbe{Enabled: true}).Generate(spQueryReq(t), nil)
	for _, v := range vs {
		if v.Mutation.Type == "parameter-pollution" {
			t.Errorf("ssrf-probe variant must not carry parameter-pollution Type")
		}
	}
}

// Payload coverage: each technique's variant body must carry the expected
// payload string (decoded for urlencoded surfaces).
func TestSSRFProbe_PayloadCoverage(t *testing.T) {
	vs := (SSRFProbe{Enabled: true}).Generate(spQueryReq(t), nil)
	tech := spTechniques(vs)
	for name, want := range ssrfPayloads {
		v, ok := tech["query:url:"+name]
		if !ok {
			t.Fatalf("missing variant for technique %q", name)
		}
		decoded, _ := url.QueryUnescape(v.Base.URL.RawQuery)
		if !strings.Contains(decoded, want) {
			t.Errorf("technique %q: decoded query %q missing payload %q",
				name, decoded, want)
		}
		// The untouched second parameter must survive.
		if !strings.Contains(decoded, "id=42") {
			t.Errorf("technique %q: lost untouched param id=42 in %q", name, decoded)
		}
	}
}

// ssrfNameMatches is over-inclusive on substring — `image_url` matches
// (contains `image` and `url`), `redirect_to` matches (contains
// `redirect`), `next_page` matches (contains `next`).
func TestSSRFProbe_NameMatchOverInclusive(t *testing.T) {
	for _, name := range []string{"image_url", "redirect_to", "callback_uri", "next_page", "RETURN_URL", "destination"} {
		if !ssrfNameMatches(name) {
			t.Errorf("ssrfNameMatches(%q) = false; want true", name)
		}
	}
	for _, name := range []string{"id", "page", "name", "email"} {
		if ssrfNameMatches(name) {
			t.Errorf("ssrfNameMatches(%q) = true; want false", name)
		}
	}
}

// ssrfValueLooksURL rejects values that merely contain a colon — only
// absolute http/https URLs with a host are eligible.
func TestSSRFProbe_ValueShapeStrict(t *testing.T) {
	for _, v := range []string{"https://x.example.com/", "http://y.example.com:8080/p"} {
		if !ssrfValueLooksURL(v) {
			t.Errorf("ssrfValueLooksURL(%q) = false; want true", v)
		}
	}
	for _, v := range []string{"", "12:34:56", "key:value", "ftp://x.example.com/", "file:///etc/passwd", "/relative/path"} {
		if ssrfValueLooksURL(v) {
			t.Errorf("ssrfValueLooksURL(%q) = true; want false", v)
		}
	}
}

// replaceFirstValue: only the first occurrence of name is rewritten;
// subsequent occurrences (e.g. an HPP-shaped repeat) are preserved. The
// untouched parameters survive in their original positions.
func TestSSRFProbe_ReplaceFirstValueOnly(t *testing.T) {
	pairs := []orderedPair{
		{name: "url", value: "https://orig.example.com/"},
		{name: "id", value: "42"},
		{name: "url", value: "https://second.example.com/"},
	}
	out := replaceFirstValue(pairs, "url", "http://127.0.0.1/")
	if out[0].value != "http://127.0.0.1/" {
		t.Errorf("first occurrence not rewritten: %q", out[0].value)
	}
	if out[2].value != "https://second.example.com/" {
		t.Errorf("second occurrence mutated: %q", out[2].value)
	}
	if out[1].name != "id" || out[1].value != "42" {
		t.Errorf("intermediate param mutated: %+v", out[1])
	}
}
