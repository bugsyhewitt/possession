package mutate

import (
	"net/http"
	"net/url"
	"sort"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// ctcJSONReq returns a captured request carrying a JSON object body authored
// by alice. Used as the default fixture for the JSON-shape technique set.
func ctcJSONReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/account/update")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	h.Set("Content-Type", "application/json")
	return &model.CapturedRequest{
		ID:          "alice-update-json",
		Method:      "POST",
		URL:         u,
		Headers:     h,
		Body:        []byte(`{"name":"alice","email":"alice@example.com"}`),
		ContentType: "application/json",
	}
}

// ctcXMLReq returns a captured request carrying an XML body authored by alice.
func ctcXMLReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/orders/create")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	h.Set("Content-Type", "application/xml")
	return &model.CapturedRequest{
		ID:          "alice-order-xml",
		Method:      "POST",
		URL:         u,
		Headers:     h,
		Body:        []byte(`<?xml version="1.0"?><order><sku>X1</sku></order>`),
		ContentType: "application/xml",
	}
}

// ctcFormReq returns a captured request carrying a urlencoded form body.
func ctcFormReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/login")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	h.Set("Content-Type", "application/x-www-form-urlencoded")
	return &model.CapturedRequest{
		ID:          "alice-login-form",
		Method:      "POST",
		URL:         u,
		Headers:     h,
		Body:        []byte(`user=alice&pass=hunter2`),
		ContentType: "application/x-www-form-urlencoded",
	}
}

// ctcByTechnique indexes the variants by their technique-detail string.
func ctcByTechnique(vs []model.Variant) map[string]model.Variant {
	out := make(map[string]model.Variant, len(vs))
	for _, v := range vs {
		out[v.Mutation.Detail["technique"]] = v
	}
	return out
}

func TestContentTypeConfusion_DisabledByDefault(t *testing.T) {
	if vs := (ContentTypeConfusion{}).Generate(ctcJSONReq(t), nil); len(vs) != 0 {
		t.Fatalf("content-type-confusion must be off by default; got %d variants", len(vs))
	}
}

func TestContentTypeConfusion_NilBaseSafe(t *testing.T) {
	if vs := (ContentTypeConfusion{Enabled: true}).Generate(nil, nil); vs != nil {
		t.Errorf("nil base must yield nil variants; got %v", vs)
	}
}

func TestContentTypeConfusion_EmptyBodyNoVariants(t *testing.T) {
	req := ctcJSONReq(t)
	req.Body = nil
	if vs := (ContentTypeConfusion{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Errorf("empty body must yield 0 variants; got %d", len(vs))
	}
}

func TestContentTypeConfusion_UnrecognisedShapeNoVariants(t *testing.T) {
	req := ctcJSONReq(t)
	req.Body = []byte{0x00, 0x01, 0x02, 0x03}
	req.Headers.Set("Content-Type", "application/octet-stream")
	req.ContentType = "application/octet-stream"
	if vs := (ContentTypeConfusion{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Errorf("binary body must yield 0 variants; got %d", len(vs))
	}
}

// Every variant must keep the caller's own credentials (Identity == nil) AND
// must keep the body bytes byte-identical — the bug is "same caller, same
// body, different label" and altering either invalidates the probe.
func TestContentTypeConfusion_KeepsCallerCredsAndBody(t *testing.T) {
	base := ctcJSONReq(t)
	vs := (ContentTypeConfusion{Enabled: true}).Generate(base, nil)
	if len(vs) == 0 {
		t.Fatal("expected variants for an enabled content-type-confusion mutator")
	}
	for _, v := range vs {
		tech := v.Mutation.Detail["technique"]
		if v.Identity != nil {
			t.Errorf("technique %q: Identity must be nil (same caller); got %v", tech, v.Identity)
		}
		if v.Base.Headers.Get("Authorization") != "Bearer alice-token" {
			t.Errorf("technique %q: caller credentials altered; Authorization=%q",
				tech, v.Base.Headers.Get("Authorization"))
		}
		if string(v.Base.Body) != string(base.Body) {
			t.Errorf("technique %q: body altered (%q vs %q)", tech, v.Base.Body, base.Body)
		}
		if v.Mutation.Type != "content-type-confusion" {
			t.Errorf("technique %q: Type = %q; want content-type-confusion", tech, v.Mutation.Type)
		}
		if v.Mutation.Class != "authz-bypass" {
			t.Errorf("technique %q: Class = %q; want authz-bypass", tech, v.Mutation.Class)
		}
	}
}

// A JSON body produces exactly four techniques: as-form, as-text, as-xml,
// strip-type. The set is fixed; the test guards against accidental drift.
func TestContentTypeConfusion_JSONTechniqueSet(t *testing.T) {
	vs := (ContentTypeConfusion{Enabled: true}).Generate(ctcJSONReq(t), nil)
	want := []string{"as-form", "as-text", "as-xml", "strip-type"}
	got := make([]string, 0, len(vs))
	for _, v := range vs {
		got = append(got, v.Mutation.Detail["technique"])
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("JSON techniques: got %v; want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("JSON techniques[%d] = %q; want %q (full set: got=%v want=%v)", i, got[i], w, got, want)
		}
	}
}

// The strip-type variant must remove the Content-Type header entirely (not
// merely blank it) and clear ContentType on the captured request struct.
func TestContentTypeConfusion_StripTypeDropsHeader(t *testing.T) {
	vs := (ContentTypeConfusion{Enabled: true}).Generate(ctcJSONReq(t), nil)
	v, ok := ctcByTechnique(vs)["strip-type"]
	if !ok {
		t.Fatal("missing strip-type variant for JSON body")
	}
	if _, present := v.Base.Headers["Content-Type"]; present {
		t.Errorf("strip-type: Content-Type header must be absent; headers=%v", v.Base.Headers)
	}
	if v.Base.ContentType != "" {
		t.Errorf("strip-type: ContentType field = %q; want empty", v.Base.ContentType)
	}
	if v.Mutation.Detail["declared_now"] != "" {
		t.Errorf("strip-type: declared_now = %q; want empty", v.Mutation.Detail["declared_now"])
	}
}

// The as-xml variant must set Content-Type to application/xml on both the
// header map and the struct field (so downstream replay sees the same value
// through either accessor).
func TestContentTypeConfusion_AsXMLSetsBothAccessors(t *testing.T) {
	vs := (ContentTypeConfusion{Enabled: true}).Generate(ctcJSONReq(t), nil)
	v, ok := ctcByTechnique(vs)["as-xml"]
	if !ok {
		t.Fatal("missing as-xml variant for JSON body")
	}
	if got := v.Base.Headers.Get("Content-Type"); got != "application/xml" {
		t.Errorf("as-xml: header Content-Type = %q; want application/xml", got)
	}
	if v.Base.ContentType != "application/xml" {
		t.Errorf("as-xml: ContentType field = %q; want application/xml", v.Base.ContentType)
	}
}

// An XML body yields exactly two techniques (as-json, as-text). No
// strip-type — without a Content-Type the XML wouldn't reach the alternate
// parser this mutator probes.
func TestContentTypeConfusion_XMLTechniqueSet(t *testing.T) {
	vs := (ContentTypeConfusion{Enabled: true}).Generate(ctcXMLReq(t), nil)
	want := []string{"as-json", "as-text"}
	got := make([]string, 0, len(vs))
	for _, v := range vs {
		got = append(got, v.Mutation.Detail["technique"])
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("XML techniques: got %v; want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("XML techniques[%d] = %q; want %q", i, got[i], w)
		}
	}
}

// A urlencoded body yields exactly one technique (as-json). Confirms the
// conservative scoping — urlencoded bodies are easy to mis-sniff so only the
// highest-signal mismatch is emitted.
func TestContentTypeConfusion_FormTechniqueSet(t *testing.T) {
	vs := (ContentTypeConfusion{Enabled: true}).Generate(ctcFormReq(t), nil)
	if len(vs) != 1 {
		t.Fatalf("urlencoded body: got %d variants; want 1", len(vs))
	}
	if vs[0].Mutation.Detail["technique"] != "as-json" {
		t.Errorf("urlencoded: technique = %q; want as-json", vs[0].Mutation.Detail["technique"])
	}
	if vs[0].Mutation.Detail["body_shape"] != "form" {
		t.Errorf("urlencoded: body_shape = %q; want form", vs[0].Mutation.Detail["body_shape"])
	}
}

// A request whose declared Content-Type already matches the target type must
// not produce a variant for that technique — relabelling X to X is a no-op
// and would manifest as noise / false confidence in the comparative ladder.
func TestContentTypeConfusion_SkipsNoOpRelabel(t *testing.T) {
	// Force the JSON body's declared type to text/plain; the as-text technique
	// should now skip (relabelling text/plain → text/plain is a no-op).
	req := ctcJSONReq(t)
	req.Headers.Set("Content-Type", "text/plain")
	req.ContentType = "text/plain"
	vs := (ContentTypeConfusion{Enabled: true}).Generate(req, nil)
	// With Content-Type=text/plain the body is sniffed as JSON (leading "{") so
	// the technique set is still the JSON set; the as-text variant must be
	// skipped (no-op).
	for _, v := range vs {
		if v.Mutation.Detail["technique"] == "as-text" {
			t.Errorf("as-text must be skipped when declared type already matches target; got variant %+v", v)
		}
	}
	// The other three JSON techniques (as-form, as-xml, strip-type) must still
	// be present.
	got := ctcByTechnique(vs)
	for _, want := range []string{"as-form", "as-xml", "strip-type"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing technique %q in skip-no-op variant set", want)
		}
	}
}

// A request with Content-Type carrying a charset parameter
// ("application/json; charset=utf-8") must still be classified as JSON AND
// must correctly detect a no-op relabel (the parameter is irrelevant to the
// media-type comparison).
func TestContentTypeConfusion_HandlesCharsetParameter(t *testing.T) {
	req := ctcJSONReq(t)
	req.Headers.Set("Content-Type", "application/json; charset=utf-8")
	req.ContentType = "application/json; charset=utf-8"
	vs := (ContentTypeConfusion{Enabled: true}).Generate(req, nil)
	if len(vs) == 0 {
		t.Fatal("charset-parameterised JSON Content-Type must still be classified as JSON")
	}
	// The full JSON technique set should be emitted (the as-form, as-text,
	// as-xml, and strip-type variants all relabel away from JSON).
	got := ctcByTechnique(vs)
	for _, want := range []string{"as-form", "as-text", "as-xml", "strip-type"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing technique %q for charset-parameterised JSON", want)
		}
	}
}

// A JSON body whose Content-Type is missing entirely is still classified as
// JSON by body-shape sniffing — the mutator's whole point is to exercise the
// "Content-Type lies (or is missing) and the parser sniffs" defect.
func TestContentTypeConfusion_SniffsJSONWithoutContentType(t *testing.T) {
	req := ctcJSONReq(t)
	req.Headers.Del("Content-Type")
	req.ContentType = ""
	vs := (ContentTypeConfusion{Enabled: true}).Generate(req, nil)
	if len(vs) == 0 {
		t.Fatal("body-sniffed JSON must yield variants even without a declared Content-Type")
	}
	for _, v := range vs {
		if v.Mutation.Detail["body_shape"] != "json" {
			t.Errorf("technique %q: body_shape = %q; want json (sniffed)",
				v.Mutation.Detail["technique"], v.Mutation.Detail["body_shape"])
		}
	}
}

// Output order is deterministic across repeated invocations (same input ⇒ same
// variant sequence). Locks the contract that lets --dry-run and the offline
// corpus cover the mutator without integration tests.
func TestContentTypeConfusion_DeterministicOrder(t *testing.T) {
	m := ContentTypeConfusion{Enabled: true}
	a := m.Generate(ctcJSONReq(t), nil)
	b := m.Generate(ctcJSONReq(t), nil)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic count: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Mutation.Detail["technique"] != b[i].Mutation.Detail["technique"] {
			t.Errorf("order drift at %d: %q vs %q", i,
				a[i].Mutation.Detail["technique"],
				b[i].Mutation.Detail["technique"])
		}
	}
}

// The mutator must be registered in the DefaultRegistry+buildRegistry chain
// (this assertion lives in the cli package test for buildRegistry; here we
// only assert the mutator is constructible and nameable).
func TestContentTypeConfusion_Name(t *testing.T) {
	if got := (ContentTypeConfusion{}).Name(); got != "content-type-confusion" {
		t.Errorf("Name() = %q; want content-type-confusion", got)
	}
}
