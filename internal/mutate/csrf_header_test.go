package mutate

import (
	"net/http"
	"net/url"
	"sort"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// csrfReq builds a POST request authenticated as alice with the given CSRF
// header (name/value, skipped if name == "") and the given CSRF cookie
// (name/value, skipped if name == "").
func csrfReq(t *testing.T, hdrName, hdrVal, cookieName, cookieVal string) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/api/transfer")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	if hdrName != "" {
		h.Set(hdrName, hdrVal)
	}
	req := &model.CapturedRequest{
		ID:      "alice-transfer",
		Method:  "POST",
		URL:     u,
		Headers: h,
		Body:    []byte(`{"to":"bob","amount":10}`),
	}
	if cookieName != "" {
		req.Cookies = []*http.Cookie{{Name: cookieName, Value: cookieVal}}
	}
	return req
}

func techniqueSet(vs []model.Variant) map[string]model.Variant {
	out := make(map[string]model.Variant, len(vs))
	for _, v := range vs {
		out[v.Mutation.Detail["technique"]] = v
	}
	return out
}

func TestCSRFHeader_DisabledByDefault(t *testing.T) {
	req := csrfReq(t, "X-CSRF-Token", "real-token", "csrf_cookie", "real-token")
	if vs := (CSRFHeader{}).Generate(req, nil); len(vs) != 0 {
		t.Fatalf("csrf-header must be off by default; got %d variants", len(vs))
	}
}

func TestCSRFHeader_NilBaseSafe(t *testing.T) {
	if vs := (CSRFHeader{Enabled: true}).Generate(nil, nil); vs != nil {
		t.Errorf("nil base must yield nil variants; got %v", vs)
	}
}

// With both a CSRF header and a CSRF cookie, all three families that apply
// (forged-double-submit + reflect-cookie-to-header) fire; inject-missing-header
// does NOT (a header is present).
func TestCSRFHeader_HeaderAndCookie(t *testing.T) {
	req := csrfReq(t, "X-CSRF-Token", "real-token", "csrf_cookie", "real-token")
	vs := CSRFHeader{Enabled: true}.Generate(req, nil)

	techs := techniqueSet(vs)
	if _, ok := techs["forged-double-submit"]; !ok {
		t.Errorf("expected a forged-double-submit variant")
	}
	if _, ok := techs["reflect-cookie-to-header"]; !ok {
		t.Errorf("expected a reflect-cookie-to-header variant")
	}
	if _, ok := techs["inject-missing-header"]; ok {
		t.Errorf("inject-missing-header must NOT fire when a CSRF header is present")
	}
	if len(vs) != 2 {
		t.Fatalf("want 2 variants got %d", len(vs))
	}

	for _, v := range vs {
		if v.Mutation.Type != "csrf-header" {
			t.Errorf("type: want csrf-header got %q", v.Mutation.Type)
		}
		if v.Mutation.Class != "authz-bypass" {
			t.Errorf("class: want authz-bypass got %q", v.Mutation.Class)
		}
		// Caller credentials must be untouched: alice's bearer survives, no swap.
		if v.Identity != nil {
			t.Errorf("identity must be nil (caller unchanged); got %+v", v.Identity)
		}
		if got := v.Base.Headers.Get("Authorization"); got != "Bearer alice-token" {
			t.Errorf("caller bearer must be preserved; got %q", got)
		}
	}
}

// forged-double-submit overwrites BOTH the header and the cookie with one
// identical forged value.
func TestCSRFHeader_ForgedDoubleSubmit(t *testing.T) {
	req := csrfReq(t, "X-CSRF-Token", "real-token", "csrf_cookie", "real-token")
	vs := CSRFHeader{Enabled: true}.Generate(req, nil)
	v := techniqueSet(vs)["forged-double-submit"]
	if v.Base == nil {
		t.Fatal("missing forged-double-submit variant")
	}
	if got := v.Base.Headers.Get("X-CSRF-Token"); got != csrfForgedToken {
		t.Errorf("header must carry the forged token; got %q", got)
	}
	var cookieVal string
	for _, c := range v.Base.Cookies {
		if c.Name == "csrf_cookie" {
			cookieVal = c.Value
		}
	}
	if cookieVal != csrfForgedToken {
		t.Errorf("cookie must carry the forged token; got %q", cookieVal)
	}
	if v.Base.Headers.Get("X-CSRF-Token") != cookieVal {
		t.Errorf("header and cookie must be identical (double-submit shape)")
	}
}

// reflect-cookie-to-header copies the CSRF cookie's value into the CSRF header.
func TestCSRFHeader_ReflectCookieToHeader(t *testing.T) {
	req := csrfReq(t, "X-CSRF-Token", "header-token", "csrf_cookie", "cookie-token")
	vs := CSRFHeader{Enabled: true}.Generate(req, nil)
	v := techniqueSet(vs)["reflect-cookie-to-header"]
	if v.Base == nil {
		t.Fatal("missing reflect-cookie-to-header variant")
	}
	if got := v.Base.Headers.Get("X-CSRF-Token"); got != "cookie-token" {
		t.Errorf("header must reflect the cookie value; got %q", got)
	}
	// The cookie itself is left untouched by this technique.
	for _, c := range v.Base.Cookies {
		if c.Name == "csrf_cookie" && c.Value != "cookie-token" {
			t.Errorf("cookie value must be untouched by reflect technique; got %q", c.Value)
		}
	}
}

// With a CSRF cookie but NO CSRF header, reflect-cookie-to-header still fires
// (targeting the canonical header name); forged-double-submit does not (no
// header to pair); inject-missing-header fires (no header present).
func TestCSRFHeader_CookieOnly(t *testing.T) {
	req := csrfReq(t, "", "", "XSRF-TOKEN", "cookie-token")
	vs := CSRFHeader{Enabled: true}.Generate(req, nil)
	techs := techniqueSet(vs)

	if _, ok := techs["forged-double-submit"]; ok {
		t.Errorf("forged-double-submit must NOT fire without a CSRF header")
	}
	reflect, ok := techs["reflect-cookie-to-header"]
	if !ok {
		t.Fatalf("expected reflect-cookie-to-header")
	}
	if got := reflect.Base.Headers.Get(csrfInjectHeader); got != "cookie-token" {
		t.Errorf("reflect must set the canonical header to the cookie value; got %q", got)
	}
	inject, ok := techs["inject-missing-header"]
	if !ok {
		t.Fatalf("expected inject-missing-header when no CSRF header present")
	}
	if got := inject.Base.Headers.Get(csrfInjectHeader); got != csrfForgedToken {
		t.Errorf("inject must set the canonical header to the forged token; got %q", got)
	}
}

// With a CSRF header but NO CSRF cookie, only inject-missing-header's
// preconditions are absent (a header exists), and the cookie-dependent
// techniques are absent (no cookie) — so no variants at all.
func TestCSRFHeader_HeaderOnly(t *testing.T) {
	req := csrfReq(t, "X-CSRF-Token", "real-token", "", "")
	vs := CSRFHeader{Enabled: true}.Generate(req, nil)
	if len(vs) != 0 {
		t.Fatalf("header-present, cookie-absent must yield 0 variants; got %d (%+v)", len(vs), techniqueSet(vs))
	}
}

// No CSRF material at all: only inject-missing-header fires (no header present),
// seeding a forged token to probe presence-only enforcement.
func TestCSRFHeader_NoCSRFMaterial(t *testing.T) {
	req := csrfReq(t, "", "", "", "")
	vs := CSRFHeader{Enabled: true}.Generate(req, nil)
	if len(vs) != 1 {
		t.Fatalf("want exactly 1 variant (inject-missing-header) got %d", len(vs))
	}
	if vs[0].Mutation.Detail["technique"] != "inject-missing-header" {
		t.Errorf("want inject-missing-header got %q", vs[0].Mutation.Detail["technique"])
	}
	if got := vs[0].Base.Headers.Get(csrfInjectHeader); got != csrfForgedToken {
		t.Errorf("injected header must carry forged token; got %q", got)
	}
}

// Variants must be emitted in a deterministic, sorted-by-technique order across
// repeated calls.
func TestCSRFHeader_Deterministic(t *testing.T) {
	req := csrfReq(t, "X-Csrf-Token", "real-token", "csrf_cookie", "real-token")
	a := CSRFHeader{Enabled: true}.Generate(req, nil)
	b := CSRFHeader{Enabled: true}.Generate(req, nil)
	if len(a) != len(b) {
		t.Fatalf("variant count differs across runs: %d vs %d", len(a), len(b))
	}
	// Order is sorted by technique name.
	names := make([]string, len(a))
	for i, v := range a {
		names[i] = v.Mutation.Detail["technique"]
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("variants must be sorted by technique name; got %v", names)
	}
	for i := range a {
		if a[i].Mutation.Detail["technique"] != b[i].Mutation.Detail["technique"] {
			t.Errorf("variant %d technique order differs across runs", i)
		}
	}
}

// The mutator must not mutate the baseline request (CloneRequest hygiene).
func TestCSRFHeader_DoesNotMutateBase(t *testing.T) {
	req := csrfReq(t, "X-CSRF-Token", "real-token", "csrf_cookie", "real-token")
	_ = CSRFHeader{Enabled: true}.Generate(req, nil)
	if got := req.Headers.Get("X-CSRF-Token"); got != "real-token" {
		t.Errorf("baseline header must be unchanged; got %q", got)
	}
	for _, c := range req.Cookies {
		if c.Name == "csrf_cookie" && c.Value != "real-token" {
			t.Errorf("baseline cookie must be unchanged; got %q", c.Value)
		}
	}
}

// CSRFHeader must NOT be part of the canonical DefaultRegistry — like every
// other gated mutator, it is appended in buildRegistry so the default order
// stays unchanged.
func TestCSRFHeader_NotInDefaultRegistry(t *testing.T) {
	for _, n := range DefaultRegistry().Names() {
		if n == "csrf-header" {
			t.Fatalf("csrf-header must NOT be in DefaultRegistry()")
		}
	}
}
