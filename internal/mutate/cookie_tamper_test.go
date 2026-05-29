package mutate

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// ctReq builds a captured request authenticated by a single session cookie whose
// value (provided by the caller) carries a privilege claim to be tampered with.
func ctReq(t *testing.T, cookieName, cookieVal string) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/account")
	return &model.CapturedRequest{
		ID:      "alice-account",
		Method:  "GET",
		URL:     u,
		Headers: http.Header{},
		Cookies: []*http.Cookie{{Name: cookieName, Value: cookieVal}},
	}
}

// ctTechniques indexes variants by their technique string.
func ctTechniques(vs []model.Variant) map[string]model.Variant {
	out := make(map[string]model.Variant, len(vs))
	for _, v := range vs {
		out[cookieTamperTechnique(v.Mutation)] = v
	}
	return out
}

// cookieValue returns the value of the named cookie on a variant's request.
func cookieValue(v model.Variant, name string) string {
	for _, c := range v.Base.Cookies {
		if c != nil && c.Name == name {
			return c.Value
		}
	}
	return ""
}

func TestCookieTamper_DisabledByDefault(t *testing.T) {
	if vs := (CookieTamper{}).Generate(ctReq(t, "session", "role=user"), nil); len(vs) != 0 {
		t.Fatalf("cookie-tamper must be off by default; got %d variants", len(vs))
	}
}

func TestCookieTamper_NilBaseSafe(t *testing.T) {
	if vs := (CookieTamper{Enabled: true}).Generate(nil, nil); vs != nil {
		t.Errorf("nil base must yield nil variants; got %v", vs)
	}
}

// A request with no cookies produces no variants (nothing to tamper).
func TestCookieTamper_NoCookiesNoVariants(t *testing.T) {
	req := ctReq(t, "session", "role=user")
	req.Cookies = nil
	if vs := (CookieTamper{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Errorf("no cookies must yield 0 variants; got %d", len(vs))
	}
}

// A cookie that is not auth-bearing is left untouched.
func TestCookieTamper_NonAuthCookieSkipped(t *testing.T) {
	// "theme" is not in AuthCookieSubstrings, so it should not be tampered.
	if vs := (CookieTamper{Enabled: true}).Generate(ctReq(t, "theme", "role=user"), nil); len(vs) != 0 {
		t.Errorf("non-auth cookie must yield 0 variants; got %d", len(vs))
	}
}

// Every variant keeps the caller's own credentials (Identity == nil) and carries
// the canonical type/class.
func TestCookieTamper_KeepsCallerCredentials(t *testing.T) {
	vs := (CookieTamper{Enabled: true}).Generate(ctReq(t, "session", "role=user;tier=free"), nil)
	if len(vs) == 0 {
		t.Fatal("expected variants for an enabled cookie-tamper mutator")
	}
	for _, v := range vs {
		tech := cookieTamperTechnique(v.Mutation)
		if v.Identity != nil {
			t.Errorf("technique %q: Identity must be nil (same caller); got %v", tech, v.Identity)
		}
		if v.Mutation.Type != "cookie-tamper" {
			t.Errorf("technique %q: Type = %q; want cookie-tamper", tech, v.Mutation.Type)
		}
		if v.Mutation.Class != "authz-bypass" {
			t.Errorf("technique %q: Class = %q; want authz-bypass", tech, v.Mutation.Class)
		}
	}
}

// value-claim-flip: a plaintext delimited claim is flipped from its unprivileged
// to its privileged form, every other byte preserved.
func TestCookieTamper_ValueClaimFlip(t *testing.T) {
	vs := (CookieTamper{Enabled: true}).Generate(ctReq(t, "session", "role=user;tier=free"), nil)
	tech := ctTechniques(vs)

	v, ok := tech["value-claim-flip:session:role"]
	if !ok {
		t.Fatalf("missing value-claim-flip variant for role; got techniques %v", techKeys(vs))
	}
	if got := cookieValue(v, "session"); got != "role=admin;tier=free" {
		t.Errorf("flipped cookie value = %q; want role=admin;tier=free", got)
	}
	if v.Mutation.Detail["claim_from"] != "user" || v.Mutation.Detail["claim_to"] != "admin" {
		t.Errorf("claim detail = %q→%q; want user→admin",
			v.Mutation.Detail["claim_from"], v.Mutation.Detail["claim_to"])
	}
	if v.Mutation.Detail["family"] != "value-claim-flip" {
		t.Errorf("family = %q; want value-claim-flip", v.Mutation.Detail["family"])
	}
}

// A boolean privilege flag (admin=0) flips to its truthy form (admin=1).
func TestCookieTamper_BooleanFlagFlip(t *testing.T) {
	vs := (CookieTamper{Enabled: true}).Generate(ctReq(t, "authflags", "admin=0"), nil)
	tech := ctTechniques(vs)
	v, ok := tech["value-claim-flip:authflags:admin"]
	if !ok {
		t.Fatalf("missing admin flag flip; techniques %v", techKeys(vs))
	}
	if got := cookieValue(v, "authflags"); got != "admin=1" {
		t.Errorf("flipped value = %q; want admin=1", got)
	}
}

// base64-claim-flip: a base64-wrapped value that decodes to a claim is flipped
// inside the decoded form and re-encoded with the same alphabet/padding.
func TestCookieTamper_Base64ClaimFlip(t *testing.T) {
	inner := "role=user&uid=42"
	enc := base64.StdEncoding.EncodeToString([]byte(inner))
	vs := (CookieTamper{Enabled: true}).Generate(ctReq(t, "session", enc), nil)
	tech := ctTechniques(vs)

	v, ok := tech["base64-claim-flip:session:role"]
	if !ok {
		t.Fatalf("missing base64-claim-flip variant; techniques %v", techKeys(vs))
	}
	got := cookieValue(v, "session")
	if decoded := decodeAnyB64(t, got); decoded != "role=admin&uid=42" {
		t.Errorf("decoded flipped value = %q; want role=admin&uid=42", decoded)
	}
}

// A base64url (raw, no padding) value round-trips in the same alphabet.
func TestCookieTamper_Base64URLRawRoundTrip(t *testing.T) {
	inner := "is_admin=false&x=1"
	enc := base64.RawURLEncoding.EncodeToString([]byte(inner))
	vs := (CookieTamper{Enabled: true}).Generate(ctReq(t, "auth", enc), nil)
	tech := ctTechniques(vs)
	v, ok := tech["base64-claim-flip:auth:is_admin"]
	if !ok {
		t.Fatalf("missing base64 is_admin flip; techniques %v", techKeys(vs))
	}
	got := cookieValue(v, "auth")
	// The flipped value must decode back to the privileged claim under one of the
	// base64 alphabets; we assert the decoded inner payload, alphabet-agnostic.
	decoded := decodeAnyB64(t, got)
	if decoded != "is_admin=true&x=1" {
		t.Errorf("decoded = %q; want is_admin=true&x=1", decoded)
	}
}

// A JWT-shaped cookie value is left to the JWT mutator family — cookie-tamper must
// not touch it (no base64-claim-flip on a three-segment JWT).
func TestCookieTamper_SkipsJWT(t *testing.T) {
	// header {"alg":"HS256"} . payload {"role":"user"} . sig
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte(`{"role":"user"}`))
	jwt := hdr + "." + pl + ".sig"
	vs := (CookieTamper{Enabled: true}).Generate(ctReq(t, "jwt", jwt), nil)
	for _, v := range vs {
		if v.Mutation.Detail["family"] == "base64-claim-flip" {
			t.Errorf("JWT-shaped cookie must not get a base64-claim-flip; got %q",
				cookieTamperTechnique(v.Mutation))
		}
	}
}

// A cookie value with no matching claim yields no variants (no false no-ops).
func TestCookieTamper_NoMatchingClaim(t *testing.T) {
	if vs := (CookieTamper{Enabled: true}).Generate(ctReq(t, "session", "tier=free;lang=en"), nil); len(vs) != 0 {
		t.Errorf("value with no privilege claim must yield 0 variants; got %d", len(vs))
	}
}

// Token-boundary discipline: role=username must NOT match role=user (the value is
// a different token), so no flip is emitted.
func TestCookieTamper_TokenBoundary(t *testing.T) {
	if vs := (CookieTamper{Enabled: true}).Generate(ctReq(t, "session", "role=username"), nil); len(vs) != 0 {
		t.Errorf("role=username must not match role=user; got %d variants", len(vs))
	}
}

// A binary/encrypted cookie value (non-printable when base64-decoded) is not
// treated as a tamperable claim string.
func TestCookieTamper_BinaryValueSkipped(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0x02, 0xff, 0xfe})
	if vs := (CookieTamper{Enabled: true}).Generate(ctReq(t, "session", enc), nil); len(vs) != 0 {
		t.Errorf("non-printable base64 cookie must yield 0 variants; got %d", len(vs))
	}
}

// Case-insensitive claim matching: ROLE=USER flips, preserving the value rewrite.
func TestCookieTamper_CaseInsensitive(t *testing.T) {
	vs := (CookieTamper{Enabled: true}).Generate(ctReq(t, "session", "ROLE=USER"), nil)
	tech := ctTechniques(vs)
	v, ok := tech["value-claim-flip:session:role"]
	if !ok {
		t.Fatalf("case-insensitive role match failed; techniques %v", techKeys(vs))
	}
	if got := cookieValue(v, "session"); got != "ROLE=admin" {
		t.Errorf("flipped value = %q; want ROLE=admin (key casing preserved)", got)
	}
}

// Generate must be deterministic: identical input yields an identical variant
// slice (same techniques in the same order).
func TestCookieTamper_Deterministic(t *testing.T) {
	in := func() *model.CapturedRequest { return ctReq(t, "session", "role=user;admin=0") }
	a := (CookieTamper{Enabled: true}).Generate(in(), nil)
	b := (CookieTamper{Enabled: true}).Generate(in(), nil)
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

// The original baseline request must not be mutated by Generate (clone discipline).
func TestCookieTamper_DoesNotMutateBaseline(t *testing.T) {
	base := ctReq(t, "session", "role=user")
	_ = (CookieTamper{Enabled: true}).Generate(base, nil)
	if base.Cookies[0].Value != "role=user" {
		t.Errorf("baseline cookie was mutated to %q; want role=user", base.Cookies[0].Value)
	}
}

// decodeAnyB64 decodes s under whichever of the four base64 alphabets succeeds,
// failing the test if none do.
func decodeAnyB64(t *testing.T, s string) string {
	t.Helper()
	for _, e := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if raw, err := e.DecodeString(s); err == nil {
			return string(raw)
		}
	}
	t.Fatalf("value %q is not valid base64 under any alphabet", s)
	return ""
}

// techKeys lists the technique strings of a variant slice for test diagnostics.
func techKeys(vs []model.Variant) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, cookieTamperTechnique(v.Mutation))
	}
	return out
}
