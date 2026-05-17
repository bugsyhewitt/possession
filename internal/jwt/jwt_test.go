package jwt

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

func TestEncodeDecode_RoundTrip(t *testing.T) {
	hdr := map[string]any{"alg": "HS256", "typ": "JWT"}
	claims := map[string]any{"sub": "alice", "role": "user"}
	tok, err := EncodeWithHS256(hdr, claims, "secret")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	h, c, sig, err := Decode(tok)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if h["alg"] != "HS256" {
		t.Errorf("alg roundtrip: %v", h["alg"])
	}
	if c["sub"] != "alice" || c["role"] != "user" {
		t.Errorf("claims roundtrip: %v", c)
	}
	if sig == "" {
		t.Errorf("expected non-empty sig")
	}
}

func TestDecode_AlgNoneLenient(t *testing.T) {
	// alg=none with no signature segment must parse without error.
	tok, err := Encode(map[string]any{"alg": "none", "typ": "JWT"}, map[string]any{"sub": "alice"}, "")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	h, c, sig, err := Decode(tok)
	if err != nil {
		t.Fatalf("decode alg=none: %v", err)
	}
	if h["alg"] != "none" {
		t.Errorf("alg=none preserved: %v", h["alg"])
	}
	if c["sub"] != "alice" {
		t.Errorf("claims: %v", c)
	}
	if sig != "" {
		t.Errorf("sig should be empty for alg=none, got %q", sig)
	}
}

func TestDecode_EmptySigSegment(t *testing.T) {
	// "header.claims." (trailing dot, empty third segment).
	tok, _ := Encode(map[string]any{"alg": "HS256"}, map[string]any{"x": 1}, "")
	if !strings.HasSuffix(tok, ".") {
		t.Fatalf("expected trailing dot, got %q", tok)
	}
	_, _, sig, err := Decode(tok)
	if err != nil {
		t.Fatalf("decode trailing-dot: %v", err)
	}
	if sig != "" {
		t.Errorf("expected empty sig, got %q", sig)
	}
}

func TestEncode_Deterministic(t *testing.T) {
	// Two encodes of the same map must produce identical bytes
	// (variant IDs are hashed off this).
	hdr := map[string]any{"alg": "HS256", "typ": "JWT"}
	claims := map[string]any{"sub": "alice", "iat": 1, "role": "user"}
	a, _ := Encode(hdr, claims, "sig")
	b, _ := Encode(hdr, claims, "sig")
	if a != b {
		t.Errorf("non-deterministic encode:\n  a=%s\n  b=%s", a, b)
	}
}

func TestDetect_BearerHeader(t *testing.T) {
	tok, _ := EncodeWithHS256(map[string]any{"alg": "HS256"}, map[string]any{"sub": "alice"}, "k")
	req := &model.CapturedRequest{
		Method:  "GET",
		URL:     mustURL(t, "https://x/y"),
		Headers: http.Header{"Authorization": []string{"Bearer " + tok}},
	}
	got := Detect(req)
	if len(got) != 1 {
		t.Fatalf("want 1 location, got %d", len(got))
	}
	if got[0].Where != "header" || got[0].Key != "Authorization" || got[0].Raw != tok {
		t.Errorf("unexpected location: %+v", got[0])
	}
}

func TestDetect_Cookie(t *testing.T) {
	tok, _ := EncodeWithHS256(map[string]any{"alg": "HS256"}, map[string]any{"sub": "bob"}, "k")
	req := &model.CapturedRequest{
		Method:  "GET",
		URL:     mustURL(t, "https://x/y"),
		Headers: http.Header{},
		Cookies: []*http.Cookie{{Name: "auth_jwt", Value: tok}},
	}
	got := Detect(req)
	if len(got) != 1 || got[0].Where != "cookie" || got[0].Key != "auth_jwt" {
		t.Fatalf("cookie detect failed: %+v", got)
	}
}

func TestDetect_JSONBody(t *testing.T) {
	tok, _ := EncodeWithHS256(map[string]any{"alg": "HS256"}, map[string]any{"sub": "carol"}, "k")
	body := `{"access_token":"` + tok + `","refresh_token":"xyz"}`
	req := &model.CapturedRequest{
		Method:      "POST",
		URL:         mustURL(t, "https://x/api"),
		Headers:     http.Header{"Content-Type": []string{"application/json"}},
		ContentType: "application/json",
		Body:        []byte(body),
	}
	got := Detect(req)
	if len(got) != 1 || got[0].Where != "body" || got[0].Key != "access_token" {
		t.Fatalf("body detect failed: %+v", got)
	}
}

func TestDetect_NoToken(t *testing.T) {
	req := &model.CapturedRequest{
		Method:  "GET",
		URL:     mustURL(t, "https://x/y"),
		Headers: http.Header{"X-Other": []string{"hello"}},
	}
	got := Detect(req)
	if len(got) != 0 {
		t.Errorf("expected zero locations, got %+v", got)
	}
}

func TestEncode_ExactBytesAlgNone(t *testing.T) {
	// Verify the exact byte output for alg=none with a known claim set
	// — this is what mutators emit, so any drift here would change every
	// JWT variant ID in the corpus.
	got, err := Encode(map[string]any{"alg": "none"}, map[string]any{"sub": "x"}, "")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Header {"alg":"none"} → eyJhbGciOiJub25lIn0
	// Claims {"sub":"x"}    → eyJzdWIiOiJ4In0
	want := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."
	if got != want {
		t.Errorf("alg=none bytes drift:\n  got  %s\n  want %s", got, want)
	}
}

func TestMarshalSorted_StableKeyOrder(t *testing.T) {
	m := map[string]any{"b": 1, "a": 2, "c": 3}
	out, _ := marshalSorted(m)
	if !reflect.DeepEqual(string(out), `{"a":2,"b":1,"c":3}`) {
		t.Errorf("unstable key order: %s", out)
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	return u
}
