package mutate

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// baseReq returns a fresh CapturedRequest mock with both header and cookie
// auth components so every mutator has something to do.
func baseReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/api/users/42")
	h := http.Header{}
	h.Set("Authorization", "Bearer base-token")
	h.Set("X-Api-Key", "base-api-key")
	h.Set("X-CSRF-Token", "base-csrf")
	h.Set("Content-Type", "application/json")
	return &model.CapturedRequest{
		ID:     "base-1",
		Method: "GET",
		URL:    u,
		Headers: h,
		Cookies: []*http.Cookie{
			{Name: "session", Value: "base-session"},
			{Name: "tracking", Value: "non-auth"},
			{Name: "auth_token", Value: "base-at"},
		},
	}
}

func sampleMatrix() *model.RoleMatrix {
	return &model.RoleMatrix{
		Identities: []model.Identity{
			{Name: "anon", Role: "unauthenticated", Rank: 0},
			{Name: "alice", Role: "user", Rank: 10, Creds: &model.Credentials{
				Headers: map[string]string{"X-Api-Key": "alice"},
				Cookies: map[string]string{"session": "alice-sess"},
			}},
			{Name: "bob", Role: "user", Rank: 10, Creds: &model.Credentials{
				Bearer: "bob-bearer",
			}},
			{Name: "admin", Role: "admin", Rank: 100, Creds: &model.Credentials{
				Basic: &model.BasicAuth{Username: "admin", Password: "pw"},
			}},
		},
	}
}

func TestStripAuth_RemovesEverything(t *testing.T) {
	vs := StripAuth{}.Generate(baseReq(t), nil)
	if len(vs) != 1 {
		t.Fatalf("want 1 variant got %d", len(vs))
	}
	r := vs[0].Base
	if r.Headers.Get("Authorization") != "" {
		t.Error("Authorization not stripped")
	}
	if r.Headers.Get("X-Api-Key") != "" {
		t.Error("X-Api-Key not stripped")
	}
	if r.Headers.Get("X-CSRF-Token") != "" {
		t.Error("X-CSRF-Token not stripped")
	}
	for _, c := range r.Cookies {
		if IsAuthCookie(c.Name) {
			t.Errorf("auth cookie %q survived strip", c.Name)
		}
	}
	if vs[0].Identity != nil {
		t.Error("strip-auth must produce Identity=nil")
	}
}

func TestSwapIdentity_OnePerIdentityIncludingSelf(t *testing.T) {
	m := sampleMatrix()
	vs := SwapIdentity{}.Generate(baseReq(t), m)
	if got, want := len(vs), len(m.Identities); got != want {
		t.Fatalf("want %d variants got %d", want, got)
	}
	// Sorted by (rank, name) → anon, alice, bob, admin
	wantOrder := []string{"anon", "alice", "bob", "admin"}
	for i, v := range vs {
		if v.Identity.Name != wantOrder[i] {
			t.Errorf("pos %d: want %q got %q", i, wantOrder[i], v.Identity.Name)
		}
	}
	// Alice's swap must yield her cookies + headers, not the baseline's.
	alice := vs[1]
	if alice.Base.Headers.Get("X-Api-Key") != "alice" {
		t.Errorf("alice variant lacks her api key, got %q", alice.Base.Headers.Get("X-Api-Key"))
	}
	// Baseline bearer was stripped first.
	if alice.Base.Headers.Get("Authorization") != "" {
		t.Errorf("baseline bearer leaked into alice variant")
	}
}

func TestDowngradeRole_StrictlyLowerRanks(t *testing.T) {
	m := sampleMatrix()
	vs := DowngradeRole{}.Generate(baseReq(t), m)
	// admin is rank 100 (owner); anon/alice/bob all strictly less → 3 variants.
	if len(vs) != 3 {
		t.Fatalf("want 3 downgrade variants got %d", len(vs))
	}
	for _, v := range vs {
		if v.Identity.Rank >= 100 {
			t.Errorf("identity %q rank %d not strictly less than owner", v.Identity.Name, v.Identity.Rank)
		}
	}
}

func TestDropCookie_OnePerAuthCookie(t *testing.T) {
	vs := DropCookie{}.Generate(baseReq(t), nil)
	// base has 2 auth cookies (session, auth_token); 1 non-auth (tracking).
	if len(vs) != 2 {
		t.Fatalf("want 2 drop-cookie variants got %d", len(vs))
	}
	// Verify the non-auth cookie is preserved in every variant.
	for _, v := range vs {
		found := false
		for _, c := range v.Base.Cookies {
			if c.Name == "tracking" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("variant dropped non-auth cookie 'tracking'")
		}
	}
}

func TestStripToken_RemovesBearerAndCSRF(t *testing.T) {
	vs := StripToken{}.Generate(baseReq(t), nil)
	// Base has both bearer Authorization and X-CSRF-Token → 2 variants.
	if len(vs) != 2 {
		t.Fatalf("want 2 strip-token variants got %d", len(vs))
	}
	// Variant 1: bearer gone, cookies preserved.
	if vs[0].Base.Headers.Get("Authorization") != "" {
		t.Error("variant 0 did not remove bearer")
	}
	authPresent := false
	for _, c := range vs[0].Base.Cookies {
		if c.Name == "session" {
			authPresent = true
		}
	}
	if !authPresent {
		t.Error("session cookie should be preserved by strip-token")
	}
}

func TestMutator_EmptyResult(t *testing.T) {
	// drop-cookie with no auth cookies → no variants.
	u, _ := url.Parse("https://x/api")
	req := &model.CapturedRequest{
		Method:  "GET",
		URL:     u,
		Headers: http.Header{},
	}
	if got := (DropCookie{}).Generate(req, nil); len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
	// strip-token with no bearer / no csrf → no variants.
	if got := (StripToken{}).Generate(req, nil); len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

func TestAuthHeaderConstants(t *testing.T) {
	wantHeaders := []string{
		"Authorization", "Cookie", "X-Api-Key", "X-Auth-Token",
		"X-CSRF-Token", "X-CSRFToken", "X-XSRF-Token",
		"X-Access-Token", "X-Session-Token", "Proxy-Authorization",
	}
	if len(AuthHeaderNames) != len(wantHeaders) {
		t.Fatalf("AuthHeaderNames count: want %d got %d", len(wantHeaders), len(AuthHeaderNames))
	}
	for i, h := range wantHeaders {
		if AuthHeaderNames[i] != h {
			t.Errorf("AuthHeaderNames[%d]: want %q got %q", i, h, AuthHeaderNames[i])
		}
	}
	wantSubs := []string{"session", "sess", "auth", "token", "sid", "jwt", "csrf", "xsrf"}
	if len(AuthCookieSubstrings) != len(wantSubs) {
		t.Fatalf("AuthCookieSubstrings count: want %d got %d", len(wantSubs), len(AuthCookieSubstrings))
	}
}

func TestRegistry_DeclarationOrder(t *testing.T) {
	r := DefaultRegistry()
	want := []string{
		"strip-auth", "swap-identity", "downgrade-role", "drop-cookie", "strip-token",
		"jwt-alg-none", "jwt-sig-strip", "jwt-claim-tamper", "jwt-resign-weak-key",
	}
	got := r.Names()
	if len(got) != len(want) {
		t.Fatalf("name count: want %d got %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d: want %q got %q", i, want[i], got[i])
		}
	}
}
