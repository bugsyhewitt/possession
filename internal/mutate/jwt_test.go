package mutate

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	jwthelper "github.com/bugsyhewitt/possession/internal/jwt"
	"github.com/bugsyhewitt/possession/internal/model"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	return u
}

// reqWithBearer builds a request whose Authorization header carries a
// real, signed JWT with the given claims.
func reqWithBearer(t *testing.T, claims map[string]any) *model.CapturedRequest {
	t.Helper()
	tok, err := jwthelper.EncodeWithHS256(map[string]any{"alg": "HS256"}, claims, "real-secret")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return &model.CapturedRequest{
		Method:  "GET",
		URL:     mustURL(t, "https://api.example.com/x"),
		Headers: http.Header{"Authorization": []string{"Bearer " + tok}},
	}
}

func TestJWTAlgNone_EmitsThreeCasings(t *testing.T) {
	req := reqWithBearer(t, map[string]any{"sub": "alice", "role": "user"})
	vs := JWTAlgNone{}.Generate(req, nil)
	if len(vs) != 3 {
		t.Fatalf("want 3 variants (none/None/NONE), got %d", len(vs))
	}
	seenAlgs := map[string]bool{}
	for _, v := range vs {
		if v.Mutation.Class != "authn-bypass" {
			t.Errorf("class should be authn-bypass, got %q", v.Mutation.Class)
		}
		alg := v.Mutation.Detail["alg"]
		seenAlgs[alg] = true
		// The mutated bearer should have empty sig (trailing dot).
		newTok := strings.TrimPrefix(v.Base.Headers.Get("Authorization"), "Bearer ")
		parts := strings.Split(newTok, ".")
		if len(parts) != 3 {
			t.Errorf("malformed mutated token: %q", newTok)
			continue
		}
		if parts[2] != "" {
			t.Errorf("sig should be empty, got %q", parts[2])
		}
	}
	for _, want := range []string{"none", "None", "NONE"} {
		if !seenAlgs[want] {
			t.Errorf("missing alg variant %q; seen=%v", want, seenAlgs)
		}
	}
}

func TestJWTSigStrip_OneVariantPerLocation(t *testing.T) {
	req := reqWithBearer(t, map[string]any{"sub": "alice"})
	vs := JWTSigStrip{}.Generate(req, nil)
	if len(vs) != 1 {
		t.Fatalf("want 1 variant, got %d", len(vs))
	}
	if vs[0].Mutation.Class != "authn-bypass" {
		t.Errorf("class: %q", vs[0].Mutation.Class)
	}
	newTok := strings.TrimPrefix(vs[0].Base.Headers.Get("Authorization"), "Bearer ")
	if !strings.HasSuffix(newTok, ".") {
		t.Errorf("sig should be empty (trailing dot); got %q", newTok)
	}
}

func TestJWTClaimTamper_EscalatesRole(t *testing.T) {
	req := reqWithBearer(t, map[string]any{"sub": "alice", "role": "user"})
	vs := JWTClaimTamper{}.Generate(req, nil)
	// Expect at least one variant flipping role→admin with privesc class.
	foundRole := false
	for _, v := range vs {
		if v.Mutation.Detail["claim"] == "role" && v.Mutation.Detail["new"] == "admin" {
			foundRole = true
			if v.Mutation.Class != "privesc" {
				t.Errorf("role tamper class should be privesc, got %q", v.Mutation.Class)
			}
		}
	}
	if !foundRole {
		t.Errorf("expected a role→admin variant; got %d variants", len(vs))
	}
}

func TestJWTClaimTamper_SwapsIdentity(t *testing.T) {
	req := reqWithBearer(t, map[string]any{"sub": "alice@x.com"})
	matrix := &model.RoleMatrix{
		Identities: []model.Identity{
			{Name: "bob", Rank: 10, Markers: []string{"bob@x.com"}},
		},
	}
	vs := JWTClaimTamper{}.Generate(req, matrix)
	foundSwap := false
	for _, v := range vs {
		if v.Mutation.Detail["claim"] == "sub" && v.Mutation.Detail["new"] == "bob@x.com" {
			foundSwap = true
			if v.Mutation.Class != "authn-bypass" {
				t.Errorf("sub swap class should be authn-bypass, got %q", v.Mutation.Class)
			}
		}
	}
	if !foundSwap {
		t.Errorf("expected sub→bob@x.com swap; got %d variants", len(vs))
	}
}

func TestJWTResignWeakKey_OnePerSecret(t *testing.T) {
	req := reqWithBearer(t, map[string]any{"sub": "alice"})
	vs := JWTResignWeakKey{}.Generate(req, nil)
	if len(vs) != len(WeakHMACSecrets) {
		t.Fatalf("want %d variants (one per secret), got %d", len(WeakHMACSecrets), len(vs))
	}
	seen := map[string]bool{}
	for _, v := range vs {
		if v.Mutation.Class != "authn-bypass" {
			t.Errorf("class: %q", v.Mutation.Class)
		}
		seen[v.Mutation.Detail["weak_secret"]] = true
	}
	for _, s := range WeakHMACSecrets {
		if !seen[s] {
			t.Errorf("missing weak secret %q", s)
		}
	}
}

func TestJWTMutators_EmptyWhenNoJWT(t *testing.T) {
	req := &model.CapturedRequest{
		Method:  "GET",
		URL:     mustURL(t, "https://api.example.com/x"),
		Headers: http.Header{"X-Other": []string{"hello"}},
	}
	for _, m := range []Mutator{JWTAlgNone{}, JWTSigStrip{}, JWTClaimTamper{}, JWTResignWeakKey{}} {
		vs := m.Generate(req, &model.RoleMatrix{})
		if len(vs) != 0 {
			t.Errorf("%s: want 0 variants, got %d", m.Name(), len(vs))
		}
	}
}

func TestJWTMutators_DefaultRegistryOrder(t *testing.T) {
	reg := DefaultRegistry()
	names := reg.Names()
	// JWT mutators must be present AFTER the P2 set, in declaration order.
	want := []string{
		"strip-auth", "swap-identity", "downgrade-role", "drop-cookie", "strip-token",
		"jwt-alg-none", "jwt-sig-strip", "jwt-claim-tamper", "jwt-resign-weak-key",
	}
	if len(names) != len(want) {
		t.Fatalf("want %d mutators, got %d (%v)", len(want), len(names), names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("position %d: want %q got %q", i, want[i], names[i])
		}
	}
}
