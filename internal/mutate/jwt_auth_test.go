package mutate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	jwthelper "github.com/bugsyhewitt/possession/internal/jwt"
	"github.com/bugsyhewitt/possession/internal/model"
)

// realSecret is the "true" signing key the mock server is configured with
// in its secure mode. The attacker (the mutator) never knows it.
const realSecret = "the-real-signing-key-only-the-server-knows"

// b64urlNoPad mirrors the encoding the jwt helper uses, for test-side
// assertions on forged tokens.
func b64urlNoPad(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signHS256 computes the HS256 signature over header.payload with secret —
// the verification primitive the mock server uses.
func signHS256(headerDotPayload, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(headerDotPayload))
	return b64urlNoPad(h.Sum(nil))
}

// reqWithRealBearer builds a request carrying a legitimately-signed HS256
// JWT (signed with realSecret) in the Authorization header.
func reqWithRealBearer(t *testing.T, claims map[string]any) *model.CapturedRequest {
	t.Helper()
	tok, err := jwthelper.EncodeWithHS256(map[string]any{"alg": "HS256", "typ": "JWT"}, claims, realSecret)
	if err != nil {
		t.Fatalf("encode real token: %v", err)
	}
	return &model.CapturedRequest{
		Method:  "GET",
		URL:     mustURL(t, "https://api.example.com/account"),
		Headers: http.Header{"Authorization": []string{"Bearer " + tok}},
	}
}

func TestJWTAuth_DisabledByDefault(t *testing.T) {
	req := reqWithRealBearer(t, map[string]any{"sub": "alice"})
	// Zero value ⇒ Enabled false ⇒ no variants.
	if vs := (JWTAuth{}).Generate(req, nil); len(vs) != 0 {
		t.Fatalf("disabled mutator must emit 0 variants, got %d", len(vs))
	}
	if vs := (JWTAuth{Enabled: false}).Generate(req, nil); len(vs) != 0 {
		t.Fatalf("explicitly-disabled mutator must emit 0 variants, got %d", len(vs))
	}
}

func TestJWTAuth_EmptyWhenNoJWT(t *testing.T) {
	req := &model.CapturedRequest{
		Method:  "GET",
		URL:     mustURL(t, "https://api.example.com/x"),
		Headers: http.Header{"X-Other": []string{"hello"}},
	}
	if vs := (JWTAuth{Enabled: true}).Generate(req, &model.RoleMatrix{}); len(vs) != 0 {
		t.Fatalf("no-JWT request must emit 0 variants, got %d", len(vs))
	}
}

func TestJWTAuth_EmitsTwoVariantsPerToken(t *testing.T) {
	req := reqWithRealBearer(t, map[string]any{"sub": "alice", "role": "user"})
	vs := JWTAuth{Enabled: true}.Generate(req, nil)
	if len(vs) != 2 {
		t.Fatalf("want 2 variants (alg:none + blank-secret), got %d", len(vs))
	}

	// Variant 0: alg:none.
	none := vs[0]
	if none.Mutation.Type != mutTypeJWTAuthNone {
		t.Errorf("variant 0 type = %q, want %q", none.Mutation.Type, mutTypeJWTAuthNone)
	}
	if none.Mutation.Class != "authn-bypass" {
		t.Errorf("variant 0 class = %q, want authn-bypass", none.Mutation.Class)
	}
	if none.Mutation.Detail["finding_id"] != FindingJWTNone {
		t.Errorf("variant 0 finding_id = %q, want %q", none.Mutation.Detail["finding_id"], FindingJWTNone)
	}
	if none.Mutation.Detail["severity"] != "high" {
		t.Errorf("variant 0 severity hint = %q, want high", none.Mutation.Detail["severity"])
	}

	// Variant 1: blank-secret.
	blank := vs[1]
	if blank.Mutation.Type != mutTypeJWTAuthBlank {
		t.Errorf("variant 1 type = %q, want %q", blank.Mutation.Type, mutTypeJWTAuthBlank)
	}
	if blank.Mutation.Class != "authn-bypass" {
		t.Errorf("variant 1 class = %q, want authn-bypass", blank.Mutation.Class)
	}
	if blank.Mutation.Detail["finding_id"] != FindingJWTBlankSecret {
		t.Errorf("variant 1 finding_id = %q, want %q", blank.Mutation.Detail["finding_id"], FindingJWTBlankSecret)
	}
	if blank.Mutation.Detail["severity"] != "high" {
		t.Errorf("variant 1 severity hint = %q, want high", blank.Mutation.Detail["severity"])
	}
}

func TestJWTAuth_AlgNoneTokenShape(t *testing.T) {
	req := reqWithRealBearer(t, map[string]any{"sub": "alice"})
	vs := JWTAuth{Enabled: true}.Generate(req, nil)
	tok := bearerToken(t, vs[0])
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("alg:none token must have 3 dot-segments (header.payload.), got %d in %q", len(parts), tok)
	}
	if parts[2] != "" {
		t.Errorf("alg:none signature segment must be empty, got %q", parts[2])
	}
	// Header must decode to exactly {"alg":"none","typ":"JWT"}.
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(hb, &hdr); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if hdr["alg"] != "none" {
		t.Errorf("alg = %v, want none", hdr["alg"])
	}
	if hdr["typ"] != "JWT" {
		t.Errorf("typ = %v, want JWT", hdr["typ"])
	}
	// Claims preserved.
	assertClaim(t, parts[1], "sub", "alice")
}

func TestJWTAuth_BlankSecretSignature(t *testing.T) {
	req := reqWithRealBearer(t, map[string]any{"sub": "alice"})
	vs := JWTAuth{Enabled: true}.Generate(req, nil)
	tok := bearerToken(t, vs[1])
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[2] == "" {
		t.Fatalf("blank-secret token must be signed (3 non-empty segments), got %q", tok)
	}
	// The signature must verify under the EMPTY key, and must NOT verify
	// under the real key.
	headerDotPayload := parts[0] + "." + parts[1]
	if got := signHS256(headerDotPayload, ""); got != parts[2] {
		t.Errorf("signature does not verify under empty key: got %q want %q", parts[2], got)
	}
	if signHS256(headerDotPayload, realSecret) == parts[2] {
		t.Errorf("signature unexpectedly verifies under the real key — not a blank-secret forgery")
	}
	assertClaim(t, parts[1], "sub", "alice")
}

func TestJWTAuth_DeterministicOutput(t *testing.T) {
	req := reqWithRealBearer(t, map[string]any{"sub": "alice", "role": "user"})
	a := JWTAuth{Enabled: true}.Generate(req, nil)
	b := JWTAuth{Enabled: true}.Generate(req, nil)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic length: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if bearerToken(t, a[i]) != bearerToken(t, b[i]) {
			t.Errorf("variant %d non-deterministic", i)
		}
	}
}

func TestJWTAuth_NotInDefaultRegistry(t *testing.T) {
	// JWTAuth is gated and added only in buildRegistry; it must stay out
	// of DefaultRegistry so the canonical order is unchanged.
	for _, n := range DefaultRegistry().Names() {
		if n == (JWTAuth{}).Name() {
			t.Fatalf("jwt-attack must NOT be in DefaultRegistry()")
		}
	}
}

// ─── integration: mock JWT-verifying server ───────────────────────────

// mockJWTServer is an httptest server that emulates an API protected by a
// JWT bearer check. It validates the token's alg and signature exactly the
// way a real (or a misconfigured) backend would.
//
//   - secure mode: rejects alg!=HS256, rejects alg=none, requires the
//     signature to verify under realSecret.
//   - vulnerable mode: trusts the header's alg field — accepts alg=none
//     with no signature, and verifies HS256 against verifierSecret (which
//     in the blank-secret scenario is "").
type mockJWTServer struct {
	verifierSecret string // the key the server checks HS256 sigs against
	acceptAlgNone  bool   // true ⇒ honours alg=none (the bug)
}

func (m mockJWTServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		tok := strings.TrimSpace(auth[len("Bearer "):])
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			http.Error(w, "malformed token", http.StatusUnauthorized)
			return
		}
		hb, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			http.Error(w, "bad header b64", http.StatusUnauthorized)
			return
		}
		var hdr map[string]any
		if err := json.Unmarshal(hb, &hdr); err != nil {
			http.Error(w, "bad header json", http.StatusUnauthorized)
			return
		}
		alg, _ := hdr["alg"].(string)

		switch {
		case strings.EqualFold(alg, "none"):
			// Unsigned token. A correct verifier rejects this outright.
			if !m.acceptAlgNone {
				http.Error(w, "alg=none rejected", http.StatusUnauthorized)
				return
			}
			// Vulnerable: accept with no signature check.
		case strings.EqualFold(alg, "HS256"):
			want := signHS256(parts[0]+"."+parts[1], m.verifierSecret)
			if want != parts[2] {
				http.Error(w, "bad signature", http.StatusUnauthorized)
				return
			}
		default:
			http.Error(w, "unsupported alg", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"account":"secret-data"}`))
	}
}

// sendBearer issues a GET carrying the given bearer token to url and
// returns the status code.
func sendBearer(t *testing.T, url, token string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestJWTAuth_AgainstMockServer drives the forged tokens through real HTTP
// against a JWT-verifying mock server in both secure and vulnerable
// configurations, proving the mutator's tokens are genuine auth-bypass
// payloads (accepted by a misconfigured verifier, rejected by a correct one).
func TestJWTAuth_AgainstMockServer(t *testing.T) {
	baseReq := reqWithRealBearer(t, map[string]any{"sub": "alice", "role": "user"})
	vs := JWTAuth{Enabled: true}.Generate(baseReq, nil)
	if len(vs) != 2 {
		t.Fatalf("want 2 forged variants, got %d", len(vs))
	}
	noneTok := bearerToken(t, vs[0])
	blankTok := bearerToken(t, vs[1])
	realTok := strings.TrimPrefix(baseReq.Headers.Get("Authorization"), "Bearer ")

	t.Run("secure server rejects both forgeries, accepts real token", func(t *testing.T) {
		srv := httptest.NewServer(mockJWTServer{verifierSecret: realSecret, acceptAlgNone: false}.handler())
		defer srv.Close()

		if code := sendBearer(t, srv.URL, realTok); code != http.StatusOK {
			t.Errorf("real token should be accepted, got %d", code)
		}
		if code := sendBearer(t, srv.URL, noneTok); code == http.StatusOK {
			t.Errorf("secure server must reject alg:none forgery, got 200")
		}
		if code := sendBearer(t, srv.URL, blankTok); code == http.StatusOK {
			t.Errorf("secure server must reject blank-secret forgery, got 200")
		}
	})

	t.Run("alg:none-vulnerable server accepts the alg:none forgery", func(t *testing.T) {
		srv := httptest.NewServer(mockJWTServer{verifierSecret: realSecret, acceptAlgNone: true}.handler())
		defer srv.Close()

		if code := sendBearer(t, srv.URL, noneTok); code != http.StatusOK {
			t.Errorf("alg:none-vulnerable server should accept the forgery, got %d", code)
		}
	})

	t.Run("blank-secret-misconfigured server accepts the blank-secret forgery", func(t *testing.T) {
		// Verifier configured with an empty signing key — the exact bug.
		srv := httptest.NewServer(mockJWTServer{verifierSecret: "", acceptAlgNone: false}.handler())
		defer srv.Close()

		if code := sendBearer(t, srv.URL, blankTok); code != http.StatusOK {
			t.Errorf("blank-secret server should accept the forgery, got %d", code)
		}
		// And the real token (signed with realSecret) must NOT verify under "".
		if code := sendBearer(t, srv.URL, realTok); code == http.StatusOK {
			t.Errorf("blank-secret server must reject the real-secret token, got 200")
		}
	})
}

// ─── helpers ──────────────────────────────────────────────────────────

func bearerToken(t *testing.T, v model.Variant) string {
	t.Helper()
	if v.Base == nil {
		t.Fatalf("variant has nil Base")
	}
	return strings.TrimPrefix(v.Base.Headers.Get("Authorization"), "Bearer ")
}

func assertClaim(t *testing.T, payloadSeg, key, want string) {
	t.Helper()
	cb, err := base64.RawURLEncoding.DecodeString(payloadSeg)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(cb, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if got, _ := claims[key].(string); got != want {
		t.Errorf("claim %q = %q, want %q", key, got, want)
	}
}
