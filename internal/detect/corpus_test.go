package detect

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	jwthelper "github.com/bugsyhewitt/possession/internal/jwt"
	"github.com/bugsyhewitt/possession/internal/model"
	"github.com/bugsyhewitt/possession/internal/mutate"
	"github.com/bugsyhewitt/possession/internal/replay"
)

// This file contains the §7 integration corpus: two httptest-backed mock
// apps (vulnapp + secureapp), a noisy endpoint, and a 2xx-denial-page
// endpoint. It is the Gate-E definition of done: vulnapp scans MUST
// surface the planted bypass findings, and secureapp scans MUST produce
// ZERO `bypass` verdicts. If secureapp shows a bypass, the test fails —
// loud, honest, no tuning-the-tests-until-they-pass.

// ─── helpers ──────────────────────────────────────────────────────────

func authForRequest(r *http.Request) (identity string, ok bool) {
	// Token map mirrors the integration matrix in this file.
	bearer := r.Header.Get("Authorization")
	if !strings.HasPrefix(bearer, "Bearer ") {
		return "", false
	}
	tok := strings.TrimPrefix(bearer, "Bearer ")
	switch tok {
	case "alice-tok":
		return "alice", true
	case "bob-tok":
		return "bob", true
	case "admin-tok":
		return "admin", true
	}
	return "", false
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// ─── vulnapp ──────────────────────────────────────────────────────────

// startVulnApp serves a deliberately broken authz surface:
//   - GET /users/{id}        — IDOR: returns ANY user's record regardless of caller
//   - GET /profile           — authn-bypass: no auth check, returns alice's data
//   - POST /admin/promote    — privesc: admin function reachable by anyone with any auth
//   - GET /noisy             — random body each request (for noisy-cap test)
//   - GET /softdeny          — 2xx with a denial-shaped body (errorSignature test)
func startVulnApp(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()

	// Static "database".
	users := map[string]string{
		"alice": `{"id":"alice","email":"alice@example.com","name":"Alice Liddell","balance":1234}`,
		"bob":   `{"id":"bob","email":"bob@example.com","name":"Bob Roberts","balance":99}`,
		"admin": `{"id":"admin","email":"admin@example.com","name":"Administrator","balance":0}`,
	}

	// IDOR: returns the requested user regardless of who's calling.
	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/users/")
		body, ok := users[id]
		if !ok {
			writeJSON(w, 404, `{"error":"not found"}`)
			return
		}
		writeJSON(w, 200, body)
	})

	// authn-bypass: no auth check.
	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, users["alice"])
	})

	// privesc: admin function with no role check.
	mux.HandleFunc("/admin/promote", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"promoted":true,"by":"admin","details":"role elevated to administrator group 42 with grant set 17"}`)
	})

	// noisy: same identity, totally different bodies each call.
	// Guarded with a mutex because httptest spawns concurrent handlers.
	var noisyMu sync.Mutex
	rng := rand.New(rand.NewSource(0))
	mux.HandleFunc("/noisy", func(w http.ResponseWriter, r *http.Request) {
		words := []string{"apple", "banana", "cherry", "date", "elderberry", "fig", "grape", "honey"}
		noisyMu.Lock()
		var picks []string
		for i := 0; i < 12; i++ {
			picks = append(picks, words[rng.Intn(len(words))]+fmt.Sprintf("-%d", rng.Intn(99999)))
		}
		noisyMu.Unlock()
		writeJSON(w, 200, fmt.Sprintf(`{"items":[%q]}`, strings.Join(picks, ",")))
	})

	// jwt: vulnerable JWT endpoint that accepts alg=none. Returns alice's
	// data based on the `sub` claim. Used to verify that JWT mutators
	// (jwt-alg-none) trigger an authn-bypass finding.
	mux.HandleFunc("/jwt", func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		sub := vulnableJWTSub(bearer)
		if sub == "" {
			writeJSON(w, 401, `{"error":"missing or unparseable jwt"}`)
			return
		}
		body, ok := users[sub]
		if !ok {
			writeJSON(w, 404, `{"error":"not found"}`)
			return
		}
		writeJSON(w, 200, body)
	})

	// softdeny: 200 with a body that errorSignature will catch.
	mux.HandleFunc("/softdeny", func(w http.ResponseWriter, r *http.Request) {
		// Owner gets the real page; anyone else (or no auth) gets the soft-deny page.
		ident, _ := authForRequest(r)
		if ident == "alice" {
			writeJSON(w, 200, `{"id":"alice","data":{"items":[1,2,3,4,5,6,7,8],"role":"user","group":"std","tier":"gold"}}`)
			return
		}
		writeJSON(w, 200, `{"error":"Access denied — you do not have permission to view this resource"}`)
	})

	return httptest.NewServer(mux)
}

// ─── secureapp ────────────────────────────────────────────────────────

// startSecureApp serves the same routes as vulnapp, but with proper
// authorization enforcement: 403 for cross-user reads, 401 for unauth,
// 403 for non-admin to admin endpoints.
func startSecureApp(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	users := map[string]string{
		"alice": `{"id":"alice","email":"alice@example.com","name":"Alice Liddell","balance":1234}`,
		"bob":   `{"id":"bob","email":"bob@example.com","name":"Bob Roberts","balance":99}`,
		"admin": `{"id":"admin","email":"admin@example.com","name":"Administrator","balance":0}`,
	}

	// IDOR-safe: only the owner of {id} (or admin) can read.
	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := authForRequest(r)
		if !ok {
			writeJSON(w, 401, `{"error":"unauthenticated"}`)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/users/")
		if id != caller && caller != "admin" {
			writeJSON(w, 403, `{"error":"forbidden"}`)
			return
		}
		body, found := users[id]
		if !found {
			writeJSON(w, 404, `{"error":"not found"}`)
			return
		}
		writeJSON(w, 200, body)
	})

	// authn-required profile.
	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := authForRequest(r)
		if !ok {
			writeJSON(w, 401, `{"error":"unauthenticated"}`)
			return
		}
		writeJSON(w, 200, users[caller])
	})

	// Admin only.
	mux.HandleFunc("/admin/promote", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := authForRequest(r)
		if !ok {
			writeJSON(w, 401, `{"error":"unauthenticated"}`)
			return
		}
		if caller != "admin" {
			writeJSON(w, 403, `{"error":"forbidden"}`)
			return
		}
		writeJSON(w, 200, `{"promoted":true,"by":"admin","details":"role elevated to administrator group 42 with grant set 17"}`)
	})

	// Noisy endpoint exists in secureapp too — but enforced.
	var noisyMu2 sync.Mutex
	rng := rand.New(rand.NewSource(1))
	mux.HandleFunc("/noisy", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := authForRequest(r)
		if !ok {
			writeJSON(w, 401, `{"error":"unauthenticated"}`)
			return
		}
		_ = caller
		words := []string{"apple", "banana", "cherry", "date", "elderberry", "fig"}
		noisyMu2.Lock()
		var picks []string
		for i := 0; i < 10; i++ {
			picks = append(picks, fmt.Sprintf(`%q`, words[rng.Intn(len(words))]+fmt.Sprintf("-%d", rng.Intn(99999))))
		}
		noisyMu2.Unlock()
		writeJSON(w, 200, fmt.Sprintf(`{"items":[%s]}`, strings.Join(picks, ",")))
	})

	// jwt: secure endpoint that REJECTS alg=none and stripped sigs.
	// Verifies HS256 against a real secret. Used to assert Gate E: zero
	// bypass findings on the JWT corpus for a properly-implemented verifier.
	mux.HandleFunc("/jwt", func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		sub, ok := secureJWTVerify(bearer)
		if !ok {
			writeJSON(w, 401, `{"error":"invalid jwt"}`)
			return
		}
		body, found := users[sub]
		if !found {
			writeJSON(w, 404, `{"error":"not found"}`)
			return
		}
		writeJSON(w, 200, body)
	})

	// Softdeny in secureapp returns proper 403.
	mux.HandleFunc("/softdeny", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := authForRequest(r)
		if !ok {
			writeJSON(w, 401, `{"error":"unauthenticated"}`)
			return
		}
		if caller != "alice" {
			writeJSON(w, 403, `{"error":"forbidden"}`)
			return
		}
		writeJSON(w, 200, `{"id":"alice","data":{"items":[1,2,3,4,5,6,7,8],"role":"user","group":"std","tier":"gold"}}`)
	})

	return httptest.NewServer(mux)
}

// ─── corpus run helper ────────────────────────────────────────────────

// matrixForServer builds the test matrix where alice is the captured-as
// identity (owner). bob is a peer (used for IDOR via swap-identity) and
// admin is a high-rank identity.
func matrixForServer(base string) *model.RoleMatrix {
	return &model.RoleMatrix{
		Version: "1",
		Target:  model.TargetConfig{BaseURL: base},
		Identities: []model.Identity{
			{Name: "anon", Role: "unauthenticated", Rank: 0},
			{Name: "alice", Role: "user", Rank: 10, Markers: []string{"alice@example.com", "Alice Liddell"}, Creds: &model.Credentials{Bearer: "alice-tok"}},
			{Name: "bob", Role: "user", Rank: 10, Markers: []string{"bob@example.com", "Bob Roberts"}, Creds: &model.Credentials{Bearer: "bob-tok"}},
			{Name: "admin", Role: "administrator", Rank: 100, Markers: []string{"admin@example.com"}, Creds: &model.Credentials{Bearer: "admin-tok"}},
		},
	}
}

// makeCaptured fabricates a CapturedRequest as if alice had performed it.
// PathTemplate is set to mirror what normalize.Apply would have produced.
func makeCaptured(method, baseURL, path, pathTemplate string) *model.CapturedRequest {
	u, _ := url.Parse(baseURL + path)
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-tok")
	h.Set("Accept", "application/json")
	return &model.CapturedRequest{
		ID:           method + " " + path,
		Method:       method,
		URL:          u,
		PathTemplate: pathTemplate,
		Headers:      h,
	}
}

// runCorpus performs the full P3 pipeline against srv:
// owner attribution → baseline plan → variant plan → calibrate → evaluate.
// Returns the aggregated findings and per-endpoint calibration results.
func runCorpus(t *testing.T, srv *httptest.Server, endpointDefs []endpointDef) (allFindings []model.Finding, cals map[string]CalibrationResult, verdictCounts map[string]int, noisy int) {
	matrix := matrixForServer(srv.URL)
	// Build endpoints from defs.
	var endpoints []*model.Endpoint
	for _, d := range endpointDefs {
		cap := makeCaptured(d.method, srv.URL, d.path, d.pathTemplate)
		ep := &model.Endpoint{
			Method:       d.method,
			Host:         cap.URL.Host,
			PathTemplate: d.pathTemplate,
			Samples:      []*model.CapturedRequest{cap},
		}
		endpoints = append(endpoints, ep)
	}
	// Owner attribution.
	for _, ep := range endpoints {
		owner, attr, _ := AttributeOwner(ep.Samples[0], matrix)
		ep.OwnerIdentity = owner
		ep.OwnerAttribution = attr
	}

	// Build baseline plan (3 samples per endpoint).
	const baselineN = 3
	baselinePlan := buildBaselinePlanLocal(endpoints, baselineN)

	// Build variant plan via the standard registry.
	reg := mutate.DefaultRegistry()
	plan := replay.Generate(endpoints, matrix, reg, 0)

	// Run replay engine — no rate limit, generous concurrency, no body cap.
	rs := model.RunSettings{
		RatePerHost: 1000,
		Concurrency: 8,
		MaxBody:     1024 * 1024,
	}
	engine := replay.New(rs, "possession-corpus-test", nil)
	ctx := t.Context()
	baselineResponses := engine.Run(ctx, baselinePlan)
	variantResponses := engine.Run(ctx, plan)

	// Group baseline responses by endpoint key.
	byEndpointKey := make(map[string][]*model.Response)
	for i, v := range baselinePlan.Variants {
		key := variantEndpointKey(&v)
		r := baselineResponses[i]
		byEndpointKey[key] = append(byEndpointKey[key], &r)
	}

	cals = make(map[string]CalibrationResult)
	verdictCounts = map[string]int{}

	ev := ComparativeEvaluator{}
	for _, ep := range endpoints {
		key := ep.Method + " " + ep.Host + ep.PathTemplate
		cal := Calibrate(byEndpointKey[key])
		cals[key] = cal
		if cal.Noisy {
			noisy++
		}
		var vrs []VariantResponse
		for i, v := range plan.Variants {
			if variantEndpointKey(&v) != key {
				continue
			}
			r := variantResponses[i]
			vrs = append(vrs, VariantResponse{Variant: &plan.Variants[i], Response: &r})
		}
		res := ev.Evaluate(EvalContext{
			Endpoint:         ep,
			Owner:            ep.OwnerIdentity,
			Calibration:      cal,
			VariantResponses: vrs,
			Matrix:           matrix,
		})
		for _, vv := range res.Verdicts {
			verdictCounts[vv.Verdict]++
		}
		allFindings = append(allFindings, res.Findings...)
	}
	return allFindings, cals, verdictCounts, noisy
}

type endpointDef struct {
	method       string
	path         string
	pathTemplate string
}

// buildBaselinePlanLocal mirrors cli.buildBaselinePlan but lives here
// (avoid importing the cli package from a test).
func buildBaselinePlanLocal(endpoints []*model.Endpoint, samples int) replay.Plan {
	plan := replay.Plan{}
	for _, ep := range endpoints {
		if ep == nil || len(ep.Samples) == 0 || ep.OwnerIdentity == nil {
			continue
		}
		best := ep.Samples[0]
		ownerCopy := *ep.OwnerIdentity
		for i := 0; i < samples; i++ {
			clone := mutate.CloneRequest(best)
			v := model.Variant{
				ID:       fmt.Sprintf("baseline-%s-%d-%s", ep.OwnerIdentity.Name, i, best.ID),
				Base:     clone,
				Identity: &ownerCopy,
				Mutation: model.Mutation{
					Type:        "baseline-self",
					Description: "owner self-replay baseline",
					Detail:      map[string]string{},
				},
			}
			plan.Variants = append(plan.Variants, v)
		}
	}
	plan.TotalBefore = len(plan.Variants)
	return plan
}

func variantEndpointKey(v *model.Variant) string {
	if v == nil || v.Base == nil || v.Base.URL == nil {
		return ""
	}
	host := v.Base.URL.Host
	tmpl := v.Base.PathTemplate
	if tmpl == "" {
		tmpl = v.Base.URL.Path
	}
	return v.Base.Method + " " + host + tmpl
}

// ─── Gate E tests ─────────────────────────────────────────────────────

// TestCorpus_VulnApp_PlantedBypassesDetected:
// The deliberately broken app must produce bypass findings on the
// planted-vulnerable endpoints. We assert presence of at least one
// bypass per planted vulnerability — not specific counts (mutator
// combinations may yield several variants).
func TestCorpus_VulnApp_PlantedBypassesDetected(t *testing.T) {
	srv := startVulnApp(t)
	defer srv.Close()

	defs := []endpointDef{
		{"GET", "/users/alice", "/users/{id}"},     // IDOR (planted)
		{"GET", "/profile", "/profile"},            // authn-bypass (planted)
		{"POST", "/admin/promote", "/admin/promote"}, // privesc (planted)
	}
	findings, _, verdictCounts, _ := runCorpus(t, srv, defs)

	wantClasses := map[string]bool{
		"idor":         false,
		"authn-bypass": false,
		"privesc":      false,
	}
	for _, f := range findings {
		if f.Verdict != VerdictBypass {
			continue
		}
		if _, ok := wantClasses[f.Class]; ok {
			wantClasses[f.Class] = true
		}
	}
	for cls, found := range wantClasses {
		if !found {
			t.Errorf("vulnapp: missing planted bypass for class %q; findings=%+v", cls, summarizeFindings(findings))
		}
	}
	t.Logf("vulnapp verdicts: %v (total findings=%d)", verdictCounts, len(findings))
}

// TestCorpus_SecureApp_ZeroBypass — Gate E.
// The secure app implements proper authz on the same routes. Any `bypass`
// verdict here is a false positive and represents a failure of the
// detection algorithm or its tuning. Per §9: DO NOT loosen this test.
// If it fails, report the design problem honestly.
func TestCorpus_SecureApp_ZeroBypass(t *testing.T) {
	srv := startSecureApp(t)
	defer srv.Close()

	defs := []endpointDef{
		{"GET", "/users/alice", "/users/{id}"},
		{"GET", "/profile", "/profile"},
		{"POST", "/admin/promote", "/admin/promote"},
	}
	findings, _, verdictCounts, _ := runCorpus(t, srv, defs)

	bypassCount := 0
	for _, f := range findings {
		if f.Verdict == VerdictBypass {
			bypassCount++
		}
	}
	if bypassCount > 0 {
		t.Errorf("secureapp Gate E FAILED: %d bypass false positive(s):\n%s",
			bypassCount, summarizeFindings(findings))
	}
	t.Logf("secureapp verdicts: %v (findings=%d, none bypass: %v)",
		verdictCounts, len(findings), bypassCount == 0)
}

// TestCorpus_NoisyEndpoint_FlaggedAndCapped:
// A noisy endpoint must be flagged `noisy` and must not produce
// `bypass` findings (caps to suspected at worst).
func TestCorpus_NoisyEndpoint_FlaggedAndCapped(t *testing.T) {
	srv := startVulnApp(t)
	defer srv.Close()

	defs := []endpointDef{
		{"GET", "/noisy", "/noisy"},
	}
	findings, cals, _, _ := runCorpus(t, srv, defs)

	cal, ok := cals["GET "+stripScheme(srv.URL)+"/noisy"]
	if !ok {
		// Endpoint key uses Host (no scheme).
		for k, c := range cals {
			t.Logf("calibration key=%q noisy=%v stability=%.2f", k, c.Noisy, c.Stability)
			if strings.HasSuffix(k, "/noisy") {
				cal, ok = c, true
				break
			}
		}
	}
	if !ok {
		t.Fatalf("no calibration result for noisy endpoint")
	}
	if !cal.Noisy {
		t.Errorf("noisy endpoint not flagged noisy (stability=%.2f, threshold=%.2f)",
			cal.Stability, NoisyEndpointThreshold)
	}
	for _, f := range findings {
		if f.Verdict == VerdictBypass {
			t.Errorf("noisy endpoint produced a bypass finding (should cap at suspected): %+v", f)
		}
	}
}

// TestCorpus_SoftDenyEndpoint_ErrorSignatureDowngrade:
// An endpoint that returns 200 + denial-shaped body must be downgraded
// to enforced via errorSignature on cross-identity replay.
func TestCorpus_SoftDenyEndpoint_ErrorSignatureDowngrade(t *testing.T) {
	srv := startVulnApp(t)
	defer srv.Close()

	defs := []endpointDef{
		{"GET", "/softdeny", "/softdeny"},
	}
	findings, _, verdictCounts, _ := runCorpus(t, srv, defs)

	for _, f := range findings {
		if f.Verdict == VerdictBypass {
			t.Errorf("softdeny endpoint produced a bypass finding "+
				"(errorSignature should have downgraded it to enforced): %+v", f)
		}
	}
	t.Logf("softdeny verdicts: %v", verdictCounts)
}

// summarizeFindings formats findings compactly for failure messages.
func summarizeFindings(fs []model.Finding) string {
	var b strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&b, "  [%s] %s/%s/%s conf=%.2f notes=%v\n",
			f.Verdict, f.EndpointKey, f.Mutation, f.Class, f.Confidence, f.Evidence.Notes)
	}
	return b.String()
}

func stripScheme(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	return u
}

// ─── JWT corpus helpers ───────────────────────────────────────────────

// vulnableJWTSub parses a JWT leniently and returns the `sub` claim
// without verifying the signature. This intentionally mirrors the
// classic "we forgot to verify" bug.
func vulnableJWTSub(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	cb, err := base64URLDecode(parts[1])
	if err != nil {
		return ""
	}
	var m map[string]any
	if err := jsonDecode(cb, &m); err != nil {
		return ""
	}
	if s, ok := m["sub"].(string); ok {
		return s
	}
	return ""
}

// secureJWTSecret is the HMAC secret the secureapp verifier expects.
// Mutators don't know it; jwt-resign-weak-key tries common defaults
// like "secret"/"password" — none of which match this value.
const secureJWTSecret = "S3cure-LongRandomServerSecret-NotInWeakHMACList-9f3b2c"

// secureJWTVerify validates the JWT's HS256 signature against
// secureJWTSecret AND requires alg=HS256 (rejects alg=none). Returns
// the sub claim on success.
func secureJWTVerify(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] == "" {
		return "", false
	}
	hb, err := base64URLDecode(parts[0])
	if err != nil {
		return "", false
	}
	var hdr map[string]any
	if err := jsonDecode(hb, &hdr); err != nil {
		return "", false
	}
	if alg, _ := hdr["alg"].(string); alg != "HS256" {
		return "", false
	}
	mac := hmacSHA256([]byte(secureJWTSecret), []byte(parts[0]+"."+parts[1]))
	got, err := base64URLDecode(parts[2])
	if err != nil || !hmacEqual(mac, got) {
		return "", false
	}
	cb, err := base64URLDecode(parts[1])
	if err != nil {
		return "", false
	}
	var claims map[string]any
	if err := jsonDecode(cb, &claims); err != nil {
		return "", false
	}
	if s, ok := claims["sub"].(string); ok {
		return s, true
	}
	return "", false
}

func base64URLDecode(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}

func jsonDecode(b []byte, dst *map[string]any) error {
	return json.Unmarshal(b, dst)
}

func hmacSHA256(key, msg []byte) []byte {
	var h hash.Hash = hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// ─── JWT corpus tests ─────────────────────────────────────────────────

// matrixForJWTServer builds a matrix where alice carries a real signed
// JWT as her bearer token. This makes jwt.Detect find a token on the
// captured request so the JWT mutators have something to chew on.
// bob/admin carry plain string tokens — they don't enable JWT detection
// on their own variants, but swap-identity variants still use them.
func matrixForJWTServer(base string) (*model.RoleMatrix, string) {
	aliceJWT := encodeHS256(map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "alice", "role": "user"}, secureJWTSecret)
	return &model.RoleMatrix{
		Version: "1",
		Target:  model.TargetConfig{BaseURL: base},
		Identities: []model.Identity{
			{Name: "anon", Role: "unauthenticated", Rank: 0},
			{Name: "alice", Role: "user", Rank: 10,
				Markers: []string{"alice@example.com", "Alice Liddell"},
				Creds:   &model.Credentials{Bearer: aliceJWT}},
		},
	}, aliceJWT
}

// encodeHS256 is the corpus-local convenience matching the secure
// verifier — keeps tests self-contained without importing the mutator
// package.
func encodeHS256(header, claims map[string]any, secret string) string {
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	eh := base64.RawURLEncoding.EncodeToString(hb)
	ec := base64.RawURLEncoding.EncodeToString(cb)
	sig := base64.RawURLEncoding.EncodeToString(hmacSHA256([]byte(secret), []byte(eh+"."+ec)))
	return eh + "." + ec + "." + sig
}

// runJWTCorpus mirrors runCorpus but uses matrixForJWTServer and
// fabricates the captured request with the alice JWT bearer.
func runJWTCorpus(t *testing.T, srv *httptest.Server) (allFindings []model.Finding, verdictCounts map[string]int) {
	matrix, aliceJWT := matrixForJWTServer(srv.URL)

	u, _ := url.Parse(srv.URL + "/jwt")
	h := http.Header{}
	h.Set("Authorization", "Bearer "+aliceJWT)
	h.Set("Accept", "application/json")
	cap := &model.CapturedRequest{
		ID: "GET /jwt", Method: "GET", URL: u, PathTemplate: "/jwt",
		Headers: h,
	}
	ep := &model.Endpoint{
		Method: "GET", Host: cap.URL.Host, PathTemplate: "/jwt",
		Samples: []*model.CapturedRequest{cap},
	}
	owner, attr, _ := AttributeOwner(ep.Samples[0], matrix)
	ep.OwnerIdentity = owner
	ep.OwnerAttribution = attr

	const baselineN = 3
	baselinePlan := buildBaselinePlanLocal([]*model.Endpoint{ep}, baselineN)
	reg := mutate.DefaultRegistry()
	plan := replay.Generate([]*model.Endpoint{ep}, matrix, reg, 0)
	rs := model.RunSettings{RatePerHost: 1000, Concurrency: 8, MaxBody: 1024 * 1024}
	engine := replay.New(rs, "possession-jwt-corpus-test", nil)
	ctx := t.Context()
	baselineResp := engine.Run(ctx, baselinePlan)
	variantResp := engine.Run(ctx, plan)

	byKey := map[string][]*model.Response{}
	for i, v := range baselinePlan.Variants {
		key := variantEndpointKey(&v)
		r := baselineResp[i]
		byKey[key] = append(byKey[key], &r)
	}
	cal := Calibrate(byKey[ep.Method+" "+ep.Host+ep.PathTemplate])
	var vrs []VariantResponse
	for i, v := range plan.Variants {
		if variantEndpointKey(&v) != ep.Method+" "+ep.Host+ep.PathTemplate {
			continue
		}
		r := variantResp[i]
		vrs = append(vrs, VariantResponse{Variant: &plan.Variants[i], Response: &r})
	}
	verdictCounts = map[string]int{}
	res := ComparativeEvaluator{}.Evaluate(EvalContext{
		Endpoint: ep, Owner: ep.OwnerIdentity, Calibration: cal,
		VariantResponses: vrs, Matrix: matrix,
	})
	for _, vv := range res.Verdicts {
		verdictCounts[vv.Verdict]++
	}
	return res.Findings, verdictCounts
}

// TestCorpus_VulnApp_JWT_AlgNoneBypass: the vulnapp /jwt accepts
// alg=none. We expect AT LEAST one bypass finding from the JWT mutators
// (alg-none or sig-strip will get through, return alice's data,
// reflectedOwner triggers).
func TestCorpus_VulnApp_JWT_AlgNoneBypass(t *testing.T) {
	srv := startVulnApp(t)
	defer srv.Close()
	findings, verdictCounts := runJWTCorpus(t, srv)
	jwtBypass := 0
	for _, f := range findings {
		if f.Verdict != VerdictBypass {
			continue
		}
		if strings.HasPrefix(f.Mutation, "jwt-") {
			jwtBypass++
		}
	}
	if jwtBypass == 0 {
		t.Errorf("vulnapp /jwt: expected at least one JWT-mutator bypass; got verdictCounts=%v findings:\n%s",
			verdictCounts, summarizeFindings(findings))
	}
	t.Logf("vulnapp /jwt: %d JWT-mutator bypasses, verdictCounts=%v", jwtBypass, verdictCounts)
}

// TestCorpus_SecureApp_JWT_ZeroBypass — Gate E for the JWT endpoint.
// The secure /jwt rejects alg=none and verifies HS256 with a strong
// secret. No JWT mutator should yield a bypass.
func TestCorpus_SecureApp_JWT_ZeroBypass(t *testing.T) {
	srv := startSecureApp(t)
	defer srv.Close()
	findings, verdictCounts := runJWTCorpus(t, srv)
	bypassCount := 0
	for _, f := range findings {
		if f.Verdict == VerdictBypass {
			bypassCount++
		}
	}
	if bypassCount > 0 {
		t.Errorf("secureapp /jwt Gate E FAILED: %d bypass(es):\n%s",
			bypassCount, summarizeFindings(findings))
	}
	t.Logf("secureapp /jwt: zero bypass; verdictCounts=%v findings=%d", verdictCounts, len(findings))
}

// ─── P5: Deep JWT corpus helpers ──────────────────────────────────────

// startVulnAppDeepJWT extends the vulnapp with endpoints for P5 deep JWT attacks.
// /jwt/deep — accepts any JWT without signature verification (covers alg-confusion,
//             kid-injection, jwks-spoof).
// /jwt/hmac-weak — HS256 endpoint using the WEAK secret "secret"; role-aware
//                  so the cracked admin token yields different output than the
//                  owner user token, making privesc detectable.
func startVulnAppDeepJWT(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()

	// /jwt/deep: no signature check — accepts any structurally valid JWT.
	// Returns alice's data when sub=alice, else 404.
	users := map[string]string{
		"alice": `{"id":"alice","email":"alice@example.com","name":"Alice Liddell","balance":1234}`,
		"bob":   `{"id":"bob","email":"bob@example.com","name":"Bob Roberts","balance":99}`,
	}
	mux.HandleFunc("/jwt/deep", func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		sub := vulnableJWTSub(bearer) // no sig check
		if sub == "" {
			writeJSON(w, 401, `{"error":"missing jwt"}`)
			return
		}
		body, ok := users[sub]
		if !ok {
			body = `{"id":"` + sub + `","email":"` + sub + `@example.com","name":"` + sub + `","balance":0}`
		}
		writeJSON(w, 200, body)
	})

	// /jwt/hmac-weak: verifies HS256 with weak secret "secret" (in crack wordlist).
	// Returns alice's profile data for any valid token (sub-based), ignoring role.
	// The bypass is that the cracked+tampered token is ACCEPTED (high body similarity
	// to baseline triggers comparative bypass detection).
	const weakSecret = "secret"
	mux.HandleFunc("/jwt/hmac-weak", func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer == "" {
			writeJSON(w, 401, `{"error":"missing jwt"}`)
			return
		}
		parts := strings.SplitN(bearer, ".", 3)
		if len(parts) != 3 {
			writeJSON(w, 401, `{"error":"malformed jwt"}`)
			return
		}
		hb, err := base64URLDecode(parts[0])
		if err != nil {
			writeJSON(w, 401, `{"error":"bad jwt header"}`)
			return
		}
		var hdr map[string]any
		if err := jsonDecode(hb, &hdr); err != nil || hdr["alg"] != "HS256" {
			writeJSON(w, 401, `{"error":"bad alg"}`)
			return
		}
		mac := hmacSHA256([]byte(weakSecret), []byte(parts[0]+"."+parts[1]))
		got, err := base64URLDecode(parts[2])
		if err != nil || !hmacEqual(mac, got) {
			writeJSON(w, 401, `{"error":"bad signature"}`)
			return
		}
		// Accept any valid token; return the sub's user data.
		cb, _ := base64URLDecode(parts[1])
		var claims map[string]any
		_ = jsonDecode(cb, &claims)
		sub, _ := claims["sub"].(string)
		body, ok := users[sub]
		if !ok {
			body = `{"id":"` + sub + `","email":"` + sub + `@example.com","balance":0}`
		}
		writeJSON(w, 200, body)
	})

	return httptest.NewServer(mux)
}

// startSecureAppDeepJWT mirrors startVulnAppDeepJWT but with proper verification.
// /jwt/deep — verifies HS256 with secureJWTSecret; rejects alg=RS256 (so jwks-spoof
//             fails), ignores kid and jwk/jku headers (kid-injection and alg-confusion
//             are defeated by the correct sig check).
// /jwt/hmac-weak — verifies HS256 with secureJWTSecret (NOT in the crack wordlist).
func startSecureAppDeepJWT(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	users := map[string]string{
		"alice": `{"id":"alice","email":"alice@example.com","name":"Alice Liddell","balance":1234}`,
		"bob":   `{"id":"bob","email":"bob@example.com","name":"Bob Roberts","balance":99}`,
	}

	mux.HandleFunc("/jwt/deep", func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		sub, ok := secureJWTVerify(bearer)
		if !ok {
			writeJSON(w, 401, `{"error":"invalid jwt"}`)
			return
		}
		body, found := users[sub]
		if !found {
			writeJSON(w, 404, `{"error":"not found"}`)
			return
		}
		writeJSON(w, 200, body)
	})

	mux.HandleFunc("/jwt/hmac-weak", func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		sub, ok := secureJWTVerify(bearer) // strong secret — crack wordlist won't match
		if !ok {
			writeJSON(w, 401, `{"error":"invalid jwt"}`)
			return
		}
		body, found := users[sub]
		if !found {
			writeJSON(w, 404, `{"error":"not found"}`)
			return
		}
		writeJSON(w, 200, body)
	})

	return httptest.NewServer(mux)
}

// matrixForDeepJWT builds a matrix where alice carries an HS256 JWT (suitable for
// alg-confusion / kid-injection / jwks-spoof corpus tests) AND the target has a
// public_key_pem so jwt-alg-confusion generates variants.
// Returns the matrix and alice's bearer token.
func matrixForDeepJWT(base string, pubKeyPEM string) (*model.RoleMatrix, string) {
	aliceJWT := encodeHS256(
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "alice", "role": "user"},
		secureJWTSecret,
	)
	var jwtCfg *model.JWTTargetConfig
	if pubKeyPEM != "" {
		jwtCfg = &model.JWTTargetConfig{PublicKeyPEM: pubKeyPEM}
	}
	return &model.RoleMatrix{
		Version: "1",
		Target:  model.TargetConfig{BaseURL: base, JWT: jwtCfg},
		Identities: []model.Identity{
			{Name: "anon", Role: "unauthenticated", Rank: 0},
			{Name: "alice", Role: "user", Rank: 10,
				Markers: []string{"alice@example.com", "Alice Liddell"},
				Creds:   &model.Credentials{Bearer: aliceJWT}},
		},
	}, aliceJWT
}

// matrixForHMACCrack builds a matrix where alice carries an HS256 JWT signed
// with the weak secret "secret" (in the crack wordlist). No public key needed.
func matrixForHMACCrack(base string) (*model.RoleMatrix, string) {
	const weakSecret = "secret"
	aliceJWT := encodeHS256(
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "alice", "role": "user"},
		weakSecret,
	)
	return &model.RoleMatrix{
		Version: "1",
		Target:  model.TargetConfig{BaseURL: base},
		Identities: []model.Identity{
			{Name: "anon", Role: "unauthenticated", Rank: 0},
			{Name: "alice", Role: "user", Rank: 10,
				Markers: []string{"alice@example.com"},
				Creds:   &model.Credentials{Bearer: aliceJWT}},
		},
	}, aliceJWT
}

// runDeepJWTCorpus runs the P5 deep JWT pipeline against srv on pathTemplate/path.
// matrix is caller-supplied (so pubkey / weak-secret tests can share this).
func runDeepJWTCorpus(t *testing.T, srv *httptest.Server, matrix *model.RoleMatrix, path, pathTemplate string) ([]model.Finding, map[string]int) {
	t.Helper()
	aliceBearerTok := ""
	for _, id := range matrix.Identities {
		if id.Name == "alice" && id.Creds != nil {
			aliceBearerTok = id.Creds.Bearer
		}
	}

	u, _ := url.Parse(srv.URL + path)
	h := http.Header{}
	h.Set("Authorization", "Bearer "+aliceBearerTok)
	h.Set("Accept", "application/json")
	cap := &model.CapturedRequest{
		ID: "GET " + path, Method: "GET", URL: u, PathTemplate: pathTemplate,
		Headers: h,
	}
	ep := &model.Endpoint{
		Method: "GET", Host: cap.URL.Host, PathTemplate: pathTemplate,
		Samples: []*model.CapturedRequest{cap},
	}
	owner, attr, _ := AttributeOwner(ep.Samples[0], matrix)
	ep.OwnerIdentity = owner
	ep.OwnerAttribution = attr

	const baselineN = 3
	baselinePlan := buildBaselinePlanLocal([]*model.Endpoint{ep}, baselineN)
	reg := mutate.DefaultRegistry()
	plan := replay.Generate([]*model.Endpoint{ep}, matrix, reg, 0)

	rs := model.RunSettings{RatePerHost: 1000, Concurrency: 8, MaxBody: 1024 * 1024}
	engine := replay.New(rs, "possession-deep-jwt-test", nil)
	ctx := t.Context()
	baselineResp := engine.Run(ctx, baselinePlan)
	variantResp := engine.Run(ctx, plan)

	byKey := map[string][]*model.Response{}
	epKey := ep.Method + " " + ep.Host + ep.PathTemplate
	for i, v := range baselinePlan.Variants {
		key := variantEndpointKey(&v)
		r := baselineResp[i]
		byKey[key] = append(byKey[key], &r)
	}
	cal := Calibrate(byKey[epKey])
	var vrs []VariantResponse
	for i, v := range plan.Variants {
		if variantEndpointKey(&v) != epKey {
			continue
		}
		r := variantResp[i]
		vrs = append(vrs, VariantResponse{Variant: &plan.Variants[i], Response: &r})
	}
	verdictCounts := map[string]int{}
	res := ComparativeEvaluator{}.Evaluate(EvalContext{
		Endpoint: ep, Owner: ep.OwnerIdentity, Calibration: cal,
		VariantResponses: vrs, Matrix: matrix,
	})
	for _, vv := range res.Verdicts {
		verdictCounts[vv.Verdict]++
	}
	return res.Findings, verdictCounts
}

// ─── P5 Tests ──────────────────────────────────────────────────────────

// TestCorpus_VulnApp_P5_DeepJWTBypass: jwt-alg-confusion, jwt-kid-injection,
// and jwt-jwks-spoof should all generate variants that bypass vulnapp /jwt/deep
// (which accepts any JWT without verification).
func TestCorpus_VulnApp_P5_DeepJWTBypass(t *testing.T) {
	// Generate ephemeral RSA key pair for alg-confusion test.
	privKey, pubKey, err := jwthelper.GenerateAttackerKeyPair()
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	_ = privKey
	pubPEM, err := jwthelper.EncodePKIX(pubKey)
	if err != nil {
		t.Fatalf("encode pubkey pem: %v", err)
	}

	srv := startVulnAppDeepJWT(t)
	defer srv.Close()

	matrix, _ := matrixForDeepJWT(srv.URL, pubPEM)
	findings, verdictCounts := runDeepJWTCorpus(t, srv, matrix, "/jwt/deep", "/jwt/deep")

	wantMutators := map[string]bool{
		"jwt-alg-confusion": false,
		"jwt-kid-injection": false,
		"jwt-jwks-spoof":    false,
	}
	for _, f := range findings {
		if f.Verdict != VerdictBypass {
			continue
		}
		if _, ok := wantMutators[f.Mutation]; ok {
			wantMutators[f.Mutation] = true
		}
	}
	for mut, found := range wantMutators {
		if !found {
			t.Errorf("vulnapp /jwt/deep: missing bypass from %q; verdictCounts=%v findings:\n%s",
				mut, verdictCounts, summarizeFindings(findings))
		}
	}
	t.Logf("vulnapp /jwt/deep P5 bypasses: %v verdictCounts=%v", wantMutators, verdictCounts)
}

// TestCorpus_SecureApp_P5_ZeroBypass — Gate E for P5 deep JWT attacks.
// secureapp /jwt/deep rejects alg-confusion (wrong HMAC secret), kid-injection
// (empty sig rejected), and jwks-spoof (alg=RS256 rejected vs HS256 expected).
func TestCorpus_SecureApp_P5_ZeroBypass(t *testing.T) {
	_, pubKey, err := jwthelper.GenerateAttackerKeyPair()
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	pubPEM, err := jwthelper.EncodePKIX(pubKey)
	if err != nil {
		t.Fatalf("encode pubkey pem: %v", err)
	}

	srv := startSecureAppDeepJWT(t)
	defer srv.Close()

	matrix, _ := matrixForDeepJWT(srv.URL, pubPEM)
	findings, verdictCounts := runDeepJWTCorpus(t, srv, matrix, "/jwt/deep", "/jwt/deep")

	bypassCount := 0
	for _, f := range findings {
		if f.Verdict == VerdictBypass {
			bypassCount++
		}
	}
	if bypassCount > 0 {
		t.Errorf("secureapp /jwt/deep Gate E FAILED: %d bypass(es):\n%s",
			bypassCount, summarizeFindings(findings))
	}
	t.Logf("secureapp /jwt/deep P5: zero bypass; verdictCounts=%v findings=%d", verdictCounts, len(findings))
}

// TestCorpus_VulnApp_P5_HMACCrack: jwt-hmac-crack recovers the weak secret and
// re-signs a role=admin token; vulnapp returns admin data → privesc finding.
func TestCorpus_VulnApp_P5_HMACCrack(t *testing.T) {
	srv := startVulnAppDeepJWT(t)
	defer srv.Close()

	matrix, _ := matrixForHMACCrack(srv.URL)
	findings, verdictCounts := runDeepJWTCorpus(t, srv, matrix, "/jwt/hmac-weak", "/jwt/hmac-weak")

	found := false
	for _, f := range findings {
		if f.Mutation == "jwt-hmac-crack" && (f.Verdict == VerdictBypass || f.Verdict == VerdictSuspected) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("vulnapp /jwt/hmac-weak: expected bypass/suspected from jwt-hmac-crack; verdictCounts=%v findings:\n%s",
			verdictCounts, summarizeFindings(findings))
	}
	t.Logf("vulnapp /jwt/hmac-weak: hmac-crack result: found=%v verdictCounts=%v", found, verdictCounts)
}

// TestCorpus_SecureApp_P5_HMACCrack_ZeroBypass — Gate E for hmac-crack.
// secureapp /jwt/hmac-weak uses secureJWTSecret (not in wordlist), so no crack.
func TestCorpus_SecureApp_P5_HMACCrack_ZeroBypass(t *testing.T) {
	srv := startSecureAppDeepJWT(t)
	defer srv.Close()

	// Alice's JWT is signed with secureJWTSecret (strong, not in wordlist).
	// matrixForHMACCrack uses "secret" as alice's token secret — secureapp will reject it.
	// But actually we want secureapp to accept alice's valid token for baseline, then reject
	// the cracked variants. Let's use a matrix where alice's token is signed with secureJWTSecret
	// so baseline succeeds, but the crack fails (secureJWTSecret not in wordlist).
	aliceJWT := encodeHS256(
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "alice", "role": "user"},
		secureJWTSecret,
	)
	matrix := &model.RoleMatrix{
		Version: "1",
		Target:  model.TargetConfig{BaseURL: srv.URL},
		Identities: []model.Identity{
			{Name: "anon", Role: "unauthenticated", Rank: 0},
			{Name: "alice", Role: "user", Rank: 10,
				Markers: []string{"alice@example.com"},
				Creds:   &model.Credentials{Bearer: aliceJWT}},
		},
	}
	findings, verdictCounts := runDeepJWTCorpus(t, srv, matrix, "/jwt/hmac-weak", "/jwt/hmac-weak")

	bypassCount := 0
	for _, f := range findings {
		if f.Verdict == VerdictBypass {
			bypassCount++
		}
	}
	if bypassCount > 0 {
		t.Errorf("secureapp /jwt/hmac-weak Gate E FAILED: %d bypass(es):\n%s",
			bypassCount, summarizeFindings(findings))
	}
	t.Logf("secureapp /jwt/hmac-weak: zero bypass; verdictCounts=%v findings=%d", verdictCounts, len(findings))
}

// ─── P6: Assertion Evaluator corpus tests ─────────────────────────────

// runAssertionCorpus runs the assertion evaluator (or "both") against srv.
// assertions is embedded in the matrix for the test.
func runAssertionCorpus(t *testing.T, srv *httptest.Server, evalName string, defs []endpointDef, assertions []model.Assertion) ([]model.Finding, map[string]int) {
	t.Helper()
	matrix := matrixForServer(srv.URL)
	matrix.Assertions = assertions

	var endpoints []*model.Endpoint
	for _, d := range defs {
		cap := makeCaptured(d.method, srv.URL, d.path, d.pathTemplate)
		ep := &model.Endpoint{
			Method:       d.method,
			Host:         cap.URL.Host,
			PathTemplate: d.pathTemplate,
			Samples:      []*model.CapturedRequest{cap},
		}
		endpoints = append(endpoints, ep)
	}
	for _, ep := range endpoints {
		owner, attr, _ := AttributeOwner(ep.Samples[0], matrix)
		ep.OwnerIdentity = owner
		ep.OwnerAttribution = attr
	}

	const baselineN = 3
	baselinePlan := buildBaselinePlanLocal(endpoints, baselineN)
	reg := mutate.DefaultRegistry()
	plan := replay.Generate(endpoints, matrix, reg, 0)
	rs := model.RunSettings{RatePerHost: 1000, Concurrency: 8, MaxBody: 1024 * 1024}
	engine := replay.New(rs, "possession-assertion-corpus-test", nil)
	ctx := t.Context()
	baselineResp := engine.Run(ctx, baselinePlan)
	variantResp := engine.Run(ctx, plan)

	byKey := make(map[string][]*model.Response)
	for i, v := range baselinePlan.Variants {
		key := variantEndpointKey(&v)
		r := baselineResp[i]
		byKey[key] = append(byKey[key], &r)
	}

	var ev Evaluator
	switch evalName {
	case "assertion":
		ev = AssertionEvaluator{}
	case "both":
		ev = BothEvaluator{}
	default:
		ev = ComparativeEvaluator{}
	}

	verdictCounts := map[string]int{}
	var allFindings []model.Finding
	for _, ep := range endpoints {
		key := ep.Method + " " + ep.Host + ep.PathTemplate
		cal := Calibrate(byKey[key])
		var vrs []VariantResponse
		for i, v := range plan.Variants {
			if variantEndpointKey(&v) != key {
				continue
			}
			r := variantResp[i]
			vrs = append(vrs, VariantResponse{Variant: &plan.Variants[i], Response: &r})
		}
		res := ev.Evaluate(EvalContext{
			Endpoint:         ep,
			Owner:            ep.OwnerIdentity,
			Calibration:      cal,
			VariantResponses: vrs,
			Matrix:           matrix,
		})
		for _, vv := range res.Verdicts {
			verdictCounts[vv.Verdict]++
		}
		allFindings = append(allFindings, res.Findings...)
	}
	return allFindings, verdictCounts
}

// TestCorpus_P6_AssertionEvaluator_VulnApp_CatchesDenyViolation:
// /admin/promote is deny for user/unauthenticated; vulnapp returns 200 for
// everyone → assertion evaluator should flag it as bypass.
func TestCorpus_P6_AssertionEvaluator_VulnApp_CatchesDenyViolation(t *testing.T) {
	srv := startVulnApp(t)
	defer srv.Close()

	assertions := []model.Assertion{
		{Endpoint: "POST /admin/promote", Expect: map[string]string{
			"user":            "deny",
			"unauthenticated": "deny",
		}},
	}
	defs := []endpointDef{
		{"POST", "/admin/promote", "/admin/promote"},
	}
	findings, verdictCounts := runAssertionCorpus(t, srv, "assertion", defs, assertions)

	bypassFound := false
	for _, f := range findings {
		if f.Verdict == VerdictBypass {
			bypassFound = true
			break
		}
	}
	if !bypassFound {
		t.Errorf("P6 assertion: expected bypass on vulnapp /admin/promote; verdictCounts=%v findings:\n%s",
			verdictCounts, summarizeFindings(findings))
	}
	t.Logf("P6 assertion vulnapp: verdictCounts=%v findings=%d", verdictCounts, len(findings))
}

// TestCorpus_P6_AssertionEvaluator_SecureApp_ZeroBypass — Gate E for P6.
// secureapp /admin/promote is properly restricted; no bypass findings expected.
func TestCorpus_P6_AssertionEvaluator_SecureApp_ZeroBypass(t *testing.T) {
	srv := startSecureApp(t)
	defer srv.Close()

	assertions := []model.Assertion{
		{Endpoint: "POST /admin/promote", Expect: map[string]string{
			"user":            "deny",
			"unauthenticated": "deny",
			"administrator":   "allow",
		}},
	}
	defs := []endpointDef{
		{"POST", "/admin/promote", "/admin/promote"},
	}
	findings, verdictCounts := runAssertionCorpus(t, srv, "assertion", defs, assertions)

	bypassCount := 0
	for _, f := range findings {
		if f.Verdict == VerdictBypass {
			bypassCount++
		}
	}
	if bypassCount > 0 {
		t.Errorf("P6 Gate E FAILED: %d bypass(es):\n%s", bypassCount, summarizeFindings(findings))
	}
	t.Logf("P6 assertion secureapp: zero bypass; verdictCounts=%v findings=%d", verdictCounts, len(findings))
}

// ─── P7: Stateful Flow corpus tests ───────────────────────────────────

// startVulnAppWithFlows extends startVulnApp with:
//   - POST /login — returns session cookie and csrf token
//   - DELETE /orders/{id} — CSRF-protected write; IDOR: any session can delete any order
func startVulnAppWithFlows(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()

	orders := map[string]string{
		"order-alice": `{"id":"order-alice","owner":"alice","total":99}`,
		"order-bob":   `{"id":"order-bob","owner":"bob","total":42}`,
	}
	// Shared CSRF map: session → csrf token (simple, single-user)
	csrfTokens := map[string]string{
		"alice-session": "csrf-alice-123",
		"bob-session":   "csrf-bob-456",
	}

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		user, _ := body["user"].(string)
		sessionName := user + "-session"
		http.SetCookie(w, &http.Cookie{Name: "session", Value: sessionName})
		writeJSON(w, 200, `{"status":"ok","csrf_token":"`+csrfTokens[sessionName]+`"}`)
	})

	// DELETE /orders/{id}: vulnerable — doesn't check session owner vs order owner.
	// Just checks session is valid and CSRF token matches.
	mux.HandleFunc("/orders/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/orders/")
		// Read session cookie.
		var sessionCookie string
		for _, c := range r.Cookies() {
			if c.Name == "session" {
				sessionCookie = c.Value
			}
		}
		if sessionCookie == "" {
			writeJSON(w, 401, `{"error":"no session"}`)
			return
		}
		// Check CSRF.
		csrfHeader := r.Header.Get("X-CSRF-Token")
		expected, ok := csrfTokens[sessionCookie]
		if !ok || csrfHeader != expected {
			writeJSON(w, 403, `{"error":"bad csrf"}`)
			return
		}
		order, ok := orders[id]
		if !ok {
			writeJSON(w, 404, `{"error":"not found"}`)
			return
		}
		// IDOR: returns/deletes regardless of who owns it.
		if r.Method == http.MethodDelete {
			writeJSON(w, 200, `{"deleted":true,"order":`+order+`}`)
		} else {
			writeJSON(w, 200, order)
		}
	})

	return httptest.NewServer(mux)
}

// startSecureAppWithFlows mirrors vulnapp but properly checks order ownership.
func startSecureAppWithFlows(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()

	orders := map[string]string{
		"order-alice": `{"id":"order-alice","owner":"alice","total":99}`,
		"order-bob":   `{"id":"order-bob","owner":"bob","total":42}`,
	}
	orderOwners := map[string]string{
		"order-alice": "alice",
		"order-bob":   "bob",
	}
	csrfTokens := map[string]string{
		"alice-session": "csrf-alice-sec",
		"bob-session":   "csrf-bob-sec",
	}
	sessionUsers := map[string]string{
		"alice-session": "alice",
		"bob-session":   "bob",
	}

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		user, _ := body["user"].(string)
		sessionName := user + "-session"
		http.SetCookie(w, &http.Cookie{Name: "session", Value: sessionName})
		writeJSON(w, 200, `{"status":"ok","csrf_token":"`+csrfTokens[sessionName]+`"}`)
	})

	mux.HandleFunc("/orders/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/orders/")
		var sessionCookie string
		for _, c := range r.Cookies() {
			if c.Name == "session" {
				sessionCookie = c.Value
			}
		}
		if sessionCookie == "" {
			writeJSON(w, 401, `{"error":"no session"}`)
			return
		}
		csrfHeader := r.Header.Get("X-CSRF-Token")
		expected, ok := csrfTokens[sessionCookie]
		if !ok || csrfHeader != expected {
			writeJSON(w, 403, `{"error":"bad csrf"}`)
			return
		}
		caller := sessionUsers[sessionCookie]
		owner := orderOwners[id]
		if owner == "" {
			writeJSON(w, 404, `{"error":"not found"}`)
			return
		}
		if caller != owner {
			writeJSON(w, 403, `{"error":"forbidden"}`)
			return
		}
		order := orders[id]
		if r.Method == http.MethodDelete {
			writeJSON(w, 200, `{"deleted":true,"order":`+order+`}`)
		} else {
			writeJSON(w, 200, order)
		}
	})

	return httptest.NewServer(mux)
}

// runFlowCorpus runs the full P7 pipeline with a stateful flow for alice.
func runFlowCorpus(t *testing.T, srv *httptest.Server, endpointDefs []endpointDef) ([]model.Finding, map[string]int) {
	t.Helper()
	// Build a matrix with a login flow for alice.
	aliceFlow := model.FlowDef{
		Name: "alice-login",
		Steps: []model.FlowStep{
			{
				Name: "login",
				Request: &model.RawRequest{
					Method: "POST",
					URL:    srv.URL + "/login",
					Body:   `{"user":"alice","pass":"alice-pass"}`,
				},
				Extract: []model.FlowExtraction{
					{Name: "session", From: "cookie", Expr: "session",
						Inject: model.Injection{Into: "cookie", Key: "session"}},
					{Name: "csrf_token", From: "body-json", Expr: "$.csrf_token", Volatile: true,
						Inject: model.Injection{Into: "header", Key: "X-CSRF-Token"}},
				},
			},
		},
	}
	bobFlow := model.FlowDef{
		Name: "bob-login",
		Steps: []model.FlowStep{
			{
				Name: "login",
				Request: &model.RawRequest{
					Method: "POST",
					URL:    srv.URL + "/login",
					Body:   `{"user":"bob","pass":"bob-pass"}`,
				},
				Extract: []model.FlowExtraction{
					{Name: "session", From: "cookie", Expr: "session",
						Inject: model.Injection{Into: "cookie", Key: "session"}},
					{Name: "csrf_token", From: "body-json", Expr: "$.csrf_token", Volatile: true,
						Inject: model.Injection{Into: "header", Key: "X-CSRF-Token"}},
				},
			},
		},
	}

	matrix := &model.RoleMatrix{
		Version: "1",
		Target:  model.TargetConfig{BaseURL: srv.URL},
		Flows:   map[string]model.FlowDef{"alice-login": aliceFlow, "bob-login": bobFlow},
		Identities: []model.Identity{
			{Name: "anon", Role: "unauthenticated", Rank: 0},
			{Name: "alice", Role: "user", Rank: 10,
				Markers:  []string{"alice", "order-alice"},
				FlowName: "alice-login"},
			{Name: "bob", Role: "user", Rank: 10,
				Markers:  []string{"bob", "order-bob"},
				FlowName: "bob-login"},
		},
	}

	var endpoints []*model.Endpoint
	for _, d := range endpointDefs {
		u, _ := url.Parse(srv.URL + d.path)
		h := http.Header{}
		// Alice's captured request — no static bearer (flow provides session).
		cap := &model.CapturedRequest{
			ID: d.method + " " + d.path, Method: d.method, URL: u,
			PathTemplate: d.pathTemplate, Headers: h,
		}
		ep := &model.Endpoint{
			Method: d.method, Host: u.Host, PathTemplate: d.pathTemplate,
			Samples: []*model.CapturedRequest{cap},
		}
		endpoints = append(endpoints, ep)
	}
	for _, ep := range endpoints {
		owner, attr, _ := AttributeOwner(ep.Samples[0], matrix)
		ep.OwnerIdentity = owner
		ep.OwnerAttribution = attr
	}

	rs := model.RunSettings{RatePerHost: 1000, Concurrency: 4, MaxBody: 1024 * 1024}
	engine := replay.New(rs, "possession-flow-corpus-test", nil)
	ctx := t.Context()
	engine.PrepareFlows(ctx, matrix)

	const baselineN = 3
	baselinePlan := buildBaselinePlanLocal(endpoints, baselineN)
	reg := mutate.DefaultRegistry()
	plan := replay.Generate(endpoints, matrix, reg, 0)

	baselineResp := engine.Run(ctx, baselinePlan)
	variantResp := engine.Run(ctx, plan)

	byKey := make(map[string][]*model.Response)
	for i, v := range baselinePlan.Variants {
		key := variantEndpointKey(&v)
		r := baselineResp[i]
		byKey[key] = append(byKey[key], &r)
	}

	verdictCounts := map[string]int{}
	var allFindings []model.Finding
	ev := ComparativeEvaluator{}
	for _, ep := range endpoints {
		key := ep.Method + " " + ep.Host + ep.PathTemplate
		cal := Calibrate(byKey[key])
		var vrs []VariantResponse
		for i, v := range plan.Variants {
			if variantEndpointKey(&v) != key {
				continue
			}
			r := variantResp[i]
			vrs = append(vrs, VariantResponse{Variant: &plan.Variants[i], Response: &r})
		}
		res := ev.Evaluate(EvalContext{
			Endpoint: ep, Owner: ep.OwnerIdentity, Calibration: cal,
			VariantResponses: vrs, Matrix: matrix,
		})
		for _, vv := range res.Verdicts {
			verdictCounts[vv.Verdict]++
		}
		allFindings = append(allFindings, res.Findings...)
	}
	return allFindings, verdictCounts
}

// TestCorpus_P7_VulnApp_WriteEndpointIDOR: DELETE /orders/order-alice is
// accessible by bob's session → IDOR on a write endpoint.
func TestCorpus_P7_VulnApp_WriteEndpointIDOR(t *testing.T) {
	srv := startVulnAppWithFlows(t)
	defer srv.Close()

	defs := []endpointDef{
		{"DELETE", "/orders/order-alice", "/orders/{id}"},
	}
	findings, verdictCounts := runFlowCorpus(t, srv, defs)

	bypassFound := false
	for _, f := range findings {
		if f.Verdict == VerdictBypass || f.Verdict == VerdictSuspected {
			bypassFound = true
			break
		}
	}
	if !bypassFound {
		t.Errorf("P7: expected bypass/suspected on vulnapp DELETE /orders/{id}; verdictCounts=%v findings:\n%s",
			verdictCounts, summarizeFindings(findings))
	}
	t.Logf("P7 flow vulnapp: verdictCounts=%v findings=%d", verdictCounts, len(findings))
}

// TestCorpus_P7_SecureApp_ZeroBypass — Gate E for P7.
// secureapp properly checks ownership; bob cannot delete alice's orders.
func TestCorpus_P7_SecureApp_ZeroBypass(t *testing.T) {
	srv := startSecureAppWithFlows(t)
	defer srv.Close()

	defs := []endpointDef{
		{"DELETE", "/orders/order-alice", "/orders/{id}"},
	}
	findings, verdictCounts := runFlowCorpus(t, srv, defs)

	bypassCount := 0
	for _, f := range findings {
		if f.Verdict == VerdictBypass {
			bypassCount++
		}
	}
	if bypassCount > 0 {
		t.Errorf("P7 Gate E FAILED: %d bypass(es):\n%s", bypassCount, summarizeFindings(findings))
	}
	t.Logf("P7 flow secureapp: zero bypass; verdictCounts=%v findings=%d", verdictCounts, len(findings))
}

// ─── P8: Tenant Awareness corpus tests ────────────────────────────────

// startVulnAppMultiTenant serves a multi-tenant endpoint that leaks across
// tenant boundaries: GET /tenants/acme/config returns the acme config regardless
// of which tenant the authenticated caller belongs to.
func startVulnAppMultiTenant(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	configs := map[string]string{
		"acme":   `{"tenant":"acme","secret":"ACME_SECRET_DATA_9f3b","plan":"enterprise"}`,
		"globex": `{"tenant":"globex","secret":"GLOBEX_SECRET_DATA_a7c2","plan":"starter"}`,
	}
	validTokens := map[string]bool{"acme-tok": true, "globex-tok": true}
	mux.HandleFunc("/tenants/", func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !validTokens[bearer] {
			writeJSON(w, 401, `{"error":"unauthenticated"}`)
			return
		}
		// Extract tenant from path: /tenants/{tenant}/config
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/tenants/"), "/")
		tenantID := parts[0]
		data, ok := configs[tenantID]
		if !ok {
			writeJSON(w, 404, `{"error":"not found"}`)
			return
		}
		// IDOR: returns the requested tenant's data regardless of caller's tenant.
		writeJSON(w, 200, data)
	})
	return httptest.NewServer(mux)
}

// startSecureAppMultiTenant properly isolates tenants.
func startSecureAppMultiTenant(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	tokenTenants := map[string]string{
		"acme-tok":   "acme",
		"globex-tok": "globex",
	}
	tenantConfigs := map[string]string{
		"acme":   `{"tenant":"acme","secret":"ACME_SECRET_DATA_9f3b","plan":"enterprise"}`,
		"globex": `{"tenant":"globex","secret":"GLOBEX_SECRET_DATA_a7c2","plan":"starter"}`,
	}
	mux.HandleFunc("/tenants/", func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		callerTenant, ok := tokenTenants[bearer]
		if !ok {
			writeJSON(w, 401, `{"error":"unauthenticated"}`)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/tenants/"), "/")
		tenantID := parts[0]
		// Secure: cross-tenant access is forbidden.
		if tenantID != callerTenant {
			writeJSON(w, 403, `{"error":"forbidden: cross-tenant access"}`)
			return
		}
		data, ok := tenantConfigs[tenantID]
		if !ok {
			writeJSON(w, 404, `{"error":"not found"}`)
			return
		}
		writeJSON(w, 200, data)
	})
	return httptest.NewServer(mux)
}

// matrixForMultiTenant builds a matrix with two tenants: alice in acme, carol in globex.
// Alice is the "owner" of the captured /tenants/acme/config request; carol is cross-tenant.
func matrixForMultiTenant(baseURL string) *model.RoleMatrix {
	return &model.RoleMatrix{
		Version: "1",
		Target:  model.TargetConfig{BaseURL: baseURL},
		Tenants: []string{"acme", "globex"},
		Identities: []model.Identity{
			{Name: "anon", Role: "unauthenticated", Rank: 0},
			{Name: "alice", Role: "user", Rank: 10, Tenant: "acme",
				Markers: []string{"ACME_SECRET_DATA_9f3b", "acme", "enterprise"},
				Creds:   &model.Credentials{Bearer: "acme-tok"}},
			{Name: "carol", Role: "user", Rank: 10, Tenant: "globex",
				Markers: []string{"GLOBEX_SECRET_DATA_a7c2", "globex", "starter"},
				Creds:   &model.Credentials{Bearer: "globex-tok"}},
		},
	}
}

// TestCorpus_P8_VulnApp_CrossTenantFinding: carol (globex tenant) can read
// alice's (acme tenant) resource → idor-cross-tenant finding expected.
func TestCorpus_P8_VulnApp_CrossTenantFinding(t *testing.T) {
	srv := startVulnAppMultiTenant(t)
	defer srv.Close()

	matrix := matrixForMultiTenant(srv.URL)
	u, _ := url.Parse(srv.URL + "/tenants/acme/config")
	h := http.Header{}
	h.Set("Authorization", "Bearer acme-tok")
	cap := &model.CapturedRequest{
		ID: "GET /tenants/acme/config", Method: "GET", URL: u,
		PathTemplate: "/tenants/{tenant}/config", Headers: h,
	}
	ep := &model.Endpoint{
		Method: "GET", Host: u.Host, PathTemplate: "/tenants/{tenant}/config",
		Samples: []*model.CapturedRequest{cap},
	}
	owner, attr, _ := AttributeOwner(ep.Samples[0], matrix)
	ep.OwnerIdentity = owner
	ep.OwnerAttribution = attr

	const baselineN = 3
	baselinePlan := buildBaselinePlanLocal([]*model.Endpoint{ep}, baselineN)
	reg := mutate.DefaultRegistry()
	plan := replay.Generate([]*model.Endpoint{ep}, matrix, reg, 0)
	rs := model.RunSettings{RatePerHost: 1000, Concurrency: 8, MaxBody: 1024 * 1024}
	engine := replay.New(rs, "possession-tenant-corpus-test", nil)
	ctx := t.Context()
	baselineResp := engine.Run(ctx, baselinePlan)
	variantResp := engine.Run(ctx, plan)

	epKey := ep.Method + " " + ep.Host + ep.PathTemplate
	byKey := map[string][]*model.Response{}
	for i, v := range baselinePlan.Variants {
		key := variantEndpointKey(&v)
		r := baselineResp[i]
		byKey[key] = append(byKey[key], &r)
	}
	cal := Calibrate(byKey[epKey])
	var vrs []VariantResponse
	for i, v := range plan.Variants {
		if variantEndpointKey(&v) != epKey {
			continue
		}
		r := variantResp[i]
		vrs = append(vrs, VariantResponse{Variant: &plan.Variants[i], Response: &r})
	}
	verdictCounts := map[string]int{}
	res := ComparativeEvaluator{}.Evaluate(EvalContext{
		Endpoint: ep, Owner: ep.OwnerIdentity, Calibration: cal,
		VariantResponses: vrs, Matrix: matrix,
	})
	for _, vv := range res.Verdicts {
		verdictCounts[vv.Verdict]++
	}

	crossTenantFound := false
	for _, f := range res.Findings {
		if f.Class == "idor-cross-tenant" && (f.Verdict == VerdictBypass || f.Verdict == VerdictSuspected) {
			crossTenantFound = true
			break
		}
	}
	if !crossTenantFound {
		t.Errorf("P8: expected idor-cross-tenant finding; verdictCounts=%v findings:\n%s",
			verdictCounts, summarizeFindings(res.Findings))
	}
	t.Logf("P8 tenant vulnapp: verdictCounts=%v findings=%d", verdictCounts, len(res.Findings))
}

// TestCorpus_P8_SecureApp_CrossTenant_ZeroBypass — Gate E for tenant isolation.
// secureapp properly isolates tenants; no cross-tenant bypass expected.
func TestCorpus_P8_SecureApp_CrossTenant_ZeroBypass(t *testing.T) {
	srv := startSecureAppMultiTenant(t)
	defer srv.Close()

	matrix := matrixForMultiTenant(srv.URL)
	u, _ := url.Parse(srv.URL + "/tenants/acme/config")
	h := http.Header{}
	h.Set("Authorization", "Bearer acme-tok")
	cap := &model.CapturedRequest{
		ID: "GET /tenants/acme/config", Method: "GET", URL: u,
		PathTemplate: "/tenants/{tenant}/config", Headers: h,
	}
	ep := &model.Endpoint{
		Method: "GET", Host: u.Host, PathTemplate: "/tenants/{tenant}/config",
		Samples: []*model.CapturedRequest{cap},
	}
	owner, attr, _ := AttributeOwner(ep.Samples[0], matrix)
	ep.OwnerIdentity = owner
	ep.OwnerAttribution = attr

	const baselineN = 3
	baselinePlan := buildBaselinePlanLocal([]*model.Endpoint{ep}, baselineN)
	reg := mutate.DefaultRegistry()
	plan := replay.Generate([]*model.Endpoint{ep}, matrix, reg, 0)
	rs := model.RunSettings{RatePerHost: 1000, Concurrency: 8, MaxBody: 1024 * 1024}
	engine := replay.New(rs, "possession-tenant-secure-test", nil)
	ctx := t.Context()
	baselineResp := engine.Run(ctx, baselinePlan)
	variantResp := engine.Run(ctx, plan)

	epKey := ep.Method + " " + ep.Host + ep.PathTemplate
	byKey := map[string][]*model.Response{}
	for i, v := range baselinePlan.Variants {
		key := variantEndpointKey(&v)
		r := baselineResp[i]
		byKey[key] = append(byKey[key], &r)
	}
	cal := Calibrate(byKey[epKey])
	var vrs []VariantResponse
	for i, v := range plan.Variants {
		if variantEndpointKey(&v) != epKey {
			continue
		}
		r := variantResp[i]
		vrs = append(vrs, VariantResponse{Variant: &plan.Variants[i], Response: &r})
	}
	verdictCounts := map[string]int{}
	res := ComparativeEvaluator{}.Evaluate(EvalContext{
		Endpoint: ep, Owner: ep.OwnerIdentity, Calibration: cal,
		VariantResponses: vrs, Matrix: matrix,
	})
	for _, vv := range res.Verdicts {
		verdictCounts[vv.Verdict]++
	}

	bypassCount := 0
	for _, f := range res.Findings {
		if f.Verdict == VerdictBypass {
			bypassCount++
		}
	}
	if bypassCount > 0 {
		t.Errorf("P8 Gate E FAILED: %d bypass(es):\n%s", bypassCount, summarizeFindings(res.Findings))
	}
	t.Logf("P8 tenant secureapp: zero bypass; verdictCounts=%v findings=%d", verdictCounts, len(res.Findings))
}
