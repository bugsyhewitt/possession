package detect

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

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
