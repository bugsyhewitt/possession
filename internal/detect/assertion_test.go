package detect

import (
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// ─── LookupAssertion unit tests ───────────────────────────────────────

func TestLookupAssertion_NoAssertions(t *testing.T) {
	m := &model.RoleMatrix{}
	a, out := LookupAssertion(m, "GET", "/api/foo", "user")
	if a != nil || out != "" {
		t.Errorf("expected nil/empty, got %v/%q", a, out)
	}
}

func TestLookupAssertion_ExactMatch(t *testing.T) {
	m := &model.RoleMatrix{
		Assertions: []model.Assertion{
			{Endpoint: "GET /api/admin", Expect: map[string]string{"user": "deny", "admin": "allow"}},
		},
	}
	a, out := LookupAssertion(m, "GET", "/api/admin", "user")
	if a == nil {
		t.Fatal("expected non-nil assertion")
	}
	if out != "deny" {
		t.Errorf("user outcome: want deny, got %q", out)
	}
	_, out2 := LookupAssertion(m, "GET", "/api/admin", "admin")
	if out2 != "allow" {
		t.Errorf("admin outcome: want allow, got %q", out2)
	}
}

func TestLookupAssertion_GlobMatch(t *testing.T) {
	m := &model.RoleMatrix{
		Assertions: []model.Assertion{
			{Endpoint: "GET /api/admin/**", Expect: map[string]string{"user": "deny"}},
		},
	}
	a, out := LookupAssertion(m, "GET", "/api/admin/users", "user")
	if a == nil {
		t.Fatal("expected glob match")
	}
	if out != "deny" {
		t.Errorf("want deny, got %q", out)
	}
}

func TestLookupAssertion_MethodMismatch(t *testing.T) {
	m := &model.RoleMatrix{
		Assertions: []model.Assertion{
			{Endpoint: "POST /api/write", Expect: map[string]string{"user": "deny"}},
		},
	}
	a, _ := LookupAssertion(m, "GET", "/api/write", "user")
	if a != nil {
		t.Error("method mismatch should return nil")
	}
}

func TestLookupAssertion_MostSpecificWins(t *testing.T) {
	m := &model.RoleMatrix{
		Assertions: []model.Assertion{
			{Endpoint: "GET /api/**", Expect: map[string]string{"user": "allow"}},
			{Endpoint: "GET /api/admin/**", Expect: map[string]string{"user": "deny"}},
		},
	}
	// /api/admin/foo — both patterns match, more specific (longer) should win.
	a, out := LookupAssertion(m, "GET", "/api/admin/foo", "user")
	if a == nil {
		t.Fatal("expected match")
	}
	if out != "deny" {
		t.Errorf("most-specific should be deny, got %q", out)
	}
	// /api/other — only the first pattern matches.
	_, out2 := LookupAssertion(m, "GET", "/api/other", "user")
	if out2 != "allow" {
		t.Errorf("general pattern should give allow, got %q", out2)
	}
}

func TestLookupAssertion_RoleNotCovered(t *testing.T) {
	m := &model.RoleMatrix{
		Assertions: []model.Assertion{
			{Endpoint: "GET /api/foo", Expect: map[string]string{"admin": "allow"}},
		},
	}
	a, _ := LookupAssertion(m, "GET", "/api/foo", "user")
	if a != nil {
		t.Error("role not in expect map should return nil")
	}
}

func TestLookupAssertion_NoMethodPrefix(t *testing.T) {
	m := &model.RoleMatrix{
		Assertions: []model.Assertion{
			{Endpoint: "/api/**", Expect: map[string]string{"user": "deny"}},
		},
	}
	_, out := LookupAssertion(m, "GET", "/api/foo", "user")
	if out != "deny" {
		t.Errorf("no-method assertion should match any method; got %q", out)
	}
	_, out2 := LookupAssertion(m, "POST", "/api/bar", "user")
	if out2 != "deny" {
		t.Errorf("POST should also match no-method pattern; got %q", out2)
	}
}

// ─── AssertionEvaluator verdict tests ────────────────────────────────

func makeAssertionCtx(endpoint, method, pathTemplate, actorRole string, status int, assertions []model.Assertion) EvalContext {
	matrix := &model.RoleMatrix{
		Assertions: assertions,
		Identities: []model.Identity{
			{Name: "alice", Role: "user", Rank: 10},
			{Name: "admin", Role: "admin", Rank: 100},
		},
	}
	ep := &model.Endpoint{
		Method:       method,
		PathTemplate: pathTemplate,
	}
	actor := &model.Identity{Name: "testactor", Role: actorRole}
	resp := &model.Response{Status: status}
	if status >= 400 {
		resp.Body = []byte(`{"error":"forbidden"}`)
	} else {
		resp.Body = []byte(`{"id":"alice","data":"user-data"}`)
	}
	vr := VariantResponse{
		Variant:  &model.Variant{Identity: actor, Mutation: model.Mutation{Type: "swap-identity", Class: "idor"}},
		Response: resp,
	}
	return EvalContext{
		Endpoint:         ep,
		VariantResponses: []VariantResponse{vr},
		Matrix:           matrix,
		Calibration:      CalibrationResult{EffThreshold: 0.9},
	}
}

func TestAssertionEvaluator_BypassWhenGrantedButDenyExpected(t *testing.T) {
	ctx := makeAssertionCtx("GET /api/admin", "GET", "/api/admin", "user", 200,
		[]model.Assertion{
			{Endpoint: "GET /api/admin", Expect: map[string]string{"user": "deny"}},
		})
	res := AssertionEvaluator{}.Evaluate(ctx)
	if len(res.Verdicts) != 1 {
		t.Fatalf("want 1 verdict, got %d", len(res.Verdicts))
	}
	if res.Verdicts[0].Verdict != VerdictBypass {
		t.Errorf("want bypass, got %q", res.Verdicts[0].Verdict)
	}
	if len(res.Findings) != 1 {
		t.Errorf("want 1 finding, got %d", len(res.Findings))
	}
}

func TestAssertionEvaluator_EnforcedWhenDeniedAndDenyExpected(t *testing.T) {
	ctx := makeAssertionCtx("GET /api/admin", "GET", "/api/admin", "user", 403,
		[]model.Assertion{
			{Endpoint: "GET /api/admin", Expect: map[string]string{"user": "deny"}},
		})
	res := AssertionEvaluator{}.Evaluate(ctx)
	if res.Verdicts[0].Verdict != VerdictEnforced {
		t.Errorf("want enforced, got %q", res.Verdicts[0].Verdict)
	}
	if len(res.Findings) != 0 {
		t.Errorf("want 0 findings for enforced, got %d", len(res.Findings))
	}
}

func TestAssertionEvaluator_BrokenDenyWhenDeniedButAllowExpected(t *testing.T) {
	ctx := makeAssertionCtx("GET /api/orders", "GET", "/api/orders", "user", 403,
		[]model.Assertion{
			{Endpoint: "GET /api/orders", Expect: map[string]string{"user": "allow"}},
		})
	res := AssertionEvaluator{}.Evaluate(ctx)
	if res.Verdicts[0].Verdict != VerdictSuspected {
		t.Errorf("broken-deny should surface as suspected, got %q", res.Verdicts[0].Verdict)
	}
}

func TestAssertionEvaluator_NoAssertionReturnsEnforced(t *testing.T) {
	ctx := makeAssertionCtx("GET /api/foo", "GET", "/api/foo", "user", 200,
		[]model.Assertion{})
	res := AssertionEvaluator{}.Evaluate(ctx)
	if res.Verdicts[0].Verdict != VerdictEnforced {
		t.Errorf("no assertion should be enforced/unknown, got %q", res.Verdicts[0].Verdict)
	}
	if len(res.Findings) != 0 {
		t.Errorf("want 0 findings when no assertion, got %d", len(res.Findings))
	}
}

// ─── BothEvaluator precedence tests ──────────────────────────────────

func TestBothEvaluator_AssertionTakesPrecedence(t *testing.T) {
	// Assertion says user → deny; response is 200 (granted) → bypass.
	// ComparativeEvaluator might not catch this (similarity may be high
	// because the body matches). Assertion should override.
	ctx := makeAssertionCtx("GET /api/admin", "GET", "/api/admin", "user", 200,
		[]model.Assertion{
			{Endpoint: "GET /api/admin", Expect: map[string]string{"user": "deny"}},
		})
	// Give calibration a decent baseline body so comparative might say enforced.
	ctx.Calibration.BaselineBody = `{"id":"alice","data":"user-data"}`
	ctx.Calibration.EffThreshold = 0.90

	res := BothEvaluator{}.Evaluate(ctx)
	if len(res.Verdicts) == 0 {
		t.Fatal("no verdicts")
	}
	if res.Verdicts[0].Verdict != VerdictBypass {
		t.Errorf("assertion should win; want bypass, got %q", res.Verdicts[0].Verdict)
	}
}
