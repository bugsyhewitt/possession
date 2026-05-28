package detect

import (
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

func TestBuildFinding_ClassMapping(t *testing.T) {
	cases := []struct {
		mutator string
		class   string
	}{
		{"strip-auth", "authn-bypass"},
		{"swap-identity", "idor"},
		{"downgrade-role", "privesc"},
		{"drop-cookie", "auth-dependency"},
		{"strip-token", "auth-dependency"},
	}
	ep := &model.Endpoint{Method: "GET", Host: "h", PathTemplate: "/x"}
	for _, c := range cases {
		// D30: Class is set at mutator generation time. BuildFinding reads
		// it; tests must seed it on the input variant. We still verify the
		// fallback path (empty Class on input ⇒ MutatorClass lookup) below.
		v := &model.Variant{ID: "v1", Mutation: model.Mutation{Type: c.mutator, Class: c.class}}
		r := &model.Response{Status: 200}
		vv := VariantVerdict{Verdict: VerdictBypass, Confidence: 0.9}
		cal := mkCal("baseline", 200, false, false, false, 0.85)
		f := BuildFinding(ep, v, r, vv, cal)
		if f.Class != c.class {
			t.Errorf("%s: want class %s got %s", c.mutator, c.class, f.Class)
		}
	}
}

// TestBuildFinding_FallbackClass verifies the fallback path: when a
// variant has no Class set, BuildFinding consults MutatorClass(). This
// preserves correctness for callers that build variants directly without
// going through the mutator registry (e.g. baseline-self).
func TestBuildFinding_FallbackClass(t *testing.T) {
	ep := &model.Endpoint{Method: "GET", Host: "h", PathTemplate: "/x"}
	v := &model.Variant{ID: "v1", Mutation: model.Mutation{Type: "swap-identity"}}
	r := &model.Response{Status: 200}
	vv := VariantVerdict{Verdict: VerdictBypass, Confidence: 0.9}
	cal := mkCal("baseline", 200, false, false, false, 0.85)
	f := BuildFinding(ep, v, r, vv, cal)
	if f.Class != "idor" {
		t.Errorf("fallback: want idor got %s", f.Class)
	}
}

func TestBuildFinding_SeverityAndASVS(t *testing.T) {
	ep := &model.Endpoint{Method: "GET", Host: "h", PathTemplate: "/x"}
	cal := mkCal("baseline", 200, false, false, false, 0.85)

	cases := []struct {
		mutator    string
		verdict    string
		wantSev    string
		wantASVS   []string
	}{
		{"strip-auth", VerdictBypass, "critical", []string{"v5.0.0-8.3.1"}},
		{"swap-identity", VerdictBypass, "high", []string{"v5.0.0-8.2.2"}},
		{"downgrade-role", VerdictBypass, "high", []string{"v5.0.0-8.2.1"}},
		{"drop-cookie", VerdictBypass, "low", []string{"v5.0.0-8.3.1"}},
		// Suspected: severity drops one notch.
		{"strip-auth", VerdictSuspected, "high", []string{"v5.0.0-8.3.1"}},
		{"swap-identity", VerdictSuspected, "medium", []string{"v5.0.0-8.2.2"}},
		{"drop-cookie", VerdictSuspected, "info", []string{"v5.0.0-8.3.1"}},
	}
	for _, c := range cases {
		v := &model.Variant{ID: "v1", Mutation: model.Mutation{Type: c.mutator}}
		vv := VariantVerdict{Verdict: c.verdict, Confidence: 0.5}
		f := BuildFinding(ep, v, &model.Response{Status: 200}, vv, cal)
		if f.Severity != c.wantSev {
			t.Errorf("%s %s: severity want %s got %s", c.mutator, c.verdict, c.wantSev, f.Severity)
		}
		if len(f.ASVS) != len(c.wantASVS) || (len(f.ASVS) > 0 && f.ASVS[0] != c.wantASVS[0]) {
			t.Errorf("%s %s: asvs want %v got %v", c.mutator, c.verdict, c.wantASVS, f.ASVS)
		}
	}
}

// TestBuildFinding_JWTAttackSeverityOverride verifies the --jwt-attack
// mutator types are pinned to HIGH severity (overriding the authn-bypass
// class default of critical), and that suspected verdicts still drop one
// notch (high→medium).
func TestBuildFinding_JWTAttackSeverityOverride(t *testing.T) {
	ep := &model.Endpoint{Method: "GET", Host: "h", PathTemplate: "/x"}
	cal := mkCal("baseline", 200, false, false, false, 0.85)

	cases := []struct {
		mutator string
		verdict string
		wantSev string
	}{
		{"jwt-attack-none", VerdictBypass, "high"},
		{"jwt-attack-blank-secret", VerdictBypass, "high"},
		{"jwt-attack-none", VerdictSuspected, "medium"},
		{"jwt-attack-blank-secret", VerdictSuspected, "medium"},
	}
	for _, c := range cases {
		v := &model.Variant{ID: "v1", Mutation: model.Mutation{Type: c.mutator, Class: "authn-bypass"}}
		vv := VariantVerdict{Verdict: c.verdict, Confidence: 0.5}
		f := BuildFinding(ep, v, &model.Response{Status: 200}, vv, cal)
		if f.Severity != c.wantSev {
			t.Errorf("%s %s: severity want %s got %s", c.mutator, c.verdict, c.wantSev, f.Severity)
		}
		if f.Class != "authn-bypass" {
			t.Errorf("%s: class want authn-bypass got %s", c.mutator, f.Class)
		}
	}
}

func TestBuildFinding_DeterministicID(t *testing.T) {
	ep := &model.Endpoint{Method: "GET", Host: "h", PathTemplate: "/x"}
	v := &model.Variant{ID: "v1", Mutation: model.Mutation{Type: "swap-identity"}}
	r := &model.Response{Status: 200}
	vv := VariantVerdict{Verdict: VerdictBypass, Confidence: 0.9}
	cal := mkCal("baseline", 200, false, false, false, 0.85)
	f1 := BuildFinding(ep, v, r, vv, cal)
	f2 := BuildFinding(ep, v, r, vv, cal)
	if f1.ID != f2.ID {
		t.Errorf("non-deterministic finding ID: %s vs %s", f1.ID, f2.ID)
	}
	if len(f1.ID) != 16 {
		t.Errorf("expected 16-char hex ID, got %q", f1.ID)
	}
}

func TestEvaluate_ProducesFindingsForReportableVerdictsOnly(t *testing.T) {
	ep := &model.Endpoint{Method: "GET", Host: "h", PathTemplate: "/x"}
	body := `{"name":"alice","items":["a","b","c","d","e","f","g","h"]}`
	cal := mkCal(NormalizeBody([]byte(body), "application/json"), 200, false, false, false, 0.85)
	vrBypass := mkVR("swap-identity", nil, 200, body, "application/json", false, "")
	vrDenied := mkVR("swap-identity", nil, 403, "forbidden", "text/plain", false, "")
	vrInconclusive := mkVR("swap-identity", nil, 0, "", "", true, "refresh failed")
	ev := ComparativeEvaluator{}
	ctx := EvalContext{
		Endpoint:    ep,
		Calibration: cal,
		VariantResponses: []VariantResponse{vrBypass, vrDenied, vrInconclusive},
	}
	res := ev.Evaluate(ctx)
	if len(res.Verdicts) != 3 {
		t.Fatalf("want 3 verdicts, got %d", len(res.Verdicts))
	}
	// Bypass produces finding; denied + inconclusive do not.
	if len(res.Findings) != 1 {
		t.Errorf("want 1 finding (bypass only), got %d", len(res.Findings))
	}
	if res.Findings[0].Verdict != VerdictBypass {
		t.Errorf("finding verdict: want bypass got %s", res.Findings[0].Verdict)
	}
}
