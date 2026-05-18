package detect

import (
	"fmt"
	"strings"

	"github.com/bugsyhewitt/possession/internal/config"
	"github.com/bugsyhewitt/possession/internal/model"
)

// AssertionEvaluator is the AuthMatrix-style evaluator (D16 / P6).
// The user predefines the intended access model as an assertions block in the
// matrix YAML; this evaluator flags deviations with high confidence because
// the expected outcome is explicit — no comparative inference needed.
//
// Verdict mapping:
//   - Granted + expect deny  → bypass (high confidence)
//   - Denied  + expect allow → broken-deny (low severity, surfaced as suspected)
//   - Matches assertion       → enforced
//   - No assertion covers it  → no finding; callers may fall through to comparative
type AssertionEvaluator struct{}

func (AssertionEvaluator) Name() string { return "assertion" }

// Evaluate implements Evaluator.
func (e AssertionEvaluator) Evaluate(ctx EvalContext) EvalResult {
	out := EvalResult{}
	out.Verdicts = make([]VariantVerdict, 0, len(ctx.VariantResponses))

	for _, vr := range ctx.VariantResponses {
		vv := e.judge(vr, ctx)
		out.Verdicts = append(out.Verdicts, vv)
		if vv.Verdict == VerdictBypass || vv.Verdict == VerdictSuspected {
			f := BuildFinding(ctx.Endpoint, vr.Variant, vr.Response, vv, ctx.Calibration)
			out.Findings = append(out.Findings, f)
		}
	}
	return out
}

func (e AssertionEvaluator) judge(vr VariantResponse, ctx EvalContext) VariantVerdict {
	v := vr.Variant
	r := vr.Response
	vv := VariantVerdict{Variant: v, Response: r}

	// Transport error or refresh failure → inconclusive.
	if r != nil && r.Inconclusive {
		vv.Verdict = VerdictInconclusive
		vv.Notes = append(vv.Notes, "inconclusive: refresh failure")
		return vv
	}

	actorRole := ""
	if v != nil && v.Identity != nil {
		actorRole = v.Identity.Role
	}

	epPath := ""
	epMethod := ""
	if ctx.Endpoint != nil {
		epPath = ctx.Endpoint.PathTemplate
		epMethod = ctx.Endpoint.Method
	}

	// Find the most-specific assertion covering this endpoint + role.
	assertion, outcome := LookupAssertion(ctx.Matrix, epMethod, epPath, actorRole)
	if assertion == nil {
		// No assertion covers this pair — mark unknown; report nothing.
		vv.Verdict = VerdictEnforced
		vv.Confidence = 0
		vv.Notes = append(vv.Notes, fmt.Sprintf("no assertion for %s %s role=%q", epMethod, epPath, actorRole))
		return vv
	}

	granted := isGranted(r)

	switch outcome {
	case "deny":
		if granted {
			// Bypass: access granted but deny expected.
			vv.Verdict = VerdictBypass
			vv.Confidence = AssertionBypassConfidence
			vv.Notes = append(vv.Notes,
				fmt.Sprintf("assertion violation: %s %s role=%q: expected deny, got access (status %d)",
					epMethod, epPath, actorRole, statusOf(r)))
		} else {
			// Correctly denied.
			vv.Verdict = VerdictEnforced
			vv.Confidence = 1.0
			vv.Notes = append(vv.Notes, fmt.Sprintf("assertion satisfied: role=%q denied as expected", actorRole))
		}
	case "allow":
		if !granted {
			// Broken deny: access denied but allow expected. Low-severity surfaced
			// as suspected so it appears in findings without alarming the user.
			vv.Verdict = VerdictSuspected
			vv.Confidence = AssertionBrokenDenyConfidence
			if v != nil {
				v.Mutation.Class = "broken-deny"
			}
			vv.Notes = append(vv.Notes,
				fmt.Sprintf("broken-deny: %s %s role=%q: expected allow, got denied (status %d)",
					epMethod, epPath, actorRole, statusOf(r)))
		} else {
			vv.Verdict = VerdictEnforced
			vv.Confidence = 1.0
			vv.Notes = append(vv.Notes, fmt.Sprintf("assertion satisfied: role=%q allowed as expected", actorRole))
		}
	}
	return vv
}

// isGranted returns true when the response indicates the request was granted
// (2xx status that is not an in-app denial page). Reuses the same signal as
// the comparative evaluator.
func isGranted(r *model.Response) bool {
	if r == nil {
		return false
	}
	sc := ClassifyStatus(r)
	if sc == StatusDenied || sc == StatusError {
		return false
	}
	// 2xx with denial-shaped body → also treat as denied.
	ct := ""
	if r.Headers != nil {
		ct = r.Headers.Get("Content-Type")
	}
	norm := NormalizeBody(r.Body, ct)
	return !ErrorSignature(norm)
}

func statusOf(r *model.Response) int {
	if r == nil {
		return 0
	}
	return r.Status
}

// LookupAssertion finds the most-specific assertion in the matrix that matches
// "METHOD /path" for the given role. Returns the assertion and the expected
// outcome ("allow"/"deny"), or nil/"" if no assertion matches.
//
// Specificity rule: an assertion whose endpoint pattern is longer (more specific)
// takes precedence over a shorter/more-general one. When two patterns have the
// same length, the one appearing earlier in the assertions list wins (stable).
func LookupAssertion(m *model.RoleMatrix, method, pathTemplate, role string) (*model.Assertion, string) {
	if m == nil || len(m.Assertions) == 0 {
		return nil, ""
	}
	var best *model.Assertion
	bestLen := -1
	for i := range m.Assertions {
		a := &m.Assertions[i]
		if !assertionMatchesEndpoint(a.Endpoint, method, pathTemplate) {
			continue
		}
		// Specificity = len of the pattern (longer = more specific).
		patLen := len(a.Endpoint)
		if best == nil || patLen > bestLen {
			outcome, ok := a.Expect[role]
			if !ok {
				continue // this assertion doesn't cover the role
			}
			_ = outcome
			best = a
			bestLen = patLen
		}
	}
	if best == nil {
		return nil, ""
	}
	return best, best.Expect[role]
}

// assertionMatchesEndpoint reports whether the assertion's endpoint pattern
// matches the given method + pathTemplate.
//
// Pattern format: "METHOD /path/glob" or "/path/glob" (method optional).
// Uses the same glob dialect as scope patterns (config.MatchGlob).
func assertionMatchesEndpoint(pattern, method, pathTemplate string) bool {
	parts := strings.SplitN(pattern, " ", 2)
	var patMethod, patPath string
	if len(parts) == 2 {
		patMethod = strings.ToUpper(parts[0])
		patPath = parts[1]
	} else {
		patMethod = ""
		patPath = parts[0]
	}
	if patMethod != "" && patMethod != strings.ToUpper(method) {
		return false
	}
	return config.MatchGlob(patPath, pathTemplate)
}

// BothEvaluator runs the AssertionEvaluator where an assertion exists, and
// the ComparativeEvaluator everywhere else (or for any variant not covered).
// The assertion verdict takes precedence when both cover the same variant (D16).
type BothEvaluator struct{}

func (BothEvaluator) Name() string { return "both" }

// Evaluate runs both evaluators and merges: for variants with an assertion,
// the assertion verdict wins; otherwise the comparative verdict is used.
func (e BothEvaluator) Evaluate(ctx EvalContext) EvalResult {
	assertResult := AssertionEvaluator{}.Evaluate(ctx)
	compResult := ComparativeEvaluator{}.Evaluate(ctx)

	// Build a set of indices where the assertion evaluator produced a real
	// (non-unknown) verdict (i.e. an assertion covered this variant).
	assertCovered := make(map[int]bool, len(assertResult.Verdicts))
	for i, vv := range assertResult.Verdicts {
		if len(vv.Notes) > 0 && strings.HasPrefix(vv.Notes[0], "no assertion") {
			continue
		}
		assertCovered[i] = true
	}

	merged := EvalResult{
		Verdicts: make([]VariantVerdict, len(ctx.VariantResponses)),
	}
	for i := range ctx.VariantResponses {
		if assertCovered[i] {
			merged.Verdicts[i] = assertResult.Verdicts[i]
		} else {
			merged.Verdicts[i] = compResult.Verdicts[i]
		}
		vv := merged.Verdicts[i]
		if vv.Verdict == VerdictBypass || vv.Verdict == VerdictSuspected {
			f := BuildFinding(ctx.Endpoint, vv.Variant, vv.Response, vv, ctx.Calibration)
			merged.Findings = append(merged.Findings, f)
		}
	}
	return merged
}
