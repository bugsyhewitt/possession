package detect

import (
	"fmt"

	"github.com/bugsyhewitt/possession/internal/model"
)

// ComparativeEvaluator is the v1.0 Autorize-style evaluator: per-endpoint
// owner self-replay is the calibrated baseline, and each variant response
// is judged against it via the §4.4 verdict ladder.
type ComparativeEvaluator struct{}

// Name returns the evaluator's identifier.
func (ComparativeEvaluator) Name() string { return "comparative" }

// Evaluate runs the verdict ladder once per variant in ctx and assembles
// the EvalResult.
func (ev ComparativeEvaluator) Evaluate(ctx EvalContext) EvalResult {
	out := EvalResult{}
	out.Verdicts = make([]VariantVerdict, 0, len(ctx.VariantResponses))

	cal := ctx.Calibration
	for _, vr := range ctx.VariantResponses {
		vv := ev.judge(vr, ctx.Owner, cal)
		vv = applyCrossRankCap(vv, vr.Variant, ctx.Owner)
		out.Verdicts = append(out.Verdicts, vv)

		if vv.Verdict == VerdictBypass || vv.Verdict == VerdictSuspected {
			f := BuildFinding(ctx.Endpoint, vr.Variant, vr.Response, vv, cal)
			out.Findings = append(out.Findings, f)
		}
	}
	return out
}

// applyCrossRankCap implements D28: a swap-identity variant where the
// acting identity's rank differs from the endpoint owner's rank is
// downgraded — bypass becomes suspected, the verdict carries a typed
// cross-rank-swap note, and confidence is dampened. Suspected stays
// suspected (no further downgrade), enforced/inconclusive untouched.
// Same-rank swaps and non-swap mutators pass through unchanged.
func applyCrossRankCap(vv VariantVerdict, v *model.Variant, owner *model.Identity) VariantVerdict {
	if v == nil || owner == nil || v.Identity == nil {
		return vv
	}
	if v.Mutation.Type != "swap-identity" || v.Identity.Rank == owner.Rank {
		return vv
	}
	if vv.Verdict != VerdictBypass && vv.Verdict != VerdictSuspected {
		return vv
	}
	if vv.Verdict == VerdictBypass {
		vv.Verdict = VerdictSuspected
		vv.Confidence *= AmbiguousPenalty
	}
	vv.Notes = append(vv.Notes,
		fmt.Sprintf("cross-rank-swap: actor rank %d vs owner rank %d — capped at suspected (D28)",
			v.Identity.Rank, owner.Rank))
	return vv
}

// judge is the §4.4 verdict ladder — first match wins.
func (ev ComparativeEvaluator) judge(vr VariantResponse, owner *model.Identity, cal CalibrationResult) VariantVerdict {
	v := vr.Variant
	r := vr.Response
	vv := VariantVerdict{Variant: v, Response: r}

	// Pre-ladder filter: a swap-identity or downgrade-role variant whose
	// actor is the endpoint's own owner is literally the baseline anchor
	// (D9). It cannot constitute a bypass — the owner reading their own
	// data is benign by definition. Skip the ladder; mark enforced with a
	// note so summary counts stay honest. Without this filter, alice-as-alice
	// trivially trips reflectedOwner on every endpoint, producing a swarm
	// of false positives on properly-secured apps.
	if v != nil && owner != nil && v.Identity != nil && v.Identity.Name == owner.Name {
		switch v.Mutation.Type {
		case "swap-identity", "downgrade-role":
			vv.Verdict = VerdictEnforced
			vv.Confidence = 0
			vv.Notes = append(vv.Notes, "same-identity replay (baseline anchor) — not a bypass candidate")
			return vv
		}
	}

	// D28: cross-rank swap-identity is NOT short-circuited here. The
	// ladder runs as normal; applyCrossRankCap (called by Evaluate after
	// judge) downgrades bypass→suspected with a typed cross-rank-swap
	// note. This keeps the ladder pure and the policy decision in one
	// auditable place.

	// Branch 3 (also short-circuits before any signal work): refresh
	// failure from Packet 2 already marked the response Inconclusive.
	if r != nil && r.Inconclusive {
		vv.Verdict = VerdictInconclusive
		vv.Confidence = 0
		vv.Notes = append(vv.Notes, "variant marked inconclusive by replay engine (refresh failure)")
		return vv
	}

	// Branch 2: baseline failed (non-2xx owner self-replay) ⇒ every
	// variant on this endpoint is inconclusive.
	if cal.BaselineFailed {
		vv.Verdict = VerdictInconclusive
		vv.Confidence = 0
		vv.Notes = append(vv.Notes, fmt.Sprintf("baseline status %d is not 2xx; cannot judge", cal.BaselineStatus))
		return vv
	}

	// Compute statusClass and the body signals.
	sc := ClassifyStatus(r)

	// Branch 1: transport error or 429/5xx.
	if sc == StatusError {
		vv.Verdict = VerdictInconclusive
		vv.Confidence = 0
		errNote := "transport error or 5xx/429"
		if r != nil && r.Err != "" {
			errNote = "request error: " + r.Err
		} else if r != nil {
			errNote = fmt.Sprintf("status %d treated as error", r.Status)
		}
		vv.Notes = append(vv.Notes, errNote)
		return vv
	}

	// Branch 4: denied status (4xx, login-redirect 3xx). Authz working.
	if sc == StatusDenied {
		vv.Verdict = VerdictEnforced
		vv.Confidence = 0
		statusVal := 0
		if r != nil {
			statusVal = r.Status
		}
		vv.Notes = append(vv.Notes, fmt.Sprintf("status %d ⇒ enforced", statusVal))
		return vv
	}

	// Now we need the variant's normalized body for similarity/signature.
	variantCT := ""
	if r != nil && r.Headers != nil {
		variantCT = r.Headers.Get("Content-Type")
	}
	var variantBody []byte
	if r != nil {
		variantBody = r.Body
	}
	variantNorm := NormalizeBody(variantBody, variantCT)
	sim := Similarity(cal.BaselineBody, variantNorm)
	szRatio := SizeRatio(cal.BaselineBody, variantNorm)
	errSig := ErrorSignature(variantNorm)

	// Marker signals require knowing both owner and actor (v.Identity).
	reflectedO := ReflectedOwner(variantBody, owner)
	reflectedA := ReflectedActor(variantBody, identityOf(v), owner)

	// Branch 5: 2xx but body looks like a denial AND similarity is below
	// effThreshold ⇒ this is really an in-app denial page.
	if errSig && sim < cal.EffThreshold {
		vv.Verdict = VerdictEnforced
		vv.Confidence = 0
		vv.Notes = append(vv.Notes, fmt.Sprintf("errorSignature matched on 2xx body (similarity %.2f < threshold %.2f) ⇒ enforced", sim, cal.EffThreshold))
		return vv
	}

	// Branch 6: variant body contains ONLY the acting identity's marker
	// (not the owner's). Server returned caller's own data ⇒ correct.
	if reflectedA {
		vv.Verdict = VerdictEnforced
		vv.Confidence = ReflectedActorConfidence
		vv.Notes = append(vv.Notes, "reflectedActor: variant body contains acting-identity markers only ⇒ enforced")
		return vv
	}

	// Branch 7: variant body contains the resource owner's marker.
	// Decisive bypass.
	if reflectedO {
		conf := ReflectedOwnerConfidence
		if sc == StatusAmbiguous {
			conf *= AmbiguousPenalty
		}
		vv.Verdict = VerdictBypass
		vv.Confidence = conf
		vv.Notes = append(vv.Notes, "reflectedOwner: variant body contains owner marker ⇒ bypass")
		// Noisy cap still applies.
		if cal.Noisy {
			vv.Verdict = VerdictSuspected
			vv.Notes = append(vv.Notes, "noisy-endpoint: bypass capped at suspected")
		}
		return vv
	}

	// Branch 8: similarity >= effThreshold AND not error-shaped ⇒ bypass.
	if sim >= cal.EffThreshold && !errSig {
		// Scale BaseHigh upward by how far similarity exceeds threshold,
		// then multiply by sizeRatio so a big size mismatch reduces conf.
		over := sim - cal.EffThreshold
		span := 1.0 - cal.EffThreshold
		boost := 0.0
		if span > 0 {
			boost = over / span // 0..1 across the band above threshold
		}
		conf := BaseHigh + boost*(MaxBypassConfidence-BaseHigh)
		conf *= szRatio
		if conf > MaxBypassConfidence {
			conf = MaxBypassConfidence
		}
		if sc == StatusAmbiguous {
			conf *= AmbiguousPenalty
		}
		vv.Verdict = VerdictBypass
		vv.Confidence = conf
		vv.Notes = append(vv.Notes,
			fmt.Sprintf("similarity %.2f >= threshold %.2f", sim, cal.EffThreshold),
			fmt.Sprintf("sizeRatio %.2f", szRatio),
		)
		if cal.Noisy {
			vv.Verdict = VerdictSuspected
			vv.Notes = append(vv.Notes, "noisy-endpoint: bypass capped at suspected")
		}
		return vv
	}

	// Branch 9: similarity in [SuspectLow, effThreshold) ⇒ suspected.
	if sim >= SuspectLow {
		// Scale confidence linearly from SuspectedConfMin at SuspectLow
		// to SuspectedConfMax at effThreshold.
		span := cal.EffThreshold - SuspectLow
		frac := 0.0
		if span > 0 {
			frac = (sim - SuspectLow) / span
		}
		conf := SuspectedConfMin + frac*(SuspectedConfMax-SuspectedConfMin)
		if sc == StatusAmbiguous {
			conf *= AmbiguousPenalty
		}
		vv.Verdict = VerdictSuspected
		vv.Confidence = conf
		vv.Notes = append(vv.Notes, fmt.Sprintf("similarity %.2f in suspect band [%.2f, %.2f)", sim, SuspectLow, cal.EffThreshold))
		return vv
	}

	// Branch 10: similarity < SuspectLow ⇒ enforced (low confidence).
	// Known v1.1 limitation: a different-but-still-unauthorized resource
	// lands here. We accept the false negative rather than the false
	// positive cost.
	vv.Verdict = VerdictEnforced
	vv.Confidence = LowConfidence
	vv.Notes = append(vv.Notes, fmt.Sprintf("similarity %.2f below suspect floor %.2f ⇒ enforced (v1.1 limitation: cannot distinguish 'denied' from 'different resource')", sim, SuspectLow))
	return vv
}

func identityOf(v *model.Variant) *model.Identity {
	if v == nil {
		return nil
	}
	return v.Identity
}
