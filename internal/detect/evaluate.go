package detect

import (
	"bytes"
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

	// WebSocket upgrade branch (--ws-hijack): a ws-hijack variant stripped or
	// swapped the caller's credentials while preserving the WebSocket upgrade
	// headers, then watches for the server completing the handshake. A response
	// status of 101 Switching Protocols means the server agreed to open a live
	// WebSocket channel for a caller whose authorization it did not enforce ⇒
	// WebSocket authz bypass. This is decisive and false-positive-free (a 101
	// never appears unless the server upgraded the connection), and it has no
	// owner/actor body baseline to compare against, so it short-circuits the
	// comparative ladder.
	//
	// This branch MUST run ahead of the StatusError short-circuit below:
	// ClassifyStatus treats status < 200 (which includes 101) as StatusError,
	// so a handshake success would otherwise be swallowed as a transport error.
	if v != nil && v.Mutation.Detail["ws-hijack"] != "" {
		if r != nil && r.Err == "" && r.Status == 101 {
			vv.Verdict = VerdictBypass
			vv.Confidence = WSHandshakeConfidence
			vv.Notes = append(vv.Notes,
				"ws-hijack: server returned 101 Switching Protocols to a stripped/swapped identity ⇒ WebSocket upgrade completed without enforcing authorization")
			return vv
		}
		// Any non-101 response (denied, error, or a normal status) means the
		// handshake did not complete under the modified identity. Treat it as
		// enforced — the WebSocket access check held. We do not fall through to
		// the body-similarity ladder: a handshake has no meaningful body to
		// compare, and the absence of a 101 is itself the enforced signal.
		vv.Verdict = VerdictEnforced
		vv.Confidence = 0
		status := 0
		if r != nil {
			status = r.Status
		}
		vv.Notes = append(vv.Notes,
			fmt.Sprintf("ws-hijack: status %d (not 101) ⇒ WebSocket upgrade not completed under modified identity ⇒ enforced", status))
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

	// XXE canary branch (R18): a --xxe variant injects an internal entity
	// whose value is a unique per-endpoint canary recorded in
	// Mutation.Detail["xxe-canary"]. If the response body contains that
	// canary verbatim, the server's XML parser expanded the entity ⇒ XML
	// External Entity processing is confirmed. This is decisive and
	// false-positive-free (the canary is unique and never present unless the
	// parser reflected it), so it short-circuits the comparative ladder —
	// XXE has no owner/actor baseline to compare against. The external-system
	// technique carries no canary and falls through to the normal ladder,
	// where a body diff from the entity-stripped baseline surfaces it.
	if v != nil {
		if canary := v.Mutation.Detail["xxe-canary"]; canary != "" {
			var rawBody []byte
			if r != nil {
				rawBody = r.Body
			}
			if len(rawBody) > 0 && bytes.Contains(rawBody, []byte(canary)) {
				vv.Verdict = VerdictBypass
				vv.Confidence = XXECanaryConfidence
				vv.Notes = append(vv.Notes,
					"xxe-canary: response body reflects injected internal-entity canary ⇒ XML entity expansion confirmed (XXE)")
				return vv
			}
		}
	}

	// GraphQL introspection branch (R19): a --graphql variant sends the
	// canonical introspection query carrying
	// Mutation.Detail["graphql-signal"] == "introspection". If the response
	// body reflects the introspection schema markers (__schema / queryType /
	// __type), the server answered the introspection query ⇒ schema
	// introspection is enabled (information disclosure). Those markers are
	// GraphQL-internal type-system identifiers that only appear when the schema
	// is walked, so the signal is decisive and short-circuits the comparative
	// ladder — introspection has no owner/actor baseline. The malformed-query
	// technique carries no introspection signal and falls through to the
	// normal ladder, where a verbose-error body diff surfaces it.
	if v != nil && v.Mutation.Detail["graphql-signal"] == "introspection" {
		var rawBody []byte
		if r != nil {
			rawBody = r.Body
		}
		if graphqlIntrospectionReflected(rawBody) {
			vv.Verdict = VerdictBypass
			vv.Confidence = GraphQLIntrospectionConfidence
			vv.Notes = append(vv.Notes,
				"graphql-introspection: response reflects introspection schema markers (__schema/queryType/__type) ⇒ GraphQL introspection is enabled (schema disclosure)")
			return vv
		}
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

	// Branch 9b: similarity < SuspectLow, but the response is a 2xx whose
	// body is NOT denial-shaped (errSig already false here — branch 5 caught
	// the 2xx-with-denial-body case) AND the mutation is a cross-identity /
	// cross-resource access test (swap-identity / swap-object). The server
	// answered with a *successful but different* resource than the owner
	// baseline: not a denial (those are 4xx ⇒ branch 4, or 2xx-error-body ⇒
	// branch 5), but a different object the actor may not be entitled to.
	// This is the "different resource class" case the comparative ladder
	// historically swallowed as enforced (the D44 / v1.1 false negative).
	// Surface it as `suspected` at low confidence so a real horizontal-IDOR
	// to a distinct object isn't silently dropped, while the divergent body
	// keeps it out of the high/medium confidence bands (ClassifyConfidenceBand
	// caps it at `low`). Scoped to swap mutators only: a low-similarity 2xx
	// from an unrelated mutator (host-header, csrf-header, …) is not an
	// object-access signal and stays enforced at branch 10.
	if sc == StatusSuccess && isResourceSwap(v) {
		vv.Verdict = VerdictSuspected
		vv.Confidence = DiffResourceConfidence
		vv.Notes = append(vv.Notes, fmt.Sprintf("similarity %.2f below suspect floor %.2f but 2xx non-denial body ⇒ different-resource access (suspected horizontal IDOR to a distinct object)", sim, SuspectLow))
		return vv
	}

	// Branch 10: similarity < SuspectLow ⇒ enforced (low confidence).
	// Reached when the divergent 2xx is not from a resource-swap mutator, or
	// the status is not a clean 2xx — i.e. there is no positive signal that
	// the actor obtained a different resource. A genuine denial (4xx, or a
	// 2xx error wrapper) was already classified enforced upstream (branches
	// 4 / 5); this branch covers the remaining "different and uninteresting"
	// tail. The resource-swap different-resource case is handled by branch 9b.
	vv.Verdict = VerdictEnforced
	vv.Confidence = LowConfidence
	vv.Notes = append(vv.Notes, fmt.Sprintf("similarity %.2f below suspect floor %.2f ⇒ enforced (no different-resource signal for this mutation)", sim, SuspectLow))
	return vv
}

// isResourceSwap reports whether a variant's mutation is a cross-identity or
// cross-resource object-access test (swap-identity / swap-object) — the
// mutators for which a successful-but-divergent 2xx response is a meaningful
// horizontal-IDOR signal (branch 9b). Other mutators returning a different
// body carry no object-access semantics and are not treated as different-
// resource hits.
func isResourceSwap(v *model.Variant) bool {
	if v == nil {
		return false
	}
	switch v.Mutation.Type {
	case "swap-identity", "swap-object":
		return true
	default:
		return false
	}
}

func identityOf(v *model.Variant) *model.Identity {
	if v == nil {
		return nil
	}
	return v.Identity
}

// graphqlIntrospectionReflected reports whether body looks like a successful
// GraphQL introspection response. A real introspection answer nests the
// schema root marker "__schema" together with the "queryType" descriptor it
// always contains; requiring BOTH (rather than either alone) keeps the signal
// decisive — a server that merely mentions "__schema" in an error string, or
// echoes the query, won't carry both markers in the structural positions a
// real result does. We also accept the "__type" marker as a corroborating
// alternative when "queryType" is absent (some servers answer a partial
// introspection). The check is case-sensitive: GraphQL introspection field
// names are fixed identifiers.
func graphqlIntrospectionReflected(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	if !bytes.Contains(body, []byte("__schema")) {
		return false
	}
	return bytes.Contains(body, []byte("queryType")) || bytes.Contains(body, []byte("__type"))
}
