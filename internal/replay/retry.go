package replay

import (
	"context"
	"net/http"

	"github.com/bugsyhewitt/possession/internal/model"
)

// IsTransientFailure reports whether a response failed for a reason a single
// re-issue could plausibly fix: a transport error (resp.Err set with no usable
// status) or a transient server-side rejection (HTTP 429 or any 5xx).
//
// It deliberately returns false for responses the engine marked Inconclusive,
// because that flag is set only for refresh/flow short-circuits (D10) — a
// per-identity setup failure that a single variant retry cannot repair and that
// would only burn another request. Those stay inconclusive.
//
// A nil response is treated as a transient failure (no response at all is the
// strongest signal that the request never completed).
func IsTransientFailure(resp *model.Response) bool {
	if resp == nil {
		return true
	}
	if resp.Inconclusive {
		return false
	}
	if resp.Err != "" {
		return true
	}
	return resp.Status == http.StatusTooManyRequests || resp.Status >= 500
}

// RetryInconclusive re-issues, exactly once, every variant in plan whose
// corresponding response in responses is a transient failure (per
// IsTransientFailure). It returns a new plan-ordered slice: a retried slot
// holds the retry's response only when that retry is itself no longer a
// transient failure; otherwise the original response is preserved (a flaky
// target should never make a result worse than the first attempt). Slots that
// were not retried are copied through unchanged.
//
// The retry honors the same rate limiter, concurrency, refresh injections, and
// body caps as the original run — it goes through the standard fire path via a
// sub-plan. The OnResponse hook fires for each successful (non-transient) retry
// so --resume/--record see the improved response. retried is the count of
// variants re-issued; improved is how many of those produced a usable result.
func (e *Engine) RetryInconclusive(ctx context.Context, plan Plan, responses []model.Response) (out []model.Response, retried, improved int) {
	out = make([]model.Response, len(responses))
	copy(out, responses)

	// Collect the indices that warrant a retry.
	var idxs []int
	for i := range responses {
		if i >= len(plan.Variants) {
			break
		}
		if IsTransientFailure(&responses[i]) {
			idxs = append(idxs, i)
		}
	}
	if len(idxs) == 0 {
		return out, 0, 0
	}

	// Build a sub-plan of just the retryable variants, preserving order.
	sub := Plan{Variants: make([]model.Variant, 0, len(idxs))}
	for _, i := range idxs {
		sub.Variants = append(sub.Variants, plan.Variants[i])
	}

	// Suppress the OnResponse hook during the bulk run; we fire it manually
	// below only for retries we actually keep, so resume/record never persist a
	// retry we discarded.
	saved := e.OnResponse
	e.OnResponse = nil
	subResponses := e.Run(ctx, sub)
	e.OnResponse = saved

	for j, i := range idxs {
		retried++
		r := subResponses[j]
		if IsTransientFailure(&r) {
			continue // retry no better than the original; keep the first attempt
		}
		out[i] = r
		improved++
		if e.OnResponse != nil {
			e.OnResponse(r, false)
		}
	}
	return out, retried, improved
}
