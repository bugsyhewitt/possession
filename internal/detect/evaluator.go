package detect

import "github.com/bugsyhewitt/possession/internal/model"

// Verdict labels (D19).
const (
	VerdictBypass       = "bypass"
	VerdictSuspected    = "suspected"
	VerdictEnforced     = "enforced"
	VerdictInconclusive = "inconclusive"
)

// VariantResponse pairs a Variant with its Response.
type VariantResponse struct {
	Variant  *model.Variant
	Response *model.Response
}

// EvalContext is the per-endpoint input to an Evaluator. The orchestrator
// builds one EvalContext per endpoint after calibration completes.
type EvalContext struct {
	Endpoint         *model.Endpoint
	Owner            *model.Identity
	BaselineSamples  []*model.Response
	Calibration      CalibrationResult
	VariantResponses []VariantResponse
	Matrix           *model.RoleMatrix
}

// EvalResult bundles the per-variant verdicts and findings an evaluator
// produced for one endpoint. Verdicts is parallel to ctx.VariantResponses
// and always populated; Findings is the subset that resulted in a
// reportable finding (bypass or suspected).
type EvalResult struct {
	Verdicts []VariantVerdict
	Findings []model.Finding
}

// VariantVerdict is the per-variant verdict produced by an evaluator,
// kept independently from Finding because enforced/inconclusive variants
// still need to be counted in the run summary.
type VariantVerdict struct {
	Variant    *model.Variant
	Response   *model.Response
	Verdict    string
	Confidence float64
	Notes      []string
}

// Evaluator turns a context (endpoint + baseline + variants) into a set
// of verdicts and findings. The interface (D16) is deliberately wide
// enough that a future AssertionEvaluator (AuthMatrix-style declarative
// expectations) can implement it alongside ComparativeEvaluator without
// rework.
type Evaluator interface {
	Name() string
	Evaluate(ctx EvalContext) EvalResult
}
