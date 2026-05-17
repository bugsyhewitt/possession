package model

import "time"

// RunResult is the aggregate scan output Packet 4 reporters render
// from. It is built by the cli/scan command after detection completes
// and serialized verbatim by the JSON reporter. Other reporters
// (SARIF, human) consume it as a Go struct and produce their own
// formats.
//
// This type is purely additive (Gate D). Existing consumers that read
// the legacy `resultDoc` JSON shape continue to work because we keep
// the same on-the-wire field names and order; RunResult is a
// superset wrapper that adds typed accessors for the reporter layer.
type RunResult struct {
	// Run captures the scan-level metadata: target URL, settings, timing.
	Run RunMeta `json:"run"`

	// Endpoints is one entry per deduplicated logical endpoint, including
	// owner attribution and typed notes (D29).
	Endpoints []EndpointReport `json:"endpoints"`

	// Results is the (variant, response) audit trail. One entry per
	// fired variant, in plan order.
	Results []ResultEntry `json:"results"`

	// Findings is the deduplicated set of bypass/suspected verdicts that
	// passed any --min-confidence filter. Always sorted by (severity,
	// confidence desc, endpoint key).
	Findings []Finding `json:"findings"`

	// Summary is the verdict/class/severity rollup.
	Summary RunSummary `json:"summary"`

	// AttributionWarnings carries owner-attribution ambiguities raised
	// during detection (e.g. "two identities matched this capture's
	// bearer token"). Empty when clean.
	AttributionWarnings []string `json:"attribution_warnings,omitempty"`
}

// RunMeta is the scan-level header — target, totals, settings, timing.
type RunMeta struct {
	BaseURL         string            `json:"base_url,omitempty"`
	TotalEndpoints  int               `json:"total_endpoints"`
	TotalVariants   int               `json:"total_variants"`
	GeneratedTotal  int               `json:"variants_generated_before_cap"`
	Capped          bool              `json:"capped"`
	Settings        RunSetView        `json:"settings"`
	Start           time.Time         `json:"start"`
	End             time.Time         `json:"end"`
	BaselineSamples int               `json:"baseline_samples"`
	Baselines       map[string]string `json:"baselines,omitempty"`
	ToolVersion     string            `json:"tool_version,omitempty"`
}

// RunSetView is the projection of RunSettings used in JSON output.
type RunSetView struct {
	RatePerHost   float64 `json:"rate_per_host"`
	Concurrency   int     `json:"concurrency"`
	MaxVariants   int     `json:"max_variants"`
	MaxBody       int64   `json:"max_body"`
	Timeout       string  `json:"timeout"`
	NoLimit       bool    `json:"no_limit"`
	Insecure      bool    `json:"insecure"`
	MinConfidence float64 `json:"min_confidence"`
}

// VariantView is the serialization-friendly projection of a Variant.
type VariantView struct {
	ID          string            `json:"id"`
	EndpointKey string            `json:"endpoint_key"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Mutation    string            `json:"mutation"`
	Class       string            `json:"class,omitempty"`
	Identity    string            `json:"identity,omitempty"`
	Detail      map[string]string `json:"detail,omitempty"`
}

// ResultEntry pairs a VariantView with its Response.
type ResultEntry struct {
	Variant  VariantView `json:"variant"`
	Response Response    `json:"response"`
}

// EndpointReport is the per-endpoint summary including calibration and
// typed notes. The Notes field is an interface-shaped slice so the
// detect package's typed enum (EndpointNote) can be carried through
// without cyclic imports; reporters type-assert as needed.
type EndpointReport struct {
	Key                string         `json:"key"`
	Method             string         `json:"method"`
	Host               string         `json:"host"`
	PathTemplate       string         `json:"path_template"`
	Owner              string         `json:"owner,omitempty"`
	OwnerAttribution   string         `json:"owner_attribution,omitempty"`
	BaselineSamples    int            `json:"baseline_samples"`
	BaselineStatus     int            `json:"baseline_status"`
	Stability          float64        `json:"stability"`
	EffThreshold       float64        `json:"eff_threshold"`
	Noisy              bool           `json:"noisy"`
	CalibrationSkipped bool           `json:"calibration_skipped"`
	BaselineFailed     bool           `json:"baseline_failed"`
	Notes              []EndpointNote `json:"notes,omitempty"`
}

// EndpointNote is the model-package mirror of detect.EndpointNote.
// We carry the typed struct through model so reporters don't have to
// import the detect package (which imports mutate, which would cycle).
type EndpointNote struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Payload map[string]string `json:"payload,omitempty"`
}

// RunSummary is the rollup the reporter footer renders.
type RunSummary struct {
	Verdicts       map[string]int `json:"verdicts"`
	NoisyEndpoints int            `json:"noisy_endpoints"`
	ByClass        map[string]int `json:"by_class"`
	BySeverity     map[string]int `json:"by_severity"`
	TotalFindings  int            `json:"total_findings"`
}
