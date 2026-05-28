package model

// Finding is a detected authz issue produced by the Packet-3 evaluator.
//
// One Finding per Variant whose Verdict is `bypass` or `suspected`. Variants
// with `enforced` or `inconclusive` verdicts produce no Finding (but are
// counted in the run summary).
type Finding struct {
	ID         string    `json:"id"`
	Endpoint   *Endpoint `json:"-"`          // serialized separately via EndpointKey
	Variant    *Variant  `json:"-"`          // serialized separately via VariantID
	Class      string    `json:"class"`      // idor | privesc | authn-bypass | auth-dependency
	Verdict    string    `json:"verdict"`    // bypass | suspected
	Confidence float64   `json:"confidence"` // 0..1

	// ConfidenceBand is the categorical BOLA-confidence label derived from
	// Confidence + response-body similarity to the owner baseline:
	//   high   — body near-identical to owner's resource (true BOLA)
	//   medium — partial match / suspected verdict
	//   low    — body diverges from owner despite 2xx (likely error wrapper)
	// See detect.ClassifyConfidenceBand.
	ConfidenceBand string `json:"confidence_band"` // high | medium | low

	Severity string   `json:"severity"` // critical | high | medium | low | info
	ASVS     []string `json:"asvs"`     // e.g. ["v5.0.0-8.2.2"]
	Evidence Evidence `json:"evidence"`

	// Convenience fields for serialization — fully derivable from
	// Endpoint+Variant but flattened so JSON consumers don't need to
	// cross-reference.
	EndpointKey string `json:"endpoint_key"`
	VariantID   string `json:"variant_id"`
	Mutation    string `json:"mutation"`
	Identity    string `json:"identity,omitempty"`
}

// Evidence captures the observed signals that justified a Finding.
//
// Notes is a human-readable list of which signals fired ("similarity 0.94
// >= effThreshold 0.85", "reflectedOwner: alice marker in body", etc.) —
// kept short so Packet 4's reporter can render them inline.
type Evidence struct {
	BaselineStatus  int      `json:"baseline_status"`
	VariantStatus   int      `json:"variant_status"`
	SimilarityScore float64  `json:"similarity"`
	SizeDelta       int      `json:"size_delta"`
	Notes           []string `json:"notes,omitempty"`
}
