package model

// Finding is a detected authz issue. Packet 3 implements the evaluator that
// produces these.
//
// TODO(packet-3): wire production by Evaluator.
type Finding struct {
	ID         string
	Endpoint   *Endpoint
	Variant    *Variant
	Class      string   // idor | privesc | authn-bypass | auth-dependency
	Confidence float64  // 0..1
	Severity   string   // critical | high | medium | low | info
	ASVS       []string // ASVS control references
	Evidence   Evidence
}

// Evidence captures the observed signals that justified a Finding.
//
// TODO(packet-3): populated by Evaluator comparing baseline vs. variant.
type Evidence struct {
	BaselineStatus  int
	VariantStatus   int
	SimilarityScore float64
	SizeDelta       int
	Notes           []string
}
