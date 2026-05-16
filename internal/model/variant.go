package model

// Mutation describes a transformation applied to a baseline CapturedRequest
// in order to produce a Variant for replay.
//
// Type and Description are populated by the mutator at generation time
// (Packet 2). Class is populated by the detection stage (Packet 3) and
// maps the mutator type to a finding class (idor | privesc | authn-bypass
// | auth-dependency). Class is empty until detection runs.
type Mutation struct {
	Type        string            // e.g. "strip-auth", "swap-identity", "jwt-alg-none"
	Description string            // human-readable rationale
	Detail      map[string]string // mutation-specific parameters
	Class       string            // populated by detection stage (P3)
}

// Variant is a single replay candidate: a baseline request, the identity it
// will be replayed as, and the mutation applied.
//
// ID is a deterministic 16-hex-char prefix of
// sha256(endpoint_key + mutator + identity_name + canonical_detail_json)
// (see D11). Same inputs ⇒ same ID across runs. Identity may be nil for
// mutators like strip-auth.
type Variant struct {
	ID       string
	Base     *CapturedRequest
	Identity *Identity
	Mutation Mutation
}
