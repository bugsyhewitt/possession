package model

// Mutation describes a transformation applied to a baseline CapturedRequest
// in order to produce a Variant for replay.
//
// TODO(packet-2/4): wire concrete mutation types ("strip-auth",
// "swap-identity", "jwt-alg-none", ...). Packet 1 declares the type only.
type Mutation struct {
	Type        string            // e.g. "strip-auth", "swap-identity", "jwt-alg-none"
	Description string            // human-readable rationale
	Detail      map[string]string // mutation-specific parameters
}

// Variant is a single replay candidate: a baseline request, the identity it
// will be replayed as, and the mutation applied.
//
// TODO(packet-2): Variant is constructed by the replay engine.
type Variant struct {
	Base     *CapturedRequest
	Identity *Identity
	Mutation Mutation
}
