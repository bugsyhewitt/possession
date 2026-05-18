// Package model contains the core domain types for possession.
//
// These types are shared across parsing, normalization, replay, and detection
// stages. Packet 1 defines and fully implements the input-side types
// (Identity, RoleMatrix, CapturedRequest, Endpoint) and declares the
// downstream types (Variant, Finding, Evidence) as stubs marked
// // TODO(packet-N).
package model

// Identity is a single authenticated (or anonymous) actor in the role matrix.
// Identities are the subjects we swap into baseline requests in order to
// test access controls. An Identity with Creds == nil represents the
// unauthenticated case ("anon"), used for authn-bypass tests.
type Identity struct {
	Name    string
	Role    string
	Rank    int
	Creds   *Credentials // nil ⇒ no auth
	Refresh *RefreshHook // nil ⇒ no Tier-1 refresh

	// Markers (D20) are optional unique strings identifying this identity's
	// data — email, account id, display name. When present, the detection
	// stage uses them as the strongest IDOR signal: a variant body containing
	// the resource owner's marker is a near-certain bypass. Empty by default
	// for backward compatibility.
	Markers []string

	// FlowName references a named FlowDef in RoleMatrix.Flows. When set,
	// the replay engine runs the flow before this identity's variants to
	// establish a live session (Tier-2, P7). Mutually exclusive with Refresh
	// at the per-identity level; if both are set, the flow takes precedence.
	FlowName string
}

// Credentials groups the static authentication material attached to an
// Identity. Any combination of cookies, headers, bearer, or basic may be
// present; at least one must be set when Credentials is non-nil.
type Credentials struct {
	Cookies map[string]string
	Headers map[string]string
	Bearer  string
	Basic   *BasicAuth
}

// BasicAuth holds HTTP basic-auth credentials.
type BasicAuth struct {
	Username string
	Password string
}

// RefreshHook describes a Tier-1 dynamic credential refresh: issue a request
// against the target, extract a value from the response, and inject it into
// subsequent replays. Packet 1 declares it; Packet 2 executes it.
type RefreshHook struct {
	Request RawRequest
	Extract []Extraction
}

// RawRequest is a minimal request descriptor used by refresh hooks and other
// configuration-driven HTTP issuance points.
type RawRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// Extraction defines how to pull a value out of a refresh response and where
// to inject it into subsequent requests.
type Extraction struct {
	Name   string
	From   string // body-json | body-regex | header | cookie
	Expr   string
	Inject Injection
}

// Injection specifies where an extracted value should be placed in a request.
type Injection struct {
	Into string // header | cookie | query | body-json
	Key  string
}
