package model

import "time"

// RoleMatrix is the user-authored configuration that drives a scan.
// It captures: who can act (Identities), what we target (Target), which
// endpoints are in/out of scope (Scope), and how aggressively we replay
// (Settings).
type RoleMatrix struct {
	Version    string
	Target     TargetConfig
	Identities []Identity
	Scope      ScopeConfig
	Settings   RunSettings
	Assertions []Assertion         // optional declarative access expectations (P6)
	Flows      map[string]FlowDef  // optional named flow definitions (P7)
}

// FlowDef is a named, ordered sequence of HTTP steps an identity runs to
// establish session state before its variants are fired. Packet 7 / D41.
type FlowDef struct {
	Name  string
	Steps []FlowStep
}

// FlowStep is one request+extract step within a flow.
type FlowStep struct {
	Name    string
	Request *RawRequest     // if non-nil, issue this request
	Extract []FlowExtraction
}

// FlowExtraction pulls a named value from a step's response and makes it
// available for {name} interpolation in later steps and for injection into
// variant requests.
type FlowExtraction struct {
	Name     string
	From     string    // body-json | body-regex | header | cookie
	Expr     string
	Volatile bool      // if true, re-run this step per replay batch (nonce/CSRF)
	Inject   Injection // optional: where to inject the value into variant requests
}

// TargetConfig describes the system under test at a coarse level.
type TargetConfig struct {
	BaseURL string
	JWT     *JWTTargetConfig // optional — enables key-dependent JWT attacks (P5)
}

// JWTTargetConfig holds optional key material for deep JWT attacks.
// Absent ⇒ attacks that require key material are skipped with a note.
type JWTTargetConfig struct {
	// PublicKeyPEM is the PEM-encoded RSA or EC public key used for the
	// alg-confusion attack (re-sign RS256/ES256 token with pubkey as HMAC secret).
	PublicKeyPEM string
	// JWKSUrl is the server's JWKS endpoint URL, used to fetch its public key.
	JWKSUrl string
}

// ScopeConfig holds glob patterns that include/exclude request paths from
// the scan.
type ScopeConfig struct {
	Include []string
	Exclude []string
}

// Assertion defines the expected access model for one endpoint pattern.
// The Expect map keys are role names; values are "allow" or "deny".
type Assertion struct {
	// Endpoint is a "METHOD /path/glob" pattern, e.g. "GET /api/admin/**".
	Endpoint string
	// Expect maps role → "allow" | "deny".
	Expect map[string]string
}

// AssertionOutcome is the typed result of evaluating one assertion.
type AssertionOutcome int

const (
	AssertionMatch   AssertionOutcome = iota // response matches expectation
	AssertionBypass                          // access granted but deny expected
	AssertionBroken                          // access denied but allow expected
	AssertionUnknown                         // no assertion covers this pair
)

// RunSettings controls replay engine behavior (Packet 2+).
type RunSettings struct {
	RatePerHost     float64
	Concurrency     int
	Timeout         time.Duration
	FollowRedirects bool

	// MaxVariants caps total variant generation (D11). 0 ⇒ engine default.
	MaxVariants int
	// MaxBody caps response body retention in bytes (D12). 0 ⇒ engine default.
	MaxBody int64
	// Insecure disables TLS verification (lab-only, loud warning).
	Insecure bool
	// NoLimit disables the per-host rate limiter (loud warning).
	NoLimit bool
}
