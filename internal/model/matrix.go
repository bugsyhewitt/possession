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
