package mutate

// JWT mutator tuning constants. Centralized so calibration is a one-file
// diff. Mirrors detect/tuning.go's role but stays in the mutate package
// because detect cannot be imported here (would form a cycle).

// WeakHMACSecrets is the list of secrets jwt-resign-weak-key tries.
// Deliberately short and conventional — long lists belong in a v1.1
// dedicated cracker; this list catches "we forgot to change the
// default" and "the secret is the product name". Order is deterministic
// (declaration order) per D11.
var WeakHMACSecrets = []string{
	"secret",
	"password",
	"changeme",
	"key",
	"jwt",
	"admin",
	"",
	"possession",
}

// JWTClaimClassByName maps a high-value JWT claim name to the finding
// class jwt-claim-tamper emits when the variant flips that claim:
// privesc when the claim affects role/scope/permission, authn-bypass
// when it affects identity, idor for tenant boundaries (dormant, D31).
var JWTClaimClassByName = map[string]string{
	"role":   "privesc",
	"admin":  "privesc",
	"scope":  "privesc",
	"groups": "privesc",
	"sub":    "authn-bypass",
	"uid":    "authn-bypass",
	"user":   "authn-bypass",
	"email":  "authn-bypass",
	"tenant": "idor",
}

// JWTEscalatedValues is the value jwt-claim-tamper substitutes when
// escalating a privilege claim. Identity-spoofing claims are not in
// this map — they get values from other matrix identities' Markers
// at generation time.
var JWTEscalatedValues = map[string]any{
	"role":   "admin",
	"admin":  true,
	"scope":  "admin",
	"groups": "admin",
}
