// Package detect is possession's detection evaluator. It consumes the
// (Variant, Response) pairs produced by Packet 2's replay engine and emits
// Findings.
//
// All thresholds, weights, regexes, and string lists used by detection
// live in this file (D23). Every constant below is a calibration starting
// point — they were chosen against the integration corpus in
// internal/detect/corpus_test.go to give zero false positives on
// `secureapp` while catching every wrong on `vulnapp`. If you change one,
// re-run `go test ./internal/detect/...` and treat any new false positive
// or false negative as a calibration regression.
package detect

import "regexp"

// ─── baseline calibration (D18) ───────────────────────────────────────

const (
	// DefaultBaselineSamples is the default value for --baseline-samples.
	// Clamped to [MinBaselineSamples, MaxBaselineSamples].
	DefaultBaselineSamples = 3
	MinBaselineSamples     = 1
	MaxBaselineSamples     = 10

	// NoisyEndpointThreshold: if mean pairwise baseline similarity falls
	// below this, the endpoint is "noisy" and verdicts on it are capped
	// at `suspected` (a noisy endpoint can't be a confident bypass).
	NoisyEndpointThreshold = 0.70

	// SimilarityMargin is subtracted from observed stability to produce
	// the per-endpoint effThreshold. Gives a small cushion before we
	// flag a variant as similar enough to be a bypass.
	SimilarityMargin = 0.05

	// MinThreshold is the floor for effThreshold so a noisy-but-not-
	// noisy-enough endpoint can't make a trivially-low threshold.
	MinThreshold = 0.5

	// DefaultThreshold is used when N=1 (calibration skipped).
	DefaultThreshold = 0.90
)

// ─── verdict ladder (§4.4) ────────────────────────────────────────────

const (
	// SuspectLow is the floor for the `suspected` band. Below this,
	// similarity is too low to suspect bypass and we call enforced.
	SuspectLow = 0.50

	// BaseHigh is the base confidence for a `bypass` verdict from
	// branch 8 (high similarity, not error-shaped, not noisy). Final
	// confidence scales up from BaseHigh by how far similarity exceeds
	// the threshold and by sizeRatio, capped at MaxBypassConfidence.
	BaseHigh = 0.80

	// MaxBypassConfidence is the cap for any scaled bypass confidence.
	MaxBypassConfidence = 0.95

	// ReflectedOwnerConfidence is the (very high) confidence for a
	// reflectedOwner=true bypass — the variant body literally contains
	// the resource owner's marker. Decisive signal.
	ReflectedOwnerConfidence = 0.95

	// ReflectedActorConfidence is the (very low) confidence cap for a
	// reflectedActor=true response — server returned only the acting
	// identity's own data, which is correct behaviour.
	ReflectedActorConfidence = 0.10

	// AmbiguousPenalty multiplies the final confidence when the
	// underlying status was 3xx (ambiguous). 3xx responses get the
	// benefit of doubt but not full credit.
	AmbiguousPenalty = 0.6

	// SuspectedConfMin / SuspectedConfMax bound the `suspected` band
	// (branch 9). Confidence in this band scales linearly with
	// similarity within [SuspectLow, effThreshold).
	SuspectedConfMin = 0.40
	SuspectedConfMax = 0.65

	// LowConfidence is the floor used for branches that emit no finding
	// but still report a numeric confidence (so callers can rank).
	LowConfidence = 0.05
)

// ─── similarity (§4.3) ────────────────────────────────────────────────

const (
	// ShingleSize is the word n-gram size for the token-shingle Jaccard
	// similarity. 4 is the standard near-dup default — small enough to
	// match short bodies, large enough that random word sequences don't
	// overlap.
	ShingleSize = 4
)

// ─── body normalization (§4.2) ────────────────────────────────────────

// VolatileJSONKeys are JSON keys whose VALUES are blanked during
// normalization. Match is case-insensitive (lower-cased key string is
// checked against each entry; any substring match blanks the value).
// Keep this list short — over-aggressive blanking hides bypass evidence.
var VolatileJSONKeys = []string{
	"csrf",
	"token",
	"nonce",
	"timestamp",
	"_at",
	"_time",
	"date",
	"expires",
	"requestid",
	"traceid",
	"correlationid",
	"sessionid",
	"etag",
	"lastmodified",
}

// HTML normalization regexes. Each strips a class of volatile content
// from text/HTML bodies so similarity scoring isn't fooled by per-request
// timestamps, csrf tokens, etc.
var (
	HTMLCSRFInput = regexp.MustCompile(`(?i)<input[^>]+name=["']?(csrf|_token|authenticity_token|xsrf)[^>]*>`)
	HTMLCSRFMeta  = regexp.MustCompile(`(?i)<meta[^>]+name=["']?(csrf-token|csrf|xsrf)[^>]*>`)
	HTMLISO8601   = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b`)
	HTMLLongHex   = regexp.MustCompile(`\b[0-9a-fA-F]{16,}\b`)
	HTMLUUID      = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)
	HTMLWhitespace = regexp.MustCompile(`\s+`)
)

// ─── errorSignature (§4.3) ────────────────────────────────────────────

// ErrorSignaturePatterns match bodies that look like denial pages even
// when delivered with a 2xx status. Case-insensitive substring match
// against the normalized body. Matched ⇒ statusClass treated as denied.
var ErrorSignaturePatterns = []string{
	"access denied",
	"forbidden",
	"not authorized",
	"unauthorized",
	"permission denied",
	"please log in",
	"please sign in",
	"login required",
	"authentication required",
	"you do not have permission",
	"you don't have permission",
}

// ErrorSignatureJSONShape matches JSON bodies that are error-shaped:
// {"error": ...} or {"message": ..., "status": 4xx} etc. Compiled once.
var ErrorSignatureJSONShape = regexp.MustCompile(
	`(?is)^\s*\{[^{}]*"(?:error|errors|errorCode|errorMessage)"\s*:`,
)

// LoginRedirectHints are substring matches against a 3xx Location header
// to reclassify the redirect as a denial (auth wall).
var LoginRedirectHints = []string{
	"/login",
	"/signin",
	"/sign-in",
	"/auth",
	"/sso",
	"/oauth",
	"/oauth2",
}

// ─── ASVS 5.0 (D22) ───────────────────────────────────────────────────

// ASVSByClass maps a finding Class to its ASVS v5.0.0 control IDs.
// Used by detect/finding.go. Fixed mapping per §5.3 of the Packet-3 brief.
var ASVSByClass = map[string][]string{
	"authn-bypass":       {"v5.0.0-8.3.1"},
	"idor":               {"v5.0.0-8.2.2"},
	"idor-cross-tenant":  {"v5.0.0-8.4.1", "v5.0.0-8.2.2"},
	"privesc":            {"v5.0.0-8.2.1"},
	"auth-dependency":    {"v5.0.0-8.3.1"},
}

// SeverityByClass is the BASE severity for `bypass` verdicts. `suspected`
// verdicts drop one notch via DowngradeSeverity below.
var SeverityByClass = map[string]string{
	"authn-bypass":      "critical",
	"idor":              "high",
	"idor-cross-tenant": "critical",
	"privesc":           "high",
	"auth-dependency":   "low",
}

// SeverityOverrideByMutator pins a fixed base severity for specific
// mutator types, overriding the class-derived SeverityByClass value.
//
// The --jwt-attack mutator forges alg:none and blank-secret tokens. These
// are authn-bypass-class findings, but we deliberately rate them HIGH
// rather than the class default (critical): the variant proves the
// verifier *can* be bypassed, but the practical impact depends on what
// the forged identity can reach — so HIGH keeps them prominent without
// flooding the critical band that strip-auth occupies. Suspected verdicts
// still drop one notch via DowngradeSeverity.
var SeverityOverrideByMutator = map[string]string{
	"jwt-attack-none":         "high",
	"jwt-attack-blank-secret": "high",
}

// DowngradeSeverity maps a `bypass` severity to its `suspected`
// counterpart (critical→high, high→medium, low→info).
var DowngradeSeverity = map[string]string{
	"critical": "high",
	"high":     "medium",
	"medium":   "low",
	"low":      "info",
}

// ─── mutator → finding class mapping (§5.2) ───────────────────────────

// MutatorClass returns the canonical finding Class for a mutator's
// Type field. Under D30 mutators set Class at generation time; this
// helper is the fallback path for callers building variants directly
// (e.g. baseline-self in scan.go, tests).
//
// JWT mutators (P4) generally set their own Class because it depends on
// the specific mutation (e.g. jwt-claim-tamper with role/admin claims
// is privesc, with sub/email claims is authn-bypass). The defaults below
// are the bypass-shaped fallback for tokens with no contextual claim.
func MutatorClass(mutatorType string) string {
	switch mutatorType {
	case "strip-auth":
		return "authn-bypass"
	case "swap-identity", "swap-object":
		return "idor"
	case "downgrade-role":
		return "privesc"
	case "drop-cookie", "strip-token":
		return "auth-dependency"
	case "jwt-alg-none", "jwt-sig-strip", "jwt-resign-weak-key":
		return "authn-bypass"
	case "jwt-attack-none", "jwt-attack-blank-secret":
		return "authn-bypass"
	case "jwt-claim-tamper":
		return "privesc" // fallback; mutator sets the per-variant class
	case "jwt-alg-confusion", "jwt-kid-injection", "jwt-jwks-spoof":
		return "authn-bypass"
	case "jwt-hmac-crack":
		return "privesc"
	default:
		return ""
	}
}

// JWT tuning constants live in internal/mutate/jwt_tuning.go to avoid
// an import cycle (detect imports mutate for the auth-component
// heuristic, so mutate cannot import detect).

// ─── assertion evaluator (P6) ─────────────────────────────────────────

const (
	// AssertionBypassConfidence is the confidence for an assertion-derived
	// bypass finding. High because the expectation is explicit — the
	// evaluator doesn't need to infer from body similarity.
	AssertionBypassConfidence = 0.97

	// AssertionBrokenDenyConfidence is the confidence for a broken-deny
	// finding (access denied but allow expected). Low/info severity to
	// distinguish it from a real bypass.
	AssertionBrokenDenyConfidence = 0.50
)
