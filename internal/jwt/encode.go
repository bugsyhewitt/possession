// This file deliberately constructs malformed JWTs for security testing.
// It bypasses the protections golang-jwt/jwt provides (alg validation,
// signature verification, header consistency). Do not use these helpers
// outside this package or outside JWT-mutator code paths.
//
// The intent is to produce the exact byte sequences a real attacker
// would send — including alg=none tokens, stripped signatures, claim-
// tampered bodies, and tokens re-signed with weak HMAC secrets — so the
// scanner can probe whether the target's verifier rejects them.

package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
)

// b64url encodes per RFC 7515: base64 URL without padding.
func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// b64urlDecode is the inverse, lenient about padding presence.
func b64urlDecode(s string) ([]byte, error) {
	// Accept both padded and unpadded; some captured tokens have padding.
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}

// marshalSorted JSON-encodes m with sorted top-level keys. Determinism
// matters because the variant ID is hashed off this output — same claims
// must produce the same bytes across runs.
func marshalSorted(m map[string]any) ([]byte, error) {
	if m == nil {
		return []byte("{}"), nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		// Use json.Marshal for the key+value so escaping matches the std
		// library exactly.
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		vb, err := json.Marshal(m[k])
		if err != nil {
			return nil, err
		}
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	b.WriteByte('}')
	return []byte(b.String()), nil
}

// Encode assembles a JWT from the given header/claims/signature, base64-
// url-encoding each segment per RFC 7515 and joining with dots. sig is
// the raw signature bytes (may be empty for alg=none / sig-strip).
//
// The header is NOT cross-checked against the signature — that is the
// whole point of this constructor: the mutator wants to emit invalid
// combinations on purpose.
func Encode(header, claims map[string]any, sig string) (string, error) {
	hb, err := marshalSorted(header)
	if err != nil {
		return "", err
	}
	cb, err := marshalSorted(claims)
	if err != nil {
		return "", err
	}
	out := b64url(hb) + "." + b64url(cb) + "."
	if sig != "" {
		out += sig
	}
	return out, nil
}

// SignHS256 produces the base64url-encoded HMAC-SHA256 signature over
// the encoded header+claims using the provided secret. Used by
// jwt-resign-weak-key.
func SignHS256(encodedHeader, encodedClaims, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(encodedHeader + "." + encodedClaims))
	return b64url(h.Sum(nil))
}

// EncodeWithHS256 is the convenience path: build header+claims, sign
// with HS256 + secret, return the assembled token.
func EncodeWithHS256(header, claims map[string]any, secret string) (string, error) {
	// Ensure header alg matches the signing path so the resulting token
	// is well-formed (alg=HS256). Mutator may override alg via the map
	// before calling this — in which case the signature still uses HMAC
	// but the declared alg may differ. That's intentional.
	if header == nil {
		header = map[string]any{}
	}
	if _, ok := header["alg"]; !ok {
		header["alg"] = "HS256"
	}
	if _, ok := header["typ"]; !ok {
		header["typ"] = "JWT"
	}
	hb, err := marshalSorted(header)
	if err != nil {
		return "", err
	}
	cb, err := marshalSorted(claims)
	if err != nil {
		return "", err
	}
	eh := b64url(hb)
	ec := b64url(cb)
	sig := SignHS256(eh, ec, secret)
	return eh + "." + ec + "." + sig, nil
}
