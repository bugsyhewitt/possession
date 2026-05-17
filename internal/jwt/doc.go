// Package jwt provides JWT inspection helpers and the malformed-token
// construction primitives used by the JWT mutators in internal/mutate.
//
// Two layers:
//
//   - Detect/Decode: lenient parsing of JWT-shaped strings found in
//     requests (Authorization headers, cookies, JSON body fields). MUST
//     succeed on real-world adversarial inputs including alg=none,
//     missing signatures, and tampered headers — failures here would
//     blind the mutators.
//   - Encode: deliberate construction of malformed tokens for testing.
//     Bypasses golang-jwt/jwt/v5's protections. Isolated in encode.go.
//
// Pure. No network I/O. Deterministic.
package jwt
