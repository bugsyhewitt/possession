package jwt

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// TokenLocation describes where a JWT was found in a CapturedRequest and
// gives the decoded header+claims plus the raw token bytes so a mutator
// can splice a mutated version back in.
type TokenLocation struct {
	Where  string         // "header" | "cookie" | "body"
	Key    string         // header name, cookie name, or JSON dotted path
	Raw    string         // the original token string
	Header map[string]any // decoded header (may be nil if undecodable)
	Claims map[string]any // decoded claims (may be nil if undecodable)
	Sig    string         // the third segment (may be empty)
}

// jwtShape matches three base64url segments separated by dots. Lenient
// length floor to avoid matching ordinary tokens like "ab.cd.ef" — JWT
// headers and claims are JSON objects that are at minimum 16 chars
// after base64 encoding.
var jwtShape = regexp.MustCompile(`[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]*`)

// jsonBodyTokenFields are the JSON body keys we treat as token-bearing.
// Matched case-insensitively against top-level keys only.
var jsonBodyTokenFields = []string{
	"access_token",
	"id_token",
	"jwt",
	"token",
}

// Detect returns every JWT-shaped string found in req's Authorization
// header, cookies, and (for JSON bodies) the top-level token fields.
// Empty slice when none found. The slice order is deterministic:
// headers (sorted), cookies (sorted), body fields (sorted by key).
func Detect(req *model.CapturedRequest) []TokenLocation {
	if req == nil {
		return nil
	}
	var out []TokenLocation

	// 1) Authorization header: Bearer <jwt>
	if auth := req.Headers.Get("Authorization"); auth != "" {
		if tok, ok := bearerJWT(auth); ok {
			h, c, s, err := Decode(tok)
			if err == nil {
				out = append(out, TokenLocation{Where: "header", Key: "Authorization", Raw: tok, Header: h, Claims: c, Sig: s})
			}
		}
	}

	// 2) Any other auth-like header whose value LOOKS like a bare JWT.
	headerNames := make([]string, 0, len(req.Headers))
	for k := range req.Headers {
		if strings.EqualFold(k, "Authorization") {
			continue
		}
		headerNames = append(headerNames, k)
	}
	sort.Strings(headerNames)
	for _, k := range headerNames {
		v := req.Headers.Get(k)
		if !looksLikeJWT(v) {
			continue
		}
		h, c, s, err := Decode(v)
		if err != nil {
			continue
		}
		out = append(out, TokenLocation{Where: "header", Key: k, Raw: v, Header: h, Claims: c, Sig: s})
	}

	// 3) Cookies whose value looks like a JWT.
	cookieNames := make([]string, 0, len(req.Cookies))
	for _, ck := range req.Cookies {
		if ck == nil {
			continue
		}
		cookieNames = append(cookieNames, ck.Name)
	}
	sort.Strings(cookieNames)
	for _, name := range cookieNames {
		for _, ck := range req.Cookies {
			if ck == nil || ck.Name != name {
				continue
			}
			if !looksLikeJWT(ck.Value) {
				continue
			}
			h, c, s, err := Decode(ck.Value)
			if err != nil {
				continue
			}
			out = append(out, TokenLocation{Where: "cookie", Key: ck.Name, Raw: ck.Value, Header: h, Claims: c, Sig: s})
			break
		}
	}

	// 4) Top-level JSON body fields.
	if isJSON(req.ContentType, req.Headers) && len(req.Body) > 0 {
		var m map[string]any
		if err := json.Unmarshal(req.Body, &m); err == nil {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if !isTokenField(k) {
					continue
				}
				s, ok := m[k].(string)
				if !ok || !looksLikeJWT(s) {
					continue
				}
				h, c, sg, err := Decode(s)
				if err != nil {
					continue
				}
				out = append(out, TokenLocation{Where: "body", Key: k, Raw: s, Header: h, Claims: c, Sig: sg})
			}
		}
	}

	return out
}

func bearerJWT(authHeader string) (string, bool) {
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(authHeader[len("Bearer "):])
	if !looksLikeJWT(tok) {
		return "", false
	}
	return tok, true
}

// looksLikeJWT returns true when s is shaped like a JWT AND its header
// segment decodes to a JSON object that includes an "alg" field. Two-
// stage check avoids matching arbitrary three-dotted base64 blobs.
func looksLikeJWT(s string) bool {
	if !jwtShape.MatchString(s) {
		return false
	}
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return false
	}
	hb, err := b64urlDecode(parts[0])
	if err != nil {
		return false
	}
	var hdr map[string]any
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return false
	}
	_, ok := hdr["alg"]
	return ok
}

// Decode parses a JWT into its decoded header, decoded claims, and raw
// signature segment. Lenient: missing or empty signature is NOT an
// error, alg=none is NOT an error. Returns error only when the token is
// not three dot-separated segments or the header/claims segments don't
// base64-decode to valid JSON objects.
//
// We deliberately do NOT use jwt.Parser — its lenient parsing options
// changed across v5 minor versions and we want a stable surface.
func Decode(token string) (header, claims map[string]any, sig string, err error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return nil, nil, "", errMalformed
	}
	if len(parts) == 2 {
		parts = append(parts, "")
	}
	hb, err := b64urlDecode(parts[0])
	if err != nil {
		return nil, nil, "", err
	}
	cb, err := b64urlDecode(parts[1])
	if err != nil {
		return nil, nil, "", err
	}
	if err := jsonDecodeStrict(hb, &header); err != nil {
		return nil, nil, "", err
	}
	if err := jsonDecodeStrict(cb, &claims); err != nil {
		// Claims that aren't a JSON object (e.g. a string) — still
		// return the header so callers can mutate alg; mark claims nil.
		claims = nil
	}
	return header, claims, parts[2], nil
}

func jsonDecodeStrict(b []byte, dst *map[string]any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return dec.Decode(dst)
}

func isJSON(ct string, h http.Header) bool {
	if strings.Contains(strings.ToLower(ct), "json") {
		return true
	}
	if h != nil {
		if strings.Contains(strings.ToLower(h.Get("Content-Type")), "json") {
			return true
		}
	}
	return false
}

func isTokenField(name string) bool {
	low := strings.ToLower(name)
	for _, f := range jsonBodyTokenFields {
		if low == f {
			return true
		}
	}
	return false
}

// errMalformed is returned from Decode when the token does not have at
// least two dot-separated segments. Kept as a package-level sentinel so
// callers can check via errors.Is if they care.
var errMalformed = jwtError("malformed token: expected at least two segments")

type jwtError string

func (e jwtError) Error() string { return string(e) }
