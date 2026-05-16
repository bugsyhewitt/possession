// Package normalize collapses path identifiers to templates and deduplicates
// CapturedRequests into Endpoints.
package normalize

import (
	"regexp"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// Placeholder is the token written into a templated path in place of an
// identifier-shaped segment.
const Placeholder = "{id}"

// identifierRule decides whether a single path segment looks like a
// machine-generated identifier (and should therefore be replaced with the
// {id} placeholder during templating).
type identifierRule struct {
	name  string
	match func(string) bool
}

var (
	reAllDigits = regexp.MustCompile(`^[0-9]+$`)
	reUUID      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reHex       = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	reB64URL    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// identifierRules is the table-driven set of heuristics that mark a path
// segment as an identifier. Rules are tried in order; first match wins.
var identifierRules = []identifierRule{
	{name: "all-digits", match: func(s string) bool { return reAllDigits.MatchString(s) }},
	{name: "uuid", match: func(s string) bool { return reUUID.MatchString(s) }},
	{name: "mongoid", match: func(s string) bool { return len(s) == 24 && reHex.MatchString(s) }},
	{name: "long-hex", match: func(s string) bool { return len(s) >= 16 && reHex.MatchString(s) }},
	{name: "base64url-ish", match: isBase64URLish},
}

// isBase64URLish returns true for ≥20-char [A-Za-z0-9_-] strings that
// contain mixed case AND/OR digits. Pure-lowercase dictionary words (even
// long ones) are explicitly excluded so that segments like
// `internationalization` are not collapsed.
func isBase64URLish(s string) bool {
	if len(s) < 20 || !reB64URL.MatchString(s) {
		return false
	}
	hasLower, hasUpper, hasDigit := false, false, false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	mixedCase := hasLower && hasUpper
	return mixedCase || hasDigit
}

// IsIdentifierSegment reports whether a single path segment matches any
// known identifier heuristic. Exposed for testing.
func IsIdentifierSegment(seg string) bool {
	if seg == "" {
		return false
	}
	for _, r := range identifierRules {
		if r.match(seg) {
			return true
		}
	}
	return false
}

// TemplatePath replaces identifier-shaped path segments with {id} while
// preserving leading/trailing slashes. Empty segments (e.g. from a
// double slash) are preserved as-is so that the structure of the input is
// not silently altered.
func TemplatePath(p string) string {
	if p == "" {
		return p
	}
	// Split keeping leading/trailing slash semantics.
	leading := strings.HasPrefix(p, "/")
	trailing := strings.HasSuffix(p, "/") && p != "/"
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return p
	}
	parts := strings.Split(trimmed, "/")
	for i, seg := range parts {
		if IsIdentifierSegment(seg) {
			parts[i] = Placeholder
		}
	}
	out := strings.Join(parts, "/")
	if leading {
		out = "/" + out
	}
	if trailing {
		out = out + "/"
	}
	return out
}

// Apply walks a slice of CapturedRequests and fills in each one's
// PathTemplate field based on its URL.Path. It mutates the requests in
// place and returns the same slice for fluent chaining.
func Apply(reqs []*model.CapturedRequest) []*model.CapturedRequest {
	for _, r := range reqs {
		if r == nil || r.URL == nil {
			continue
		}
		r.PathTemplate = TemplatePath(r.URL.Path)
	}
	return reqs
}
