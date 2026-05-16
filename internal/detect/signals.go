package detect

import (
	"net/http"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// StatusClass categorizes an HTTP status into one of four buckets used by
// the verdict ladder.
type StatusClass int

const (
	StatusSuccess   StatusClass = iota // 2xx
	StatusDenied                       // 401/403/most 4xx, or 3xx pointing at login
	StatusError                        // 429/5xx or transport error
	StatusAmbiguous                    // 3xx that doesn't look like login
)

// ClassifyStatus inspects a Response and returns its StatusClass. A
// transport error (resp.Err != "") is treated as StatusError. A 3xx is
// reclassified as StatusDenied if its Location header points at a login
// or SSO endpoint per LoginRedirectHints.
func ClassifyStatus(resp *model.Response) StatusClass {
	if resp == nil {
		return StatusError
	}
	if resp.Err != "" {
		return StatusError
	}
	s := resp.Status
	switch {
	case s >= 200 && s < 300:
		return StatusSuccess
	case s == http.StatusTooManyRequests || s >= 500:
		return StatusError
	case s >= 300 && s < 400:
		loc := ""
		if resp.Headers != nil {
			loc = resp.Headers.Get("Location")
		}
		low := strings.ToLower(loc)
		for _, hint := range LoginRedirectHints {
			if strings.Contains(low, hint) {
				return StatusDenied
			}
		}
		return StatusAmbiguous
	case s >= 400 && s < 500:
		return StatusDenied
	default:
		return StatusError
	}
}

// Similarity returns a [0,1] score for two normalized bodies using
// 4-gram word-shingle Jaccard. Identical inputs return 1.0; fully
// disjoint inputs return 0.0. Degenerate case: when both bodies have
// fewer than ShingleSize words, falls back to exact string equality
// (returning 1.0 if equal, 0.0 otherwise) so a tiny shared body still
// scores 1.0.
func Similarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if a == "" || b == "" {
		return 0.0
	}
	sa := shingles(a, ShingleSize)
	sb := shingles(b, ShingleSize)
	if len(sa) == 0 || len(sb) == 0 {
		if a == b {
			return 1.0
		}
		return 0.0
	}
	// Jaccard
	var inter int
	for sh := range sa {
		if _, ok := sb[sh]; ok {
			inter++
		}
	}
	union := len(sa) + len(sb) - inter
	if union == 0 {
		return 0.0
	}
	return float64(inter) / float64(union)
}

// shingles splits s into whitespace-delimited tokens and produces the
// set of word n-grams of size n. Returns an empty set if s has fewer
// than n tokens.
func shingles(s string, n int) map[string]struct{} {
	if n <= 0 {
		return nil
	}
	tokens := strings.Fields(s)
	if len(tokens) < n {
		return nil
	}
	out := make(map[string]struct{}, len(tokens)-n+1)
	for i := 0; i+n <= len(tokens); i++ {
		out[strings.Join(tokens[i:i+n], " ")] = struct{}{}
	}
	return out
}

// SizeRatio returns min(len(a),len(b)) / max(len(a),len(b)) on the
// normalized bodies. Both empty ⇒ 1.0. Used as a scaling factor for
// bypass confidence (huge size mismatch between baseline and variant
// reduces confidence even at high token-similarity).
func SizeRatio(a, b string) float64 {
	la, lb := len(a), len(b)
	if la == 0 && lb == 0 {
		return 1.0
	}
	if la == 0 || lb == 0 {
		return 0.0
	}
	mn, mx := la, lb
	if lb < la {
		mn, mx = lb, la
	}
	return float64(mn) / float64(mx)
}

// ErrorSignature reports true if body looks like a denial page even when
// the HTTP status is 2xx. Lower-cased substring match against
// ErrorSignaturePatterns plus a JSON-shape regex check.
func ErrorSignature(normalizedBody string) bool {
	if normalizedBody == "" {
		return false
	}
	low := strings.ToLower(normalizedBody)
	for _, pat := range ErrorSignaturePatterns {
		if strings.Contains(low, pat) {
			return true
		}
	}
	if ErrorSignatureJSONShape.MatchString(normalizedBody) {
		return true
	}
	return false
}

// ReflectedOwner reports true if the variant body contains any marker
// belonging to the resource owner (the identity who originally made the
// captured request). Markers are exact-substring matched on the raw
// (non-normalized) body — normalization could blank out the very strings
// we're looking for.
func ReflectedOwner(rawBody []byte, owner *model.Identity) bool {
	return hasAnyMarker(rawBody, owner)
}

// ReflectedActor reports true if the variant body contains any marker
// belonging to the acting identity (the identity the variant was
// replayed as) AND does NOT contain the owner's marker. This is the
// "server returned only the caller's own data" benign signal.
func ReflectedActor(rawBody []byte, actor, owner *model.Identity) bool {
	if !hasAnyMarker(rawBody, actor) {
		return false
	}
	if hasAnyMarker(rawBody, owner) {
		// Body contains both — owner reflection wins (it's the bypass).
		return false
	}
	return true
}

func hasAnyMarker(body []byte, ident *model.Identity) bool {
	if ident == nil || len(ident.Markers) == 0 || len(body) == 0 {
		return false
	}
	for _, m := range ident.Markers {
		if m == "" {
			continue
		}
		if strings.Contains(string(body), m) {
			return true
		}
	}
	return false
}
