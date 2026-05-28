package detect

import (
	"regexp"
	"sort"
	"strings"
)

// Marker harvesting (POST_V01 Item 5).
//
// Marker-based detection is possession's most decisive IDOR branch: a variant
// body that contains the resource owner's unique data string (email, account
// id, display name) is a near-certain bypass (evaluate.go branch 7). Today
// those markers must be hand-entered per identity in the role matrix, which is
// the single highest-friction setup step.
//
// Harvesting learns each identity's markers automatically from the owner
// self-replay baseline bodies that the scan already collects. A candidate
// token is promoted to an identity's effective marker set only when it is:
//
//   - extractable as a high-signal shape (email, UUID, long digit run, or an
//     account-id-shaped alphanumeric token), AND
//   - stable: it appears in every baseline sample for that identity, AND
//   - unique: it appears for exactly one identity across the whole run.
//
// The stable+unique gate is what keeps false positives down — a token shared
// across identities (a CSRF field name, a common API version string) is
// discarded, and a token that flickers between samples (a per-request nonce,
// a timestamp) is discarded. Harvesting only ever AUGMENTS markers; it never
// removes or overrides operator-supplied ones.

var (
	// reEmail matches RFC-ish email addresses. Deliberately conservative.
	reEmail = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}`)

	// reUUID matches canonical 8-4-4-4-12 UUIDs (any version/variant nibble).
	reUUID = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

	// reDigits matches long runs of digits (account numbers, sequential ids).
	// Bounded at 5+ to avoid years/ports/small counts; capped to a sane upper
	// bound so a giant numeric blob doesn't become one mega-marker.
	reDigits = regexp.MustCompile(`\b\d{5,24}\b`)

	// reAccountID matches mixed alphanumeric identifier-shaped tokens that
	// carry at least one digit and one letter (e.g. "acct_9f3b2c", "usr-1A2B",
	// "ACME_SECRET_DATA_9f3b"). Bounded length keeps prose words out.
	reAccountID = regexp.MustCompile(`\b[A-Za-z0-9][A-Za-z0-9_\-]{5,63}\b`)
)

// minMarkerLen is the shortest token harvesting will keep. Short tokens are
// too collision-prone to be reliable IDOR signals.
const minMarkerLen = 5

// ExtractCandidateTokens pulls high-signal unique-shaped tokens out of a single
// response body. The returned slice is de-duplicated but unordered-stable
// (sorted) so callers get deterministic output. Tokens shorter than
// minMarkerLen, and the obvious non-identifying numeric/alphanumeric noise that
// the shape regexes would otherwise admit, are dropped.
func ExtractCandidateTokens(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	s := string(body)
	set := make(map[string]struct{})

	add := func(tok string) {
		tok = strings.TrimSpace(tok)
		if len(tok) < minMarkerLen {
			return
		}
		set[tok] = struct{}{}
	}

	for _, m := range reEmail.FindAllString(s, -1) {
		add(m)
	}
	for _, m := range reUUID.FindAllString(s, -1) {
		add(m)
	}
	for _, m := range reDigits.FindAllString(s, -1) {
		add(m)
	}
	for _, m := range reAccountID.FindAllString(s, -1) {
		// An account-id-shaped token must mix letters and digits to count;
		// pure-letter words (prose) and pure-digit runs (already handled by
		// reDigits) are rejected here to keep the candidate set tight.
		if hasLetter(m) && hasDigit(m) {
			add(m)
		}
	}

	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func hasLetter(s string) bool {
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

func hasDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

// HarvestMarkers learns per-identity markers from baseline response bodies.
//
// bodiesByIdentity maps an identity name to the list of its owner-baseline
// response bodies (one entry per baseline sample, possibly across several
// endpoints). The result maps an identity name to the tokens that are both
// STABLE for that identity (present in every one of its baseline bodies) and
// UNIQUE across the run (present for no other identity). Identities with no
// learned markers are omitted from the result.
//
// The function is pure and deterministic: same input ⇒ same output, sorted.
func HarvestMarkers(bodiesByIdentity map[string][][]byte) map[string][]string {
	if len(bodiesByIdentity) == 0 {
		return nil
	}

	// Stage 1: per identity, the set of tokens stable across all its bodies.
	stable := make(map[string]map[string]struct{})
	for name, bodies := range bodiesByIdentity {
		if len(bodies) == 0 {
			continue
		}
		// Intersect candidate tokens across every body for this identity.
		var inter map[string]struct{}
		for i, b := range bodies {
			toks := make(map[string]struct{})
			for _, t := range ExtractCandidateTokens(b) {
				toks[t] = struct{}{}
			}
			if i == 0 {
				inter = toks
				continue
			}
			for t := range inter {
				if _, ok := toks[t]; !ok {
					delete(inter, t)
				}
			}
		}
		if len(inter) > 0 {
			stable[name] = inter
		}
	}

	// Stage 2: count how many distinct identities carry each stable token.
	tokenOwners := make(map[string]int)
	for _, toks := range stable {
		for t := range toks {
			tokenOwners[t]++
		}
	}

	// Stage 3: keep only tokens unique to one identity.
	out := make(map[string][]string)
	for name, toks := range stable {
		var kept []string
		for t := range toks {
			if tokenOwners[t] == 1 {
				kept = append(kept, t)
			}
		}
		if len(kept) > 0 {
			sort.Strings(kept)
			out[name] = kept
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// MergeMarkers returns the union of existing operator-supplied markers and the
// newly learned ones, preserving the operator's markers first (and never
// dropping them) and appending only learned markers not already present. The
// result is deterministic: operator markers in their original order, followed
// by learned markers sorted. Returns the merged slice and the count of markers
// actually added.
func MergeMarkers(existing, learned []string) (merged []string, added int) {
	have := make(map[string]struct{}, len(existing))
	merged = make([]string, 0, len(existing)+len(learned))
	for _, m := range existing {
		merged = append(merged, m)
		have[m] = struct{}{}
	}
	add := append([]string(nil), learned...)
	sort.Strings(add)
	for _, m := range add {
		if m == "" {
			continue
		}
		if _, ok := have[m]; ok {
			continue
		}
		merged = append(merged, m)
		have[m] = struct{}{}
		added++
	}
	return merged, added
}
