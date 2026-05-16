package detect

import (
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
	"github.com/bugsyhewitt/possession/internal/mutate"
)

// Attribution reasons (D17). Stored on Endpoint.OwnerAttribution.
const (
	AttrExactBearer       = "exact-bearer"
	AttrExactCookie       = "exact-cookie"
	AttrExactHeader       = "exact-header"
	AttrBasicUsername     = "basic-username"
	AttrFallbackHighRank  = "fallback-highest-rank"
	AttrAmbiguous         = "ambiguous"
)

// AttributeOwner picks the matrix Identity whose credentials best match
// the auth components of req, per D17. First match wins across the
// identities sorted by (rank asc, name asc); a tie raises an ambiguity
// warning but resolution remains deterministic. When no identity matches
// any auth component, the highest-rank identity is the fallback.
//
// Returns (owner, attribution, warnings). owner is non-nil whenever matrix
// has any identities. warnings is empty unless ambiguity was detected.
func AttributeOwner(req *model.CapturedRequest, matrix *model.RoleMatrix) (*model.Identity, string, []string) {
	if matrix == nil || len(matrix.Identities) == 0 {
		return nil, "", nil
	}
	// Sort copy by (rank asc, name asc) so iteration order is deterministic.
	ids := make([]model.Identity, len(matrix.Identities))
	copy(ids, matrix.Identities)
	sort.SliceStable(ids, func(i, j int) bool {
		if ids[i].Rank != ids[j].Rank {
			return ids[i].Rank < ids[j].Rank
		}
		return ids[i].Name < ids[j].Name
	})

	if req == nil {
		return fallback(ids)
	}

	// Extract auth components from the request, reusing mutate's heuristic.
	reqBearer, reqHeaders, reqCookies := extractAuthFromRequest(req)

	type match struct {
		ident *model.Identity
		reason string
	}
	var matches []match
	for i := range ids {
		id := &ids[i]
		if id.Creds == nil {
			continue
		}
		c := id.Creds

		// Bearer exact match.
		if c.Bearer != "" && reqBearer != "" && c.Bearer == reqBearer {
			matches = append(matches, match{id, AttrExactBearer})
			continue
		}
		// Auth header exact match (any header value).
		if matchedAuthHeader(c.Headers, reqHeaders) {
			matches = append(matches, match{id, AttrExactHeader})
			continue
		}
		// Auth cookie exact match (any cookie value).
		if matchedAuthCookie(c.Cookies, reqCookies) {
			matches = append(matches, match{id, AttrExactCookie})
			continue
		}
		// Basic auth username match.
		if c.Basic != nil && matchedBasicUsername(c.Basic.Username, reqHeaders) {
			matches = append(matches, match{id, AttrBasicUsername})
			continue
		}
	}

	if len(matches) == 0 {
		return fallback(ids)
	}
	// First match wins (ids already sorted). If multiple matches at the
	// same priority (multiple identities share a credential value), the
	// first one wins (deterministic) but a warning is recorded.
	chosen := matches[0]
	var warnings []string
	if len(matches) > 1 {
		// Distinguish duplicates from layered matches: if any two matches
		// share the SAME reason, that's ambiguity on the same credential.
		seenReasons := make(map[string][]string)
		for _, m := range matches {
			seenReasons[m.reason] = append(seenReasons[m.reason], m.ident.Name)
		}
		for reason, names := range seenReasons {
			if len(names) > 1 {
				warnings = append(warnings, "owner-attribution: ambiguous "+reason+" across identities "+strings.Join(names, ","))
			}
		}
	}
	return chosen.ident, chosen.reason, warnings
}

func fallback(ids []model.Identity) (*model.Identity, string, []string) {
	if len(ids) == 0 {
		return nil, "", nil
	}
	// Highest-rank identity: sort desc by rank, ties to name asc.
	best := &ids[0]
	for i := 1; i < len(ids); i++ {
		switch {
		case ids[i].Rank > best.Rank:
			best = &ids[i]
		case ids[i].Rank == best.Rank && ids[i].Name < best.Name:
			best = &ids[i]
		}
	}
	return best, AttrFallbackHighRank, nil
}

// extractAuthFromRequest pulls the bearer token, auth-header map, and
// auth-cookie map out of req — reusing mutate.IsAuthHeader / IsAuthCookie
// for the membership test so the heuristic is shared (no reimplementation).
func extractAuthFromRequest(req *model.CapturedRequest) (bearer string, headers map[string]string, cookies map[string]string) {
	headers = make(map[string]string)
	cookies = make(map[string]string)
	if req == nil {
		return "", headers, cookies
	}
	if req.Headers != nil {
		for name, vals := range req.Headers {
			if !mutate.IsAuthHeader(name) {
				continue
			}
			if len(vals) == 0 {
				continue
			}
			val := vals[0]
			if strings.EqualFold(name, "Authorization") {
				low := strings.ToLower(val)
				if strings.HasPrefix(low, "bearer ") {
					bearer = strings.TrimSpace(val[len("Bearer "):])
					continue
				}
				// Basic / other Authorization schemes flow through as header.
			}
			headers[name] = val
		}
	}
	for _, c := range req.Cookies {
		if c == nil {
			continue
		}
		if mutate.IsAuthCookie(c.Name) {
			cookies[c.Name] = c.Value
		}
	}
	return bearer, headers, cookies
}

// matchedAuthHeader is true if any value in identHeaders appears as a
// value of an auth header in reqHeaders. Header names are matched
// case-insensitively; values exact.
func matchedAuthHeader(identHeaders, reqHeaders map[string]string) bool {
	if len(identHeaders) == 0 || len(reqHeaders) == 0 {
		return false
	}
	for idName, idVal := range identHeaders {
		if idVal == "" {
			continue
		}
		for reqName, reqVal := range reqHeaders {
			if strings.EqualFold(idName, reqName) && idVal == reqVal {
				return true
			}
		}
	}
	return false
}

// matchedAuthCookie is true if any (name,value) pair in identCookies
// appears in reqCookies (case-insensitive name, exact value).
func matchedAuthCookie(identCookies, reqCookies map[string]string) bool {
	if len(identCookies) == 0 || len(reqCookies) == 0 {
		return false
	}
	for idName, idVal := range identCookies {
		if idVal == "" {
			continue
		}
		for reqName, reqVal := range reqCookies {
			if strings.EqualFold(idName, reqName) && idVal == reqVal {
				return true
			}
		}
	}
	return false
}

// matchedBasicUsername is true if the request's Authorization header
// is a Basic scheme whose username matches identUsername.
func matchedBasicUsername(identUsername string, reqHeaders map[string]string) bool {
	if identUsername == "" {
		return false
	}
	for name, val := range reqHeaders {
		if !strings.EqualFold(name, "Authorization") {
			continue
		}
		low := strings.ToLower(val)
		if !strings.HasPrefix(low, "basic ") {
			continue
		}
		enc := strings.TrimSpace(val[len("Basic "):])
		dec, err := decodeBasic(enc)
		if err != nil {
			continue
		}
		i := strings.IndexByte(dec, ':')
		if i < 0 {
			continue
		}
		if dec[:i] == identUsername {
			return true
		}
	}
	return false
}

// decodeBasic decodes a base64 string (std encoding, padded).
func decodeBasic(s string) (string, error) {
	return base64Decode(s)
}
