package mutate

import (
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// StripToken removes the bearer token and CSRF headers while preserving any
// session cookie. Probes which side of the (cookie ⊕ token) pair the server
// is actually validating.
//
// Emits one or two variants depending on what's present: one if only one of
// {bearer, csrf} exists, two if both exist (one strips each independently
// plus a combined strip). To keep things tight in v1.0 we emit a single
// "strip both" variant — same scope as the brief: "one or two variants
// depending on what's present".
type StripToken struct{}

func (StripToken) Name() string { return "strip-token" }

func (StripToken) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if base == nil {
		return nil
	}
	hasBearer := strings.HasPrefix(strings.ToLower(base.Headers.Get("Authorization")), "bearer ")
	csrfHeaders := findCSRFHeaders(base)
	if !hasBearer && len(csrfHeaders) == 0 {
		return nil
	}

	out := make([]model.Variant, 0, 2)

	if hasBearer {
		req := CloneRequest(base)
		req.Headers.Del("Authorization")
		out = append(out, model.Variant{
			Base: req,
			Mutation: model.Mutation{
				Type:        "strip-token",
				Description: "remove bearer token, keep cookies",
				Detail:      map[string]string{"removed": "bearer"},
				Class:       "auth-dependency",
			},
		})
	}
	if len(csrfHeaders) > 0 {
		req := CloneRequest(base)
		for _, h := range csrfHeaders {
			req.Headers.Del(h)
		}
		out = append(out, model.Variant{
			Base: req,
			Mutation: model.Mutation{
				Type:        "strip-token",
				Description: "remove CSRF header(s), keep cookies",
				Detail:      map[string]string{"removed": strings.Join(csrfHeaders, ",")},
				Class:       "auth-dependency",
			},
		})
	}
	return out
}

// findCSRFHeaders returns the canonical names of CSRF-ish headers present on
// the request, sorted for determinism.
func findCSRFHeaders(req *model.CapturedRequest) []string {
	found := make([]string, 0, 3)
	for k := range req.Headers {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "csrf") || strings.Contains(lk, "xsrf") {
			found = append(found, k)
		}
	}
	sort.Strings(found)
	return found
}
