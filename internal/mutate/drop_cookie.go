package mutate

import (
	"net/http"
	"sort"

	"github.com/bugsyhewitt/possession/internal/model"
)

// DropCookie emits one variant per auth-cookie present on the baseline,
// each with that single cookie removed and the rest intact. Maps
// auth-dependency: which cookie is actually enforcing access?
//
// Cookies are processed in name-sorted order so output is deterministic
// regardless of header parsing order upstream.
type DropCookie struct{}

func (DropCookie) Name() string { return "drop-cookie" }

func (DropCookie) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if base == nil {
		return nil
	}
	authCookies := make([]string, 0)
	for _, c := range base.Cookies {
		if c != nil && IsAuthCookie(c.Name) {
			authCookies = append(authCookies, c.Name)
		}
	}
	sort.Strings(authCookies)
	if len(authCookies) == 0 {
		return nil
	}
	out := make([]model.Variant, 0, len(authCookies))
	for _, name := range authCookies {
		req := CloneRequest(base)
		req.Cookies = filterCookies(req.Cookies, name)
		out = append(out, model.Variant{
			Base: req,
			// Identity preserved as nil — base creds are kept-as-is on req
			// already; mutation is a deletion, not a swap.
			Mutation: model.Mutation{
				Type:        "drop-cookie",
				Description: "remove auth cookie " + name,
				Detail:      map[string]string{"removed_cookie": name},
			},
		})
	}
	return out
}

func filterCookies(cs []*http.Cookie, drop string) []*http.Cookie {
	out := cs[:0]
	for _, c := range cs {
		if c == nil || c.Name == drop {
			continue
		}
		out = append(out, c)
	}
	return out
}
