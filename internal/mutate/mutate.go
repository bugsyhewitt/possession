// Package mutate produces deterministic Variant sets for one baseline
// CapturedRequest under a given role matrix.
//
// Mutators are pure functions — they never touch the network. Replay
// owns network I/O. This separation keeps variant generation reproducible
// and testable offline (the foundation of --dry-run).
//
// Auth-component identification is intentionally heuristic and over-inclusive:
// a missed auth header is silent and dangerous; a falsely-flagged header is
// at worst noisy. See AuthHeaderNames and AuthCookieSubstrings.
package mutate

import (
	"net/http"
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// Mutator transforms a baseline request into zero or more replay variants.
// Generate must be pure and deterministic: identical inputs ⇒ identical
// output slice (including order).
type Mutator interface {
	Name() string
	Generate(base *model.CapturedRequest, matrix *model.RoleMatrix) []model.Variant
}

// AuthHeaderNames lists request headers that we treat as auth-bearing.
// Case-insensitive matching is used at strip time. Extend with care —
// false positives are safer than false negatives.
var AuthHeaderNames = []string{
	"Authorization",
	"Cookie",
	"X-Api-Key",
	"X-Auth-Token",
	"X-CSRF-Token",
	"X-CSRFToken",
	"X-XSRF-Token",
	"X-Access-Token",
	"X-Session-Token",
	"Proxy-Authorization",
}

// AuthCookieSubstrings are case-insensitive substrings of cookie names we
// treat as auth-bearing.
var AuthCookieSubstrings = []string{
	"session",
	"sess",
	"auth",
	"token",
	"sid",
	"jwt",
	"csrf",
	"xsrf",
}

// IsAuthHeader reports whether name appears in AuthHeaderNames (case-insensitive).
func IsAuthHeader(name string) bool {
	for _, h := range AuthHeaderNames {
		if strings.EqualFold(name, h) {
			return true
		}
	}
	return false
}

// IsAuthCookie reports whether the cookie name matches any AuthCookieSubstrings
// (case-insensitive).
func IsAuthCookie(name string) bool {
	low := strings.ToLower(name)
	for _, s := range AuthCookieSubstrings {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}

// CloneRequest produces a deep-enough copy of req that mutators can mutate
// headers/cookies/body without aliasing the baseline. URL is shared (URLs
// are mutated by replay only, never by mutators).
func CloneRequest(req *model.CapturedRequest) *model.CapturedRequest {
	if req == nil {
		return nil
	}
	out := *req
	out.Headers = req.Headers.Clone()
	if out.Headers == nil {
		out.Headers = http.Header{}
	}
	if len(req.Cookies) > 0 {
		out.Cookies = make([]*http.Cookie, len(req.Cookies))
		for i, c := range req.Cookies {
			if c == nil {
				continue
			}
			cc := *c
			out.Cookies[i] = &cc
		}
	}
	if len(req.Body) > 0 {
		out.Body = append([]byte(nil), req.Body...)
	}
	return &out
}

// Registry is the ordered set of mutators in declaration order (D11).
type Registry struct {
	names []string
	by    map[string]Mutator
}

// NewRegistry constructs a Registry from the given mutators. Order is
// preserved (it is the iteration order during variant generation).
func NewRegistry(mutators ...Mutator) *Registry {
	r := &Registry{by: make(map[string]Mutator, len(mutators))}
	for _, m := range mutators {
		r.names = append(r.names, m.Name())
		r.by[m.Name()] = m
	}
	return r
}

// All returns the mutators in declaration order.
func (r *Registry) All() []Mutator {
	out := make([]Mutator, 0, len(r.names))
	for _, n := range r.names {
		out = append(out, r.by[n])
	}
	return out
}

// Names returns the registered mutator names in declaration order.
func (r *Registry) Names() []string {
	out := make([]string, len(r.names))
	copy(out, r.names)
	return out
}

// Get returns the mutator by name, or nil.
func (r *Registry) Get(name string) Mutator { return r.by[name] }

// DefaultRegistry returns the v1.0+v1.1 mutator set in canonical order.
// P2 mutators first (D8), then P4 JWT basics (D24), then P5 deep JWT
// attacks. All registered in declaration order per D11.
func DefaultRegistry() *Registry {
	return NewRegistry(
		StripAuth{},
		SwapIdentity{},
		DowngradeRole{},
		DropCookie{},
		StripToken{},
		// P4: basic JWT attacks
		JWTAlgNone{},
		JWTSigStrip{},
		JWTClaimTamper{},
		JWTResignWeakKey{},
		// P5: deep JWT attacks
		JWTAlgConfusion{},
		JWTKidInjection{},
		JWTJwksSpoof{},
		JWTHmacCrack{},
	)
}

// applyIdentity rewrites cred-bearing headers/cookies on req to reflect
// ident. If ident is nil all credentials are removed. The base auth is
// first cleared so creds don't "stack".
//
// Note: refresh-hook injections are layered on top of this by the replay
// engine; mutate does not know about them.
func applyIdentity(req *model.CapturedRequest, ident *model.Identity) {
	stripAllAuth(req)
	if ident == nil || ident.Creds == nil {
		return
	}
	c := ident.Creds
	for k, v := range c.Headers {
		req.Headers.Set(k, v)
	}
	for name, val := range c.Cookies {
		req.Cookies = append(req.Cookies, &http.Cookie{Name: name, Value: val})
	}
	if c.Bearer != "" {
		req.Headers.Set("Authorization", "Bearer "+c.Bearer)
	}
	if c.Basic != nil {
		req.Headers.Set("Authorization", basicAuthHeader(c.Basic.Username, c.Basic.Password))
	}
}

func stripAllAuth(req *model.CapturedRequest) {
	// Strip auth headers (case-insensitive via http.Header.Del which is
	// already canonical).
	for _, h := range AuthHeaderNames {
		req.Headers.Del(h)
	}
	// Strip auth cookies.
	if len(req.Cookies) > 0 {
		kept := req.Cookies[:0]
		for _, c := range req.Cookies {
			if c == nil {
				continue
			}
			if IsAuthCookie(c.Name) {
				continue
			}
			kept = append(kept, c)
		}
		req.Cookies = kept
	}
}

// basicAuthHeader is the same encoding net/http uses for SetBasicAuth.
// Kept inline to avoid the round-trip of constructing an http.Request.
func basicAuthHeader(user, pass string) string {
	return "Basic " + base64Std(user+":"+pass)
}

// sortIdentities returns a copy of ids sorted by (rank, name) — the canonical
// per-mutator iteration order from D11.
func sortIdentities(ids []model.Identity) []model.Identity {
	out := make([]model.Identity, len(ids))
	copy(out, ids)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Rank != out[j].Rank {
			return out[i].Rank < out[j].Rank
		}
		return out[i].Name < out[j].Name
	})
	return out
}
