package mutate

import (
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// MethodOverride is the HTTP verb-tampering / method-override access-control
// bypass mutator. Where ForbiddenBypass attacks *how the path is matched* and
// CSRFHeader attacks *the anti-CSRF token*, MethodOverride attacks *which HTTP
// verb the access-control layer evaluates* — the canonical "method bypass"
// family every 403/401-bypass cheat-sheet lists alongside path mutation.
//
// Two distinct techniques, both keeping the caller's own credentials
// (Identity == nil) — this is emphatically NOT an identity swap. The bug being
// tested is "the same rejected caller slips past the gate by changing the verb."
//
//   - override-header: keep the request line verb unchanged but inject a
//     method-override header (X-HTTP-Method-Override, X-HTTP-Method,
//     X-Method-Override) naming a different verb. A fronting proxy / API gateway
//     enforces its allow/deny rule on the *request-line* method (e.g. "deny
//     DELETE /admin") while the application framework (Spring, Symfony, Rails,
//     many REST stacks) honours the override header and dispatches the
//     overridden verb to the protected handler. The header verb chosen is the
//     opposite-side verb relative to the request: a safe-method request
//     (GET/HEAD/OPTIONS) is overridden to a state-changing verb (POST), and a
//     state-changing request (POST/PUT/PATCH/DELETE) is overridden to GET, so
//     the override always crosses the safe/unsafe boundary the gateway most
//     commonly gates on.
//
//   - verb-swap: change the actual request-line method to a sibling verb the
//     access-control layer may not protect while the handler still serves it.
//     Many gateways gate only the captured verb (e.g. allow GET, deny POST on a
//     path) but the framework's route is method-agnostic, or a deny rule omits
//     HEAD/OPTIONS, or the matcher is case-sensitive on the method token. The
//     emitted siblings depend on the captured verb (see methodSiblings) plus a
//     case-toggled form of the original verb (Get vs GET) for case-sensitive
//     matchers.
//
// Detection rides the existing comparative ladder unchanged. The caller's own
// baseline against the unmutated, protected endpoint is (expected to be) a
// denial; a variant that returns an owner-shaped 2xx where the baseline was
// denied is the bypass. Findings are class "authz-bypass" (ASVS V8.3.x,
// severity high) — the same class ForbiddenBypass uses.
//
// Generate is pure and deterministic: techniques are emitted in a fixed
// (sorted-by-name) order and the verbs are constants, so identical inputs yield
// an identical variant slice (--dry-run and the offline corpus cover it).
//
// MethodOverride is OFF by default (Enabled == false). Verb-swap variants
// re-issue requests under state-changing methods (POST/PUT/DELETE) and the
// override headers can reach mutating handlers, so it only fires when the
// operator explicitly opts in via --method-override. This mirrors the
// off-by-default gating of XXE, MassAssign, EnumerateID, ForbiddenBypass,
// WSHijack, CSRFHeader, and JWTAuth.
type MethodOverride struct {
	Enabled bool
}

func (MethodOverride) Name() string { return "method-override" }

// methodOverrideHeaders is the built-in method-override header set. Each names
// a header an application framework may honour to override the request-line
// verb. Sorted by name for deterministic generation order; the order test
// covers this.
var methodOverrideHeaders = []string{
	"X-HTTP-Method",
	"X-HTTP-Method-Override",
	"X-Method-Override",
}

// methodSiblings maps a captured request verb to the sibling verbs worth
// probing — methods the access-control layer may not gate while the handler
// still serves them. Keys are canonical upper-case verbs. The original verb is
// never re-emitted as a sibling (that would be a no-op); a case-toggled form of
// the original is added separately by Generate.
//
// Rationale per verb family:
//   - safe reads (GET/HEAD): each other safe verb (a deny rule that lists GET
//     may omit HEAD, and vice-versa), plus OPTIONS which gateways routinely
//     leave unprotected.
//   - state-changing writes (POST/PUT/PATCH/DELETE): GET (a write gated by verb
//     may serve the same handler on GET), plus the other write siblings (a deny
//     rule on POST may omit PUT/PATCH).
//   - unknown/other verbs: fall back to the universal safe/unsafe pair.
var methodSiblings = map[string][]string{
	"GET":     {"HEAD", "OPTIONS", "POST"},
	"HEAD":    {"GET", "OPTIONS", "POST"},
	"OPTIONS": {"GET", "HEAD", "POST"},
	"POST":    {"GET", "PATCH", "PUT"},
	"PUT":     {"GET", "PATCH", "POST"},
	"PATCH":   {"GET", "POST", "PUT"},
	"DELETE":  {"GET", "POST", "PUT"},
}

// methodFallbackSiblings is used when the captured verb is not in
// methodSiblings (a non-standard or extension method).
var methodFallbackSiblings = []string{"GET", "POST"}

// overrideVerbFor picks the override-header verb for a captured request verb:
// safe reads are overridden to POST (cross into state-changing), everything
// else is overridden to GET (cross into safe). This always crosses the
// safe/unsafe boundary gateways most commonly gate on.
func overrideVerbFor(method string) string {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS", "TRACE", "":
		return "POST"
	default:
		return "GET"
	}
}

func (mo MethodOverride) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !mo.Enabled || base == nil {
		return nil
	}

	origMethod := base.Method
	if origMethod == "" {
		origMethod = "GET"
	}
	upper := strings.ToUpper(origMethod)

	var out []model.Variant

	// ── override-header variants ─────────────────────────────────────────
	// Request line verb is unchanged; the override header names a different
	// verb that crosses the safe/unsafe boundary.
	overrideVerb := overrideVerbFor(origMethod)
	headers := append([]string(nil), methodOverrideHeaders...)
	sort.Strings(headers)
	for _, hName := range headers {
		req := CloneRequest(base)
		if req.Headers == nil {
			continue
		}
		req.Headers.Set(hName, overrideVerb)
		out = append(out, model.Variant{
			Base:     req,
			Identity: nil, // credentials unchanged — same rejected caller
			Mutation: model.Mutation{
				Type:        "method-override",
				Description: "inject " + hName + ": " + overrideVerb + " to bypass verb-based access control",
				Detail: map[string]string{
					"method-override": "header:" + hName,
					"technique":       "header:" + hName,
					"header":          hName,
					"override_verb":   overrideVerb,
					"request_method":  upper,
				},
				Class: "authz-bypass",
			},
		})
	}

	// ── verb-swap variants ───────────────────────────────────────────────
	// The actual request-line method is changed to a sibling verb the
	// access-control layer may not gate.
	siblings, ok := methodSiblings[upper]
	if !ok {
		siblings = methodFallbackSiblings
	}
	// Deterministic order, with the original verb filtered out so a swap is
	// never a no-op.
	verbs := append([]string(nil), siblings...)
	sort.Strings(verbs)
	for _, verb := range verbs {
		if verb == upper {
			continue
		}
		req := CloneRequest(base)
		req.Method = verb
		out = append(out, model.Variant{
			Base:     req,
			Identity: nil, // credentials unchanged — same rejected caller
			Mutation: model.Mutation{
				Type:        "method-override",
				Description: "swap request method " + upper + " → " + verb + " to bypass verb-based access control",
				Detail: map[string]string{
					"method-override": "verb-swap:" + verb,
					"technique":       "verb-swap:" + verb,
					"method_from":     upper,
					"method_to":       verb,
				},
				Class: "authz-bypass",
			},
		})
	}

	// ── case-toggle verb variant ─────────────────────────────────────────
	// A case-sensitive method matcher (e.g. a gateway rule matching the
	// literal "GET") denies a differently-cased verb while a case-insensitive
	// framework router still serves it. Emit one variant with the original
	// verb's case toggled (GET → get), if toggling changes anything.
	if toggled := toggleMethodCase(origMethod); toggled != "" && toggled != origMethod {
		req := CloneRequest(base)
		req.Method = toggled
		out = append(out, model.Variant{
			Base:     req,
			Identity: nil, // credentials unchanged — same rejected caller
			Mutation: model.Mutation{
				Type:        "method-override",
				Description: "case-toggle request method " + origMethod + " → " + toggled + " to bypass case-sensitive verb matcher",
				Detail: map[string]string{
					"method-override": "case-toggle:" + toggled,
					"technique":       "case-toggle",
					"method_from":     origMethod,
					"method_to":       toggled,
				},
				Class: "authz-bypass",
			},
		})
	}

	return out
}

// toggleMethodCase returns m with every ASCII letter case-flipped (GET → get,
// get → GET, Get → gET). Returns "" if m has no ASCII letters to toggle, so a
// no-op never emits a variant.
func toggleMethodCase(m string) string {
	bs := []byte(m)
	changed := false
	for i := 0; i < len(bs); i++ {
		c := bs[i]
		switch {
		case c >= 'a' && c <= 'z':
			bs[i] = c - 32
			changed = true
		case c >= 'A' && c <= 'Z':
			bs[i] = c + 32
			changed = true
		}
	}
	if !changed {
		return ""
	}
	return string(bs)
}
