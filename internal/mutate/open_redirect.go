package mutate

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// OpenRedirect is the unvalidated-redirect / open-redirect access-control
// bypass mutator. It targets the OWASP A01:2021 (Broken Access Control) /
// CWE-601 family at the request-parameter layer: the application accepts a
// destination URL from the client (a post-login next parameter, a returnTo
// after a payment flow, a callback, a redirect_uri in an OAuth dance) and
// echoes that value into a Location: header (or a meta-refresh / JS
// window.location.assign) without validating that the destination is
// in-scope for the application. An attacker who substitutes the value with
// an attacker-controlled URL turns the application into a phishing redirect
// surface — the victim sees a legitimate target.example login page that
// silently bounces to attacker.example, where the credentials harvested
// look authentic because the redirect originated from the trusted host.
// On an OAuth flow, an open redirect on the redirect_uri leaks
// authorization codes / access tokens to attacker.example via the URL
// fragment.
//
// Where SSRFProbe attacks *what server-side network resource the application
// fetches on the caller's behalf* (the value is consumed by an outbound HTTP
// client → internal-network probes), OpenRedirect attacks *what destination
// the application bounces the caller's browser to* (the value is reflected
// into a Location header → external attacker site). The vuln classes are
// disjoint: SSRF reaches internal IPs / cloud metadata; open-redirect reaches
// external attacker domains and abuses URL-parser disagreement. The fixes
// are also disjoint (URL-allowlist + same-origin check vs. metadata-endpoint
// blocking + outbound URL allowlist), so the two mutators share helpers but
// run independently and produce separate findings.
//
// Four surfaces, each emitted as a separate variant family for attribution:
//
//   - query-open-redirect: any query parameter whose name matches a
//     redirect-destination token (redirect, redirect_uri, redirect_url,
//     redirect_to, redir, return, return_url, return_to, returnto, next,
//     nexturl, next_url, url, dest, destination, goto, target, continue,
//     callback, success, success_url, back) OR whose value already parses
//     as an absolute http(s) URL. The substring match catches the
//     long-tail of in-house redirect parameters (next_page, returnUrl,
//     RedirectURI, etc.); the value-shape check catches the rest.
//
//   - body-open-redirect: the same name+value-shape match applied to an
//     application/x-www-form-urlencoded request body — common in form
//     POST → redirect flows (legacy login forms, payment confirmations).
//
//   - json-open-redirect: top-level JSON object keys matching the same
//     name list. Only string-valued keys are eligible; nested objects are
//     not walked.
//
//   - header-referer: the Referer header itself. Some applications redirect
//     the caller back to the Referer after a state-change (post-action
//     redirects, "back" buttons that read the Referer), and an attacker
//     who controls the Referer (by hosting a link on an attacker-controlled
//     page) reaches the same primitive. Emitted only when a Referer is
//     present on the captured request — there is no signal otherwise.
//
// Seven payload techniques, each emitted as a separate variant per eligible
// parameter for attribution. Generation order is fixed (sorted-by-technique-
// name) so identical inputs yield an identical variant slice:
//
//   - backslash-host: https://attacker.example\@target.example/ — RFC 3986
//     forbids backslash in the authority component, but browsers (and many
//     URL parsers) normalise '\' → '/', so the parsed authority becomes
//     attacker.example while a naive validator that splits on '@' or that
//     only checks the literal host substring reads target.example.
//
//   - cross-origin: https://attacker.example/ — the textbook external URL.
//     An application that does not validate the destination at all (or
//     only checks presence) honours a blatantly cross-site redirect target.
//
//   - data-uri: data:text/html,<script>alert(1)</script> — the data: URL
//     scheme. Browsers that follow a Location: data:... can be coerced
//     into rendering attacker HTML / JavaScript in the origin of the
//     redirecting site (modern browsers block top-level navigation to
//     data: but the legacy ecosystem and many native HTTP clients honour
//     it). Same XSS-via-redirect class as javascript:.
//
//   - javascript-uri: javascript:alert(1) — the javascript: URL scheme.
//     An app that emits Location: javascript:... can be turned into a
//     reflected-XSS sink via the redirect; browsers vary in their handling
//     (most modern browsers refuse javascript: in Location, but the legacy
//     ecosystem and embedded WebViews honour it).
//
//   - protocol-relative: //attacker.example/ — the scheme-relative URL.
//     A validator that requires the destination begin with '/' (assuming
//     it is therefore same-origin) approves; browsers interpret the
//     leading '//' as scheme-relative and navigate to attacker.example
//     under the current scheme. The most common open-redirect bypass on
//     same-origin-by-leading-slash defenses.
//
//   - userinfo-confusion: https://target.example@attacker.example/ — the
//     authority's userinfo component. RFC 3986 splits the authority into
//     userinfo@host:port, so the parsed host is attacker.example while
//     target.example is the username. A validator that does a naive
//     substring / hasPrefix check on the URL string sees target.example
//     and approves. Parallels the userinfo-confusion technique
//     OriginSpoof emits against the Origin header.
//
//   - whitespace-prefix: a leading space + https://attacker.example/. RFC
//     3986 forbids leading whitespace in URLs, but many validators trim
//     before matching, then pass the un-trimmed value to the browser,
//     which also trims — the validator and the browser agree on a
//     different URL than what the validator inspected. Disjoint from
//     CRLF/header-splitting (raw CR/LF in header values is rejected by
//     net/http before reaching the wire; we use a literal space which is
//     URL-safe to transport).
//
// Cross-product is (4 surfaces × 7 techniques × eligible-parameter count),
// gated by what the captured request actually carries: a GET with no
// redirect-shaped query parameter, no body, and no Referer emits zero
// variants (no signal to probe). The variant ID derived by the planner
// from the mutation Detail carries surface + technique + parameter so the
// offline corpus tests pin every cell.
//
// Every variant keeps the caller's own credentials (Identity == nil): this
// is emphatically NOT an identity swap. The bug being tested is "the same
// legitimately-credentialed caller coerces the application into bouncing
// their browser to an attacker-controlled destination." Detection rides
// the existing comparative ladder: a variant whose response carries a 3xx
// Location header containing the attacker payload (or, for data:/
// javascript:, whose body reflects the payload) is the candidate
// open-redirect finding. Findings are class "open-redirect" (ASVS V5.1.5
// — URL redirect validation, severity MEDIUM: the impact is phishing /
// OAuth-token leakage, not direct privilege bypass).
//
// OpenRedirect is OFF by default (Enabled == false). The payloads point
// callers' browsers at attacker-controlled URLs and embed XSS-via-redirect
// shapes (data:/javascript:), so it only fires when the operator
// explicitly opts in via --open-redirect. This mirrors the off-by-default
// gating of SSRFProbe, PathTraversal, PrototypePollution, CacheDeception,
// ContentTypeConfusion, OriginSpoof, ParamPollution, HeaderInjection,
// CookieTamper, HostHeader, ForbiddenBypass, MethodOverride, CSRFHeader,
// WSHijack, XXE, and MassAssign.
//
// Like every mutator, Generate is pure and deterministic: parameters are
// processed in sorted name order and techniques emitted in sorted name
// order within each parameter, so identical inputs yield an identical
// variant slice.
type OpenRedirect struct {
	Enabled bool
}

func (OpenRedirect) Name() string { return "open-redirect" }

// openRedirectParamNames is the canonical, sorted list of
// redirect-destination parameter name tokens. A parameter whose lowercased
// name CONTAINS any of these substrings is eligible. Substring match
// catches the long-tail of in-house redirect parameters (next_page,
// returnUrl, RedirectURI). Sorted alphabetically so the order test pins
// the set.
var openRedirectParamNames = []string{
	"back",
	"callback",
	"continue",
	"dest",
	"destination",
	"goto",
	"next",
	"redir",
	"redirect",
	"return",
	"returnto",
	"success",
	"target",
	"url",
}

// openRedirectTechniques is the canonical, sorted list of open-redirect
// payload technique names. The payload for each is held in
// openRedirectPayloads. Sorted so the cross-product emission order is
// stable regardless of map iteration; the order test pins this.
var openRedirectTechniques = []string{
	"backslash-host",
	"cross-origin",
	"data-uri",
	"javascript-uri",
	"protocol-relative",
	"userinfo-confusion",
	"whitespace-prefix",
}

// openRedirectPayloads maps each technique name to its wire payload. Kept
// package-private so the variant ID is stable across runs and across
// builds. The target-bearing techniques (backslash-host, userinfo-
// confusion) use a placeholder "target.example" host that the planner
// could later substitute with the captured request's actual host; the
// fixed token keeps the variant ID stable regardless of input host so the
// offline corpus pins it.
var openRedirectPayloads = map[string]string{
	"backslash-host":     `https://attacker.example\@target.example/`,
	"cross-origin":       "https://attacker.example/",
	"data-uri":           "data:text/html,<script>alert(1)</script>",
	"javascript-uri":     "javascript:alert(1)",
	"protocol-relative":  "//attacker.example/",
	"userinfo-confusion": "https://target.example@attacker.example/",
	"whitespace-prefix":  " https://attacker.example/",
}

func (or OpenRedirect) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !or.Enabled || base == nil {
		return nil
	}

	techniques := append([]string(nil), openRedirectTechniques...)
	sort.Strings(techniques)

	var out []model.Variant
	out = append(out, or.queryVariants(base, techniques)...)
	out = append(out, or.bodyVariants(base, techniques)...)
	out = append(out, or.jsonVariants(base, techniques)...)
	out = append(out, or.refererVariants(base, techniques)...)
	return out
}

func (or OpenRedirect) queryVariants(base *model.CapturedRequest, techniques []string) []model.Variant {
	if base.URL == nil || base.URL.RawQuery == "" {
		return nil
	}
	pairs, err := parseOrderedPairs(base.URL.RawQuery)
	if err != nil || len(pairs) == 0 {
		return nil
	}
	eligible := openRedirectEligibleNames(pairs)
	if len(eligible) == 0 {
		return nil
	}
	var out []model.Variant
	for _, name := range eligible {
		for _, tech := range techniques {
			payload := openRedirectPayloads[tech]
			rewritten := replaceFirstValue(pairs, name, payload)
			req := CloneRequest(base)
			cloneURL(req, base)
			req.URL.RawQuery = encodeOrderedPairs(rewritten)
			out = append(out, model.Variant{
				Base:     req,
				Identity: nil,
				Mutation: model.Mutation{
					Type: "open-redirect",
					Description: "rewrite query parameter " + name + " to open-redirect payload (" +
						tech + ") to bounce the caller's browser to an attacker-controlled destination",
					Detail: map[string]string{
						"open-redirect": "query:" + name + ":" + tech,
						"technique":     "query-open-redirect:" + tech,
						"surface":       "query",
						"parameter":     name,
						"shape":         tech,
						"payload":       payload,
					},
					Class: "open-redirect",
				},
			})
		}
	}
	return out
}

func (or OpenRedirect) bodyVariants(base *model.CapturedRequest, techniques []string) []model.Variant {
	if len(base.Body) == 0 || !isFormURLEncoded(base.ContentType) {
		return nil
	}
	pairs, err := parseOrderedPairs(string(base.Body))
	if err != nil || len(pairs) == 0 {
		return nil
	}
	eligible := openRedirectEligibleNames(pairs)
	if len(eligible) == 0 {
		return nil
	}
	var out []model.Variant
	for _, name := range eligible {
		for _, tech := range techniques {
			payload := openRedirectPayloads[tech]
			rewritten := replaceFirstValue(pairs, name, payload)
			req := CloneRequest(base)
			req.Body = []byte(encodeOrderedPairs(rewritten))
			out = append(out, model.Variant{
				Base:     req,
				Identity: nil,
				Mutation: model.Mutation{
					Type: "open-redirect",
					Description: "rewrite form-body parameter " + name + " to open-redirect payload (" +
						tech + ") to bounce the caller's browser to an attacker-controlled destination",
					Detail: map[string]string{
						"open-redirect": "body:" + name + ":" + tech,
						"technique":     "body-open-redirect:" + tech,
						"surface":       "body",
						"parameter":     name,
						"shape":         tech,
						"payload":       payload,
					},
					Class: "open-redirect",
				},
			})
		}
	}
	return out
}

func (or OpenRedirect) jsonVariants(base *model.CapturedRequest, techniques []string) []model.Variant {
	if len(base.Body) == 0 || !looksJSON(base.ContentType, base.Body) {
		return nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(base.Body, &doc); err != nil {
		return nil
	}
	var eligible []string
	for k, raw := range doc {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			continue
		}
		if openRedirectNameMatches(k) || ssrfValueLooksURL(s) {
			eligible = append(eligible, k)
		}
	}
	if len(eligible) == 0 {
		return nil
	}
	sort.Strings(eligible)

	var out []model.Variant
	for _, key := range eligible {
		for _, tech := range techniques {
			payload := openRedirectPayloads[tech]
			rewritten := rewriteJSONStringField(base.Body, key, payload)
			if rewritten == nil {
				continue
			}
			req := CloneRequest(base)
			req.Body = rewritten
			out = append(out, model.Variant{
				Base:     req,
				Identity: nil,
				Mutation: model.Mutation{
					Type: "open-redirect",
					Description: "rewrite JSON field " + key + " to open-redirect payload (" +
						tech + ") to bounce the caller's browser to an attacker-controlled destination",
					Detail: map[string]string{
						"open-redirect": "json:" + key + ":" + tech,
						"technique":     "json-open-redirect:" + tech,
						"surface":       "json",
						"parameter":     key,
						"shape":         tech,
						"payload":       payload,
					},
					Class: "open-redirect",
				},
			})
		}
	}
	return out
}

// refererVariants emits one variant per technique when the captured request
// carries a Referer header. The Referer is the one header an attacker can
// reliably set on a victim's browser (by hosting a link on an attacker-
// controlled page), so an app that redirects to the Referer post-action
// has the same open-redirect primitive.
//
// Some techniques (backslash-host, whitespace-prefix) carry bytes net/http
// would reject as raw header values; those are skipped here. The standard
// library validates a stricter subset of byte ranges in header values than
// in URL query / body bytes, so the technique set the Referer surface
// covers is a subset of the technique set the URL surfaces cover. The
// remaining techniques (cross-origin, data-uri, javascript-uri, protocol-
// relative, userinfo-confusion) are all valid header-value bytes.
func (or OpenRedirect) refererVariants(base *model.CapturedRequest, techniques []string) []model.Variant {
	if base.Headers == nil {
		return nil
	}
	if base.Headers.Get("Referer") == "" {
		return nil
	}
	var out []model.Variant
	for _, tech := range techniques {
		if !openRedirectHeaderSafe(tech) {
			continue
		}
		payload := openRedirectPayloads[tech]
		req := CloneRequest(base)
		req.Headers.Set("Referer", payload)
		out = append(out, model.Variant{
			Base:     req,
			Identity: nil,
			Mutation: model.Mutation{
				Type: "open-redirect",
				Description: "rewrite Referer header to open-redirect payload (" +
					tech + ") to bounce the caller's browser to an attacker-controlled destination",
				Detail: map[string]string{
					"open-redirect": "header:Referer:" + tech,
					"technique":     "header-referer-open-redirect:" + tech,
					"surface":       "header",
					"parameter":     "Referer",
					"shape":         tech,
					"payload":       payload,
				},
				Class: "open-redirect",
			},
		})
	}
	return out
}

// openRedirectEligibleNames returns the distinct parameter names (in sorted
// order) eligible for open-redirect probing — either the name matches the
// redirect-destination token list, or the value parses as an absolute
// http(s) URL.
func openRedirectEligibleNames(pairs []orderedPair) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, p := range pairs {
		if _, ok := seen[p.name]; ok {
			continue
		}
		if !openRedirectNameMatches(p.name) && !ssrfValueLooksURL(p.value) {
			continue
		}
		seen[p.name] = struct{}{}
		out = append(out, p.name)
	}
	sort.Strings(out)
	return out
}

// openRedirectNameMatches reports whether the lowercased parameter name
// contains any redirect-destination token substring. Over-inclusive on
// purpose — a noisy probe against a non-redirect parameter is harmless,
// a missed real redirect parameter is a missed open-redirect finding.
func openRedirectNameMatches(name string) bool {
	low := strings.ToLower(name)
	for _, tok := range openRedirectParamNames {
		if strings.Contains(low, tok) {
			return true
		}
	}
	return false
}

// openRedirectHeaderSafe reports whether a technique's payload is safe to
// transport as an HTTP header value. net/http rejects raw CR/LF and a
// stricter byte subset in header values than in URL/body bytes;
// backslash-host carries a literal '\' which Go's HTTP/2 transport (and
// some HTTP/1 servers) will reject, and whitespace-prefix carries a
// leading space which net/http trims silently — both signals would be
// destroyed in transit. The URL-surface generators carry these techniques
// unaffected.
func openRedirectHeaderSafe(technique string) bool {
	switch technique {
	case "backslash-host", "whitespace-prefix":
		return false
	}
	return true
}

// openRedirectTechniqueOf returns the technique label from a mutation's
// Detail map. Used by tests to assert technique coverage without leaking
// the Detail key layout outside the package. Mirrors ssrfProbeTechnique.
func openRedirectTechniqueOf(m model.Mutation) string {
	if m.Detail == nil {
		return ""
	}
	// "query-open-redirect:cross-origin" → "cross-origin"
	t := strings.TrimSpace(m.Detail["technique"])
	if i := strings.LastIndex(t, ":"); i >= 0 {
		return t[i+1:]
	}
	return t
}

// openRedirectKnownTechnique reports whether a technique name is recognised.
// Used by tests; also a defensive check should the payload map ever drift
// out of sync with the technique list.
func openRedirectKnownTechnique(name string) bool {
	_, ok := openRedirectPayloads[name]
	return ok
}

// ensure url import survives (helper signature parity with ssrf-probe).
var _ = url.Parse
