package mutate

import (
	"net/url"
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// ParamPollution is the HTTP Parameter Pollution (HPP) access-control bypass
// mutator. Where MethodOverride attacks *which verb* the gate evaluates,
// ForbiddenBypass attacks *how the path is matched*, and SwapObject *replaces*
// a reference value, ParamPollution attacks *which copy of a duplicated
// parameter each layer of the stack reads* — the canonical HPP family every
// access-control bypass cheat-sheet lists.
//
// The bug being tested: a request carries the same parameter name more than
// once, and two components disagree on which occurrence is authoritative. A
// fronting WAF / API gateway typically reads the FIRST occurrence (or
// concatenates), while the application framework reads a DIFFERENT occurrence
// (PHP, ASP.NET → last; some Java stacks → first; Express/Rails → array). By
// supplying the original (gate-passing) value once and an attacker-chosen value
// in a second occurrence, the request slips an unsanitised / privilege-altering
// value past the gate. Critically the caller keeps their own credentials
// (Identity == nil) — this is emphatically NOT an identity swap.
//
// Two surfaces, both keeping the caller's credentials:
//
//   - query-pollute: for each existing query parameter, emit two variants that
//     duplicate the name — one appending the tamper value AFTER the original
//     (original;tamper, exploiting last-wins parsers) and one prepending it
//     BEFORE the original (tamper;original, exploiting first-wins parsers). The
//     original occurrence is always preserved so the variant still satisfies a
//     gate that reads the value it expects.
//
//   - body-pollute: the same duplication applied to an
//     application/x-www-form-urlencoded request body, the second-most-common
//     HPP surface. Only urlencoded bodies are touched; JSON and multipart are
//     left alone (duplicate keys there do not exhibit the cross-layer
//     disagreement HPP relies on).
//
// Detection rides the existing comparative ladder unchanged: the caller's
// baseline against the protected endpoint is (expected to be) a denial; a
// polluted variant that returns an owner-shaped 2xx where the baseline was
// denied is the bypass. Findings are class "authz-bypass" (ASVS V8.3.x,
// severity high) — the same class the sibling bypass mutators use.
//
// Generate is pure and deterministic: parameters are processed in sorted name
// order and the two orderings (append / prepend) are emitted in a fixed
// sequence, so identical inputs yield an identical variant slice (--dry-run and
// the offline corpus cover it).
//
// ParamPollution is OFF by default (Enabled == false). It re-issues requests
// with altered parameter values that can reach mutating handlers, so it only
// fires when the operator explicitly opts in via --parameter-pollution. This
// mirrors the off-by-default gating of XXE, MassAssign, EnumerateID,
// ForbiddenBypass, WSHijack, CSRFHeader, MethodOverride, HostHeader,
// CookieTamper, and HeaderInjection.
type ParamPollution struct {
	Enabled bool

	// TamperValue is the attacker-chosen value injected as the duplicate
	// occurrence. When empty, defaultPollutionValue is used. Kept configurable
	// so an operator-supplied value can target a known privileged identifier.
	TamperValue string
}

func (ParamPollution) Name() string { return "parameter-pollution" }

// defaultPollutionValue is the duplicate value injected when no TamperValue is
// configured. It is a deliberately privilege-suggestive but inert token: a
// value many access-control checks treat as "admin/elevated" while remaining a
// harmless string if the handler does not honour it.
const defaultPollutionValue = "admin"

// formContentType is the urlencoded body media type ParamPollution rewrites.
const formContentType = "application/x-www-form-urlencoded"

// pollutionOrder names the two duplication strategies in deterministic order.
// "append" places the tamper value after the original (last-wins parsers);
// "prepend" places it before (first-wins parsers).
var pollutionOrder = []string{"append", "prepend"}

func (pp ParamPollution) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !pp.Enabled || base == nil {
		return nil
	}

	tamper := pp.TamperValue
	if tamper == "" {
		tamper = defaultPollutionValue
	}

	var out []model.Variant

	// ── query-pollute variants ───────────────────────────────────────────
	out = append(out, pp.queryVariants(base, tamper)...)

	// ── body-pollute variants (urlencoded forms only) ────────────────────
	out = append(out, pp.bodyVariants(base, tamper)...)

	return out
}

// queryVariants duplicates each query parameter with the tamper value, once
// appended and once prepended, preserving the original occurrence.
func (pp ParamPollution) queryVariants(base *model.CapturedRequest, tamper string) []model.Variant {
	if base.URL == nil || base.URL.RawQuery == "" {
		return nil
	}
	pairs, err := parseOrderedPairs(base.URL.RawQuery)
	if err != nil || len(pairs) == 0 {
		return nil
	}

	names := distinctNames(pairs)
	var out []model.Variant
	for _, name := range names {
		for _, order := range pollutionOrder {
			polluted := pollutePairs(pairs, name, tamper, order)
			req := CloneRequest(base)
			cloneURL(req, base)
			req.URL.RawQuery = encodeOrderedPairs(polluted)
			out = append(out, model.Variant{
				Base:     req,
				Identity: nil, // credentials unchanged — same rejected caller
				Mutation: model.Mutation{
					Type: "parameter-pollution",
					Description: "duplicate query parameter " + name + " (" + order +
						" tamper value) to exploit cross-layer HPP parsing disagreement",
					Detail: map[string]string{
						"parameter-pollution": "query:" + name + ":" + order,
						"technique":           "query-pollute:" + order,
						"surface":             "query",
						"parameter":           name,
						"order":               order,
						"tamper_value":        tamper,
					},
					Class: "authz-bypass",
				},
			})
		}
	}
	return out
}

// bodyVariants duplicates each urlencoded body parameter with the tamper value.
func (pp ParamPollution) bodyVariants(base *model.CapturedRequest, tamper string) []model.Variant {
	if len(base.Body) == 0 || !isFormURLEncoded(base.ContentType) {
		return nil
	}
	pairs, err := parseOrderedPairs(string(base.Body))
	if err != nil || len(pairs) == 0 {
		return nil
	}

	names := distinctNames(pairs)
	var out []model.Variant
	for _, name := range names {
		for _, order := range pollutionOrder {
			polluted := pollutePairs(pairs, name, tamper, order)
			req := CloneRequest(base)
			req.Body = []byte(encodeOrderedPairs(polluted))
			out = append(out, model.Variant{
				Base:     req,
				Identity: nil, // credentials unchanged — same rejected caller
				Mutation: model.Mutation{
					Type: "parameter-pollution",
					Description: "duplicate form-body parameter " + name + " (" + order +
						" tamper value) to exploit cross-layer HPP parsing disagreement",
					Detail: map[string]string{
						"parameter-pollution": "body:" + name + ":" + order,
						"technique":           "body-pollute:" + order,
						"surface":             "body",
						"parameter":           name,
						"order":               order,
						"tamper_value":        tamper,
					},
					Class: "authz-bypass",
				},
			})
		}
	}
	return out
}

// orderedPair is one name=value occurrence, retaining input order. HPP depends
// on occurrence order, so url.Values (a map, unordered) is unsuitable.
type orderedPair struct {
	name  string
	value string
}

// parseOrderedPairs decodes a urlencoded string (query or form body) into an
// ordered slice of name=value occurrences. Duplicate names are preserved as
// separate entries. A bare key (no '=') is kept with an empty value.
func parseOrderedPairs(raw string) ([]orderedPair, error) {
	var out []orderedPair
	for _, segment := range strings.Split(raw, "&") {
		if segment == "" {
			continue
		}
		key, val, found := strings.Cut(segment, "=")
		name, err := url.QueryUnescape(key)
		if err != nil {
			return nil, err
		}
		if !found {
			out = append(out, orderedPair{name: name})
			continue
		}
		value, err := url.QueryUnescape(val)
		if err != nil {
			return nil, err
		}
		out = append(out, orderedPair{name: name, value: value})
	}
	return out, nil
}

// encodeOrderedPairs re-encodes ordered pairs back into a urlencoded string,
// preserving occurrence order (unlike url.Values.Encode, which sorts and
// thereby destroys the HPP ordering signal).
func encodeOrderedPairs(pairs []orderedPair) string {
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(p.name))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(p.value))
	}
	return b.String()
}

// distinctNames returns the distinct parameter names in sorted order, giving a
// deterministic per-parameter iteration order independent of input order.
func distinctNames(pairs []orderedPair) []string {
	seen := make(map[string]struct{}, len(pairs))
	var names []string
	for _, p := range pairs {
		if _, ok := seen[p.name]; ok {
			continue
		}
		seen[p.name] = struct{}{}
		names = append(names, p.name)
	}
	sort.Strings(names)
	return names
}

// pollutePairs returns a copy of pairs with a tamper occurrence of name
// inserted. For "append" the tamper occurrence is placed immediately after the
// LAST existing occurrence of name; for "prepend" immediately before the FIRST.
// All original occurrences are preserved so a gate that reads the expected
// value still passes.
func pollutePairs(pairs []orderedPair, name, tamper, order string) []orderedPair {
	out := make([]orderedPair, 0, len(pairs)+1)
	inject := orderedPair{name: name, value: tamper}

	switch order {
	case "prepend":
		firstIdx := indexOfName(pairs, name)
		for i, p := range pairs {
			if i == firstIdx {
				out = append(out, inject)
			}
			out = append(out, p)
		}
	default: // "append"
		lastIdx := lastIndexOfName(pairs, name)
		for i, p := range pairs {
			out = append(out, p)
			if i == lastIdx {
				out = append(out, inject)
			}
		}
	}
	return out
}

// indexOfName returns the index of the first occurrence of name, or -1.
func indexOfName(pairs []orderedPair, name string) int {
	for i, p := range pairs {
		if p.name == name {
			return i
		}
	}
	return -1
}

// lastIndexOfName returns the index of the last occurrence of name, or -1.
func lastIndexOfName(pairs []orderedPair, name string) int {
	idx := -1
	for i, p := range pairs {
		if p.name == name {
			idx = i
		}
	}
	return idx
}

// isFormURLEncoded reports whether contentType is (or carries) the urlencoded
// form media type. Parameters (e.g. "; charset=utf-8") are tolerated.
func isFormURLEncoded(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct == formContentType
}
