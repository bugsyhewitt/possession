package mutate

import (
	"net/http"
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// ContentTypeConfusion is the Content-Type confusion / parser-sniffing
// access-control bypass mutator. Where ParamPollution attacks *which copy of a
// duplicated parameter each layer reads*, HostHeader attacks *which host the
// access-control layer believes the request targets*, and XXE attacks *how the
// XML parser resolves entities*, ContentTypeConfusion attacks *which body
// parser each layer of the stack chooses* — the canonical "Content-Type
// confusion" family every modern API security cheat-sheet describes.
//
// The bug being tested: a fronting WAF / API gateway / framework router
// dispatches the request body to a parser based on the declared Content-Type,
// but the application handler ignores the declared type and content-sniffs the
// body (or vice-versa). By keeping the body shape unchanged and mismatching
// the Content-Type header, the variant probes for two related defects:
//
//   - the WAF/gateway short-circuits its body-inspection rules ("this is
//     text/plain, no JSON to validate") while the handler still parses the
//     body as JSON and executes its logic — letting an attacker bypass
//     input-validation rules without touching the body;
//
//   - the handler is wired to multiple parsers (JSON ↔ XML ↔ form) and
//     coerces between them based on Content-Type, exposing an alternate
//     code path with weaker authorization checks (XML parsers, in
//     particular, often skip the JSON-body authz middleware).
//
// Every variant keeps the caller's own credentials (Identity == nil) — this is
// NOT an identity swap; the same caller's request slips past the gate by
// claiming a different body format. The bug being tested is "the same caller's
// same body is parsed differently when re-labelled."
//
// Body-shape detection is intentionally narrow to keep variant counts bounded
// and deterministic per request:
//
//   - JSON body (object or array, or Content-Type contains "json"): emit
//     variants relabelling it as text/plain, application/xml, and
//     application/x-www-form-urlencoded; plus a strip-content-type variant
//     that drops the header entirely (forcing the receiver to sniff).
//
//   - XML body (Content-Type contains "xml", or body starts with "<?xml" /
//     a recognizable tag): emit variants relabelling it as application/json
//     and text/plain.
//
//   - urlencoded form body (Content-Type contains "x-www-form-urlencoded"):
//     emit a variant relabelling it as application/json (some frameworks
//     attempt JSON-parse on a urlencoded body and accept the empty/error
//     result as a no-op; the WAF, having matched "form", skips field
//     validation).
//
// Bodies whose declared and sniffed type already agree on "other" (binary,
// multipart, empty) produce no variants — there is nothing for a parser to
// confuse them with.
//
// The strip-content-type technique is emitted only for JSON bodies (the
// most common API body shape and the one where missing-Content-Type sniffing
// has the highest hit rate); XML / urlencoded bodies need their declared
// type for the alternate-parser to even consider them, so a stripped variant
// would be a no-op rather than a probe.
//
// Detection rides the existing comparative ladder unchanged: the caller's
// baseline against the protected endpoint with its honest Content-Type is the
// reference response; a variant that returns an owner-shaped 2xx where the
// baseline was denied, OR that diverges meaningfully from the baseline in a
// way that suggests a different code path executed, is the bypass. Findings
// are class "authz-bypass" (ASVS V8.3.x, severity high) — the same class the
// sibling bypass mutators use.
//
// Generate is pure and deterministic: the body shape is classified by a fixed
// heuristic, the technique set is fixed per shape, and techniques are emitted
// in sorted order, so identical inputs yield an identical variant slice
// (--dry-run and the offline corpus cover it).
//
// ContentTypeConfusion is OFF by default (Enabled == false). The relabelled
// variants re-issue the request and can reach alternate-parser code paths
// with weaker validation, so it only fires when the operator explicitly opts
// in via --content-type-confusion. This mirrors the off-by-default gating of
// OriginSpoof, ParamPollution, HeaderInjection, CookieTamper, HostHeader,
// MethodOverride, CSRFHeader, ForbiddenBypass, WSHijack, XXE, MassAssign,
// and EnumerateID.
type ContentTypeConfusion struct {
	Enabled bool
}

func (ContentTypeConfusion) Name() string { return "content-type-confusion" }

// ctcTechnique names a single Content-Type relabelling strategy. Each emits a
// separate variant so the reporter can attribute a confirmed bypass to the
// precise parser-confusion shape that resolved.
type ctcTechnique struct {
	// name is a stable identifier used in Mutation.Detail and ordering.
	name string
	// targetType is the Content-Type value the variant declares (empty means
	// "drop the Content-Type header entirely" for the strip technique).
	targetType string
	// strip, when true, removes the Content-Type header instead of setting
	// it. targetType is ignored when strip is true.
	strip bool
}

// ctcJSONTechniques are the techniques emitted for a JSON-bodied request.
// Sorted by name so generation order is deterministic without a sort at call
// time (the order test still sorts as a safety belt).
var ctcJSONTechniques = []ctcTechnique{
	{name: "as-form", targetType: "application/x-www-form-urlencoded"},
	{name: "as-text", targetType: "text/plain"},
	{name: "as-xml", targetType: "application/xml"},
	{name: "strip-type", strip: true},
}

// ctcXMLTechniques are the techniques emitted for an XML-bodied request.
var ctcXMLTechniques = []ctcTechnique{
	{name: "as-json", targetType: "application/json"},
	{name: "as-text", targetType: "text/plain"},
}

// ctcFormTechniques are the techniques emitted for a urlencoded-form-bodied
// request.
var ctcFormTechniques = []ctcTechnique{
	{name: "as-json", targetType: "application/json"},
}

func (c ContentTypeConfusion) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !c.Enabled || base == nil {
		return nil
	}
	if len(base.Body) == 0 {
		return nil
	}

	shape := classifyBodyShape(base.ContentType, base.Body)
	var techs []ctcTechnique
	switch shape {
	case "json":
		techs = ctcJSONTechniques
	case "xml":
		techs = ctcXMLTechniques
	case "form":
		techs = ctcFormTechniques
	default:
		return nil
	}

	// Defensive sort: techniques are declared sorted, but a future edit could
	// drift; sorting here keeps the order test honest without extra ceremony.
	techs = append([]ctcTechnique(nil), techs...)
	sort.Slice(techs, func(i, j int) bool { return techs[i].name < techs[j].name })

	out := make([]model.Variant, 0, len(techs))
	for _, t := range techs {
		// Skip a no-op relabel: if the declared Content-Type already matches
		// the target type, the variant would be byte-identical to the
		// baseline and produce a false-confidence "bypass" on noise.
		if !t.strip && contentTypeEquals(base.ContentType, t.targetType) {
			continue
		}

		req := CloneRequest(base)
		if req.Headers == nil {
			req.Headers = http.Header{}
		}
		if t.strip {
			req.Headers.Del("Content-Type")
			req.ContentType = ""
		} else {
			req.Headers.Set("Content-Type", t.targetType)
			req.ContentType = t.targetType
		}

		detail := map[string]string{
			"technique":    t.name,
			"body_shape":   shape,
			"declared_was": base.ContentType,
		}
		if t.strip {
			detail["declared_now"] = ""
		} else {
			detail["declared_now"] = t.targetType
		}

		out = append(out, model.Variant{
			Base:     req,
			Identity: nil, // credentials unchanged — caller stays the captured owner
			Mutation: model.Mutation{
				Type:        "content-type-confusion",
				Description: "relabel request Content-Type to confuse parser dispatch (" + t.name + ")",
				Detail:      detail,
				Class:       "authz-bypass",
			},
		})
	}
	return out
}

// classifyBodyShape returns "json", "xml", "form", or "" for an unrecognised /
// uninteresting body. Both the declared Content-Type and the body bytes are
// consulted so a request whose Content-Type lies or is missing is still
// classified correctly. The shape governs which technique set the mutator
// emits.
func classifyBodyShape(contentType string, body []byte) string {
	ct := strings.ToLower(contentType)

	// Content-Type is authoritative when it names a known shape.
	if strings.Contains(ct, "json") {
		return "json"
	}
	if strings.Contains(ct, "xml") {
		return "xml"
	}
	if strings.Contains(ct, "x-www-form-urlencoded") {
		return "form"
	}

	// No Content-Type or an unfamiliar one — sniff the body shape.
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return ""
	}
	switch trimmed[0] {
	case '{', '[':
		return "json"
	case '<':
		if len(trimmed) > 1 {
			c := trimmed[1]
			if c == '?' || c == '!' || c == '/' ||
				(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				return "xml"
			}
		}
	}
	// urlencoded forms are hard to sniff (k=v&k=v is also valid text); only
	// classify by Content-Type to keep the heuristic conservative.
	return ""
}

// contentTypeEquals reports whether two Content-Type strings name the same
// media type. The comparison is case-insensitive on the media-type token and
// ignores parameters (charset, boundary, …) so "application/json" and
// "application/json; charset=utf-8" compare equal — relabelling the latter to
// the former would be a no-op and must be skipped.
func contentTypeEquals(a, b string) bool {
	return strings.EqualFold(splitMediaType(a), splitMediaType(b))
}

// splitMediaType returns the media-type token (everything before the first
// ";"), trimmed. Empty input returns empty.
func splitMediaType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(ct)
}
