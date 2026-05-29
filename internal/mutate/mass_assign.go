package mutate

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// MassAssign is the mass-assignment / privileged-property injection mutator
// (POST_V01: BOPLA — Broken Object Property Level Authorization, OWASP API #3).
//
// Where SwapIdentity swaps the *caller* and SwapObject swaps the *object
// reference*, MassAssign keeps both the caller's credentials AND the original
// object untouched and instead *adds* privileged properties to the JSON request
// body that the caller should not be able to set — `"role":"admin"`,
// `"is_admin":true`, `"verified":true`, and so on. This is the textbook
// mass-assignment test: "if alice POSTs her own profile but smuggles in
// `is_admin:true`, does the server bind it?"
//
// The attack is property-level rather than object-level, so it only makes sense
// against a request that carries a JSON object body the server might
// auto-bind onto a model. MassAssign therefore emits variants ONLY when the
// base request has a JSON *object* body (arrays and scalar bodies are skipped).
//
// For each privileged property, a separate variant is emitted so the
// comparative ladder can attribute a bypass to the specific field that was
// accepted (one field per variant keeps repro and triage unambiguous). A
// property already present in the request body is skipped for that field — the
// caller legitimately set it, so injecting it proves nothing.
//
// Like every mutator, Generate is pure and deterministic: properties are
// applied in canonical (sorted) order, so identical inputs yield an identical
// variant slice.
//
// MassAssign is OFF by default (Enabled == false): unlike the read-shaped
// identity/object swaps, mass-assignment variants are write-shaped (they
// usually ride POST/PUT/PATCH) and mutate server state, so they only fire when
// the operator explicitly opts in via --mass-assign. This mirrors the
// off-by-default gating of EnumerateID (rate-sensitive) and JWTAuth (forgery).
type MassAssign struct {
	Enabled bool
}

func (MassAssign) Name() string { return "mass-assign" }

// PrivilegedProperty is one privileged field MassAssign attempts to smuggle
// into a request body, paired with the value it injects.
type PrivilegedProperty struct {
	Key   string
	Value interface{}
}

// PrivilegedProperties is the built-in set of properties a client should not
// normally be permitted to set on itself or its objects. Each is tested in a
// separate variant. The list is intentionally small and high-signal — the
// canonical privilege-escalation fields seen across REST APIs — to keep the
// variant count bounded and the false-positive surface low.
//
// Kept sorted by Key so generation order is deterministic without a sort at
// call time; the order test in MassAssign covers this.
var PrivilegedProperties = []PrivilegedProperty{
	{Key: "admin", Value: true},
	{Key: "is_admin", Value: true},
	{Key: "isAdmin", Value: true},
	{Key: "role", Value: "admin"},
	{Key: "roles", Value: []interface{}{"admin"}},
	{Key: "verified", Value: true},
}

func (ma MassAssign) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !ma.Enabled || base == nil {
		return nil
	}
	if len(base.Body) == 0 || !looksJSON(base.ContentType, base.Body) {
		return nil
	}

	// The body must be a JSON object — mass-assignment binds named properties
	// onto a model, which only applies to an object payload.
	var doc map[string]interface{}
	if err := json.Unmarshal(base.Body, &doc); err != nil {
		return nil
	}

	// Snapshot the existing top-level keys (case-insensitive) so we can skip
	// any privileged property the caller already legitimately sets.
	existing := make(map[string]struct{}, len(doc))
	for k := range doc {
		existing[strings.ToLower(k)] = struct{}{}
	}

	props := append([]PrivilegedProperty(nil), PrivilegedProperties...)
	sort.Slice(props, func(i, j int) bool { return props[i].Key < props[j].Key })

	var out []model.Variant
	for _, p := range props {
		if _, ok := existing[strings.ToLower(p.Key)]; ok {
			continue // already present — injecting it tests nothing
		}

		injected := injectTopLevel(base.Body, p.Key, p.Value)
		if injected == nil {
			continue
		}

		req := CloneRequest(base)
		req.Body = injected

		out = append(out, model.Variant{
			Base:     req,
			Identity: nil, // credentials unchanged — caller stays the captured owner
			Mutation: model.Mutation{
				Type:        "mass-assign",
				Description: "inject privileged property " + p.Key + " into request body",
				Detail: map[string]string{
					"field": p.Key,
					"value": stringifyJSON(p.Value),
				},
				Class: "privesc",
			},
		})
	}
	return out
}

// injectTopLevel parses body as a JSON object, sets key=value at the top
// level, and re-marshals. Returns nil on any parse/marshal failure. The
// re-marshal sorts object keys (encoding/json marshals map keys sorted), so the
// output is deterministic.
func injectTopLevel(body []byte, key string, value interface{}) []byte {
	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	doc[key] = value
	out, err := json.Marshal(doc)
	if err != nil {
		return nil
	}
	return out
}

// stringifyJSON renders a privileged value as a compact string for the
// finding Detail map. Falls back to the raw JSON encoding for non-scalars.
func stringifyJSON(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		if b, err := json.Marshal(v); err == nil {
			return string(b)
		}
		return ""
	}
}
