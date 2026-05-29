package mutate

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// GraphQL is the GraphQL body-fuzzing mutator (POST_V01 Item 6, scoped to the
// operation-level probes that fit possession's pure-mutator architecture).
// It targets endpoints that accept GraphQL POST bodies and tests two of the
// highest-signal GraphQL misconfigurations a bug-bounty hunter checks first:
//
//   - introspection: GraphQL servers that leave schema introspection enabled
//     in production leak their entire type system (queries, mutations, field
//     names, argument types) to any caller — the canonical first move against
//     a GraphQL endpoint and a real information-disclosure finding. This
//     variant replaces the captured query with the standard introspection
//     query while KEEPING the caller's own credentials, then watches for the
//     server reflecting introspection schema markers (__schema / queryType /
//     __type) back. That reflection is decisive: a server that answers an
//     introspection query MUST have introspection enabled.
//
//   - malformed-query: a deliberately invalid GraphQL document probes the
//     server for verbose/debug error responses (stack traces, "did you mean"
//     field suggestions, internal type hints) that leak schema or
//     implementation detail. It carries no canary and is judged by the normal
//     comparative ladder against the owner baseline.
//
// Where SwapIdentity attacks *who* the caller is, SwapObject attacks *which*
// object is referenced, MassAssign attacks *which properties* are bound, and
// XXE attacks *how an XML body is parsed*, GraphQL attacks *what the GraphQL
// layer exposes* — it keeps the caller's own credentials untouched
// (Identity == nil) and rewrites the GraphQL operation itself.
//
// Detection (handled in internal/detect): the introspection variant carries
// Mutation.Detail["graphql-signal"] == "introspection". The evaluator gates a
// decisive "introspection enabled" verdict on the response body reflecting the
// canonical introspection markers, mirroring the in-band XXE canary branch
// (introspection has no owner/actor baseline to compare against). The
// malformed-query variant carries Detail["graphql-signal"] == "malformed" and
// no canary, so it falls through to the comparative ladder.
//
// GraphQL detection is by content type ("graphql"), by a JSON body carrying a
// "query" (or "mutation") string field, or by a "/graphql" path. Non-GraphQL
// bodies (plain JSON without a query field, form-encoded, XML, empty) produce
// no variants.
//
// Like every mutator, Generate is pure and deterministic: the two techniques
// are emitted in a fixed (sorted-by-name) order and the canary derives only
// from the base request's deterministic ID, so identical inputs yield an
// identical variant slice.
//
// GraphQL is OFF by default (Enabled == false). The introspection and
// malformed probes are read-shaped (they never run a mutation the caller
// authored), but they are still active reconnaissance against the GraphQL
// layer, so they only fire when the operator explicitly opts in via --graphql.
// This mirrors the off-by-default gating of MassAssign, EnumerateID, JWTAuth,
// and XXE.
type GraphQL struct {
	Enabled bool
}

func (GraphQL) Name() string { return "graphql" }

// graphqlCanaryPrefix marks the unique reflection token recorded on the
// introspection variant. The full canary is this prefix plus the base
// request's deterministic ID; it is not injected into the request (the server
// can't be made to echo an arbitrary token via introspection) but is kept on
// the variant so detection notes can attribute the signal to one endpoint.
const graphqlCanaryPrefix = "possession-graphql-"

// introspectionQuery is the canonical minimal introspection query. A server
// that answers it (reflecting __schema/queryType) has introspection enabled.
// Kept compact but complete enough to force the server to walk its schema.
const introspectionQuery = `query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind } } }`

// malformedQuery is a deliberately invalid GraphQL document: it references a
// field that cannot exist and leaves a syntax fault, probing the server for
// verbose error output (field suggestions, type hints, stack traces).
const malformedQuery = `query { __possession_invalid_field__ { `

// graphqlTechnique is one GraphQL probe strategy. Each emits a separate
// variant so the reporter can attribute a hit to the precise probe.
type graphqlTechnique struct {
	// name is a stable identifier used in Mutation.Detail and ordering.
	name string
	// query is the GraphQL document this technique sends in place of the
	// captured operation.
	query string
}

// graphqlTechniques is the built-in probe set, sorted by name so generation
// order is deterministic without a sort at call time (the order test covers
// this):
//   - "introspection": decisive schema-disclosure probe (canary branch).
//   - "malformed": verbose-error probe (comparative ladder).
var graphqlTechniques = []graphqlTechnique{
	{name: "introspection", query: introspectionQuery},
	{name: "malformed", query: malformedQuery},
}

func (g GraphQL) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !g.Enabled || base == nil {
		return nil
	}
	shape, ok := graphqlBodyShape(base)
	if !ok {
		return nil
	}

	canary := graphqlCanaryPrefix + base.ID

	techs := append([]graphqlTechnique(nil), graphqlTechniques...)
	sort.Slice(techs, func(i, j int) bool { return techs[i].name < techs[j].name })

	var out []model.Variant
	for _, t := range techs {
		mutated := buildGraphQLBody(shape, base.Body, t.query)
		if mutated == nil {
			continue
		}

		req := CloneRequest(base)
		req.Body = mutated

		detail := map[string]string{
			"technique":      t.name,
			"graphql-signal": t.name,
		}
		// Only the introspection technique carries a canary detail for the
		// decisive detection branch; the malformed technique is judged by the
		// comparative ladder.
		if t.name == "introspection" {
			detail["graphql-canary"] = canary
		}

		out = append(out, model.Variant{
			Base:     req,
			Identity: nil, // credentials unchanged — caller stays the captured owner
			Mutation: model.Mutation{
				Type:        "graphql",
				Description: "probe GraphQL endpoint (" + t.name + ") using the caller's own credentials",
				Detail:      detail,
				Class:       "graphql-exposure",
			},
		})
	}
	return out
}

// graphqlShape records how the captured GraphQL request encodes its operation,
// so the mutated body can be re-encoded the same way.
type graphqlShape int

const (
	// shapeJSON: a JSON body with a top-level "query" (or "mutation") string
	// field — the standard application/json GraphQL transport.
	shapeJSON graphqlShape = iota
	// shapeRaw: a raw GraphQL document body (content type application/graphql).
	shapeRaw
)

// graphqlBodyShape reports whether base looks like a GraphQL request and, if
// so, how its operation is encoded. Recognition order:
//  1. content type application/graphql  ⇒ raw document body.
//  2. JSON body with a top-level "query"/"mutation" string field ⇒ JSON shape.
//  3. a "/graphql" path with a JSON body carrying "query" ⇒ JSON shape.
//
// A body that is not parseable as one of these is not GraphQL (ok == false),
// so non-GraphQL JSON (e.g. a plain {"name":"x"} POST) produces no variants.
func graphqlBodyShape(base *model.CapturedRequest) (graphqlShape, bool) {
	ct := strings.ToLower(base.ContentType)
	if strings.Contains(ct, "application/graphql") {
		if len(strings.TrimSpace(string(base.Body))) == 0 {
			return 0, false
		}
		return shapeRaw, true
	}
	// JSON transport: require a top-level "query" or "mutation" string field.
	if len(base.Body) > 0 {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(base.Body, &obj); err == nil {
			if hasGraphQLQueryField(obj) {
				return shapeJSON, true
			}
		}
	}
	return 0, false
}

// hasGraphQLQueryField reports whether obj has a top-level "query" or
// "mutation" field whose value is a JSON string. GraphQL-over-HTTP encodes the
// operation document in the "query" field for both queries and mutations; some
// clients use "mutation" — accept either.
func hasGraphQLQueryField(obj map[string]json.RawMessage) bool {
	for _, key := range []string{"query", "mutation"} {
		raw, ok := obj[key]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil && strings.TrimSpace(s) != "" {
			return true
		}
	}
	return false
}

// buildGraphQLBody re-encodes base's body with the operation document replaced
// by query, preserving the original transport shape. For the JSON shape it
// rewrites the "query" field (dropping any "mutation" alias and any
// "operationName"/"variables" that no longer match) and re-marshals with
// sorted keys for deterministic output. For the raw shape it returns the query
// document verbatim. Returns nil if re-encoding fails (never best-effort).
func buildGraphQLBody(shape graphqlShape, body []byte, query string) []byte {
	switch shape {
	case shapeRaw:
		return []byte(query)
	case shapeJSON:
		// Build a fresh minimal JSON envelope rather than splicing into the
		// original: the original "variables"/"operationName" reference the old
		// operation and would be invalid against the probe document. encoding/
		// json marshals struct fields in declaration order deterministically.
		env := struct {
			Query string `json:"query"`
		}{Query: query}
		out, err := json.Marshal(env)
		if err != nil {
			return nil
		}
		return out
	default:
		return nil
	}
}
