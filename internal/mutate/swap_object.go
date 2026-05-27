package mutate

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// SwapObject is the resource-reference swap mutator (POST_V01 Item 1). Unlike
// SwapIdentity — which replays a baseline request under another identity's
// credentials — SwapObject keeps the original caller's credentials untouched
// and instead substitutes another identity's owned object reference into the
// request's path segments, query parameters, and JSON body fields. This is the
// textbook horizontal-IDOR / BOLA test: "can alice, using alice's own valid
// token, read bob's object?"
//
// A variant is emitted only when BOTH a source identity (the request's owner)
// and a target identity have a `resources` map AND at least one of the source
// identity's resource values actually appears in the request (path/query/body).
// For every such (source → target) pair, the matching source values are
// replaced with the target's value for the same resource key. Credentials are
// never modified, so the variant carries the source caller's auth exactly as
// captured.
//
// Like every mutator, Generate is pure and deterministic: identities are
// iterated in canonical (rank, name) order and resource keys are applied in
// sorted order, so identical inputs yield an identical variant slice.
type SwapObject struct{}

func (SwapObject) Name() string { return "swap-object" }

func (SwapObject) Generate(base *model.CapturedRequest, m *model.RoleMatrix) []model.Variant {
	if base == nil || m == nil || base.URL == nil {
		return nil
	}

	ids := sortIdentities(m.Identities)

	// Identify the source identity (the request's owner) — the identity whose
	// credentials match the captured request. SwapObject only swaps the object
	// reference for an owner that itself declares resources; otherwise we have
	// no known-owned values to look for in the request.
	source := matchOwnerIdentity(base, ids)
	if source == nil || len(source.Resources) == 0 {
		return nil
	}

	var out []model.Variant
	for i := range ids {
		target := &ids[i]
		if target.Name == source.Name {
			continue // swapping an identity's object into its own request is a no-op
		}
		if len(target.Resources) == 0 {
			continue
		}
		// Resource keys present in BOTH source and target, sorted for
		// deterministic application order.
		keys := sharedResourceKeys(source.Resources, target.Resources)
		if len(keys) == 0 {
			continue
		}

		req := CloneRequest(base)
		cloneURL(req, base)

		swapped := map[string]string{}
		for _, key := range keys {
			from := source.Resources[key]
			to := target.Resources[key]
			if from == "" || to == "" || from == to {
				continue
			}
			if substituteResource(req, key, from, to) {
				swapped[key] = from + "→" + to
			}
		}
		// No actual substitution happened — the source's owned values never
		// appeared in this request, so there's nothing to test.
		if len(swapped) == 0 {
			continue
		}

		detail := map[string]string{
			"caller":      source.Name,
			"object_from": source.Name,
			"object_to":   target.Name,
		}
		for k, v := range swapped {
			detail["swap_"+k] = v
		}

		out = append(out, model.Variant{
			Base:     req,
			Identity: source, // credentials remain the original caller's
			Mutation: model.Mutation{
				Type:        "swap-object",
				Description: "replay as " + source.Name + " against " + target.Name + "'s object reference",
				Detail:      detail,
				Class:       "idor",
			},
		})
	}
	return out
}

// matchOwnerIdentity returns the identity whose credentials match the captured
// request's auth headers/cookies, using the same over-inclusive first-match
// logic the rest of the system uses for owner attribution. Returns nil if no
// identity matches.
func matchOwnerIdentity(base *model.CapturedRequest, ids []model.Identity) *model.Identity {
	bearer := ""
	if auth := base.Headers.Get("Authorization"); len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
		bearer = auth[7:]
	}
	for i := range ids {
		id := &ids[i]
		if id.Creds == nil {
			continue
		}
		c := id.Creds
		if bearer != "" && c.Bearer == bearer {
			return id
		}
		// Header match (e.g. X-Api-Key).
		for k, v := range c.Headers {
			if v != "" && base.Headers.Get(k) == v {
				return id
			}
		}
		// Cookie match.
		for name, val := range c.Cookies {
			if val == "" {
				continue
			}
			for _, ck := range base.Cookies {
				if ck != nil && ck.Name == name && ck.Value == val {
					return id
				}
			}
		}
	}
	return nil
}

// sharedResourceKeys returns the resource keys present in both maps, sorted.
func sharedResourceKeys(a, b map[string]string) []string {
	var keys []string
	for k := range a {
		if _, ok := b[k]; ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// substituteResource replaces occurrences of from with to across the request's
// path segments, query parameter values, and JSON body fields. Matching is by
// exact value: any path segment, query-param value, or JSON string leaf equal
// to the source identity's owned value is rewritten to the target's value.
// This captures the reference regardless of the param/field name it travels
// under (account_id, id, userId, raw path segment, …), which is exactly how
// IDOR references appear in practice. Returns true if any substitution
// occurred.
func substituteResource(req *model.CapturedRequest, key, from, to string) bool {
	changed := false
	if substitutePath(req, from, to) {
		changed = true
	}
	if substituteQuery(req, from, to) {
		changed = true
	}
	if substituteJSONBody(req, from, to) {
		changed = true
	}
	return changed
}

// substitutePath replaces any path segment equal to from with to.
func substitutePath(req *model.CapturedRequest, from, to string) bool {
	if req.URL == nil || req.URL.Path == "" {
		return false
	}
	parts := strings.Split(req.URL.Path, "/")
	changed := false
	for i, seg := range parts {
		if seg == from {
			parts[i] = to
			changed = true
		}
	}
	if changed {
		req.URL.Path = strings.Join(parts, "/")
		// Keep RawPath consistent so URL.String() emits the substituted path.
		req.URL.RawPath = ""
	}
	return changed
}

// substituteQuery rewrites any query-parameter value equal to from.
func substituteQuery(req *model.CapturedRequest, from, to string) bool {
	if req.URL == nil || req.URL.RawQuery == "" {
		return false
	}
	vals := req.URL.Query()
	changed := false
	for name, list := range vals {
		for i, v := range list {
			if v == from {
				list[i] = to
				changed = true
			}
		}
		vals[name] = list
	}
	if changed {
		req.URL.RawQuery = encodeQuerySorted(vals)
	}
	return changed
}

// encodeQuerySorted is url.Values.Encode (which sorts keys) — kept explicit so
// the deterministic-ordering contract is visible at the call site.
func encodeQuerySorted(v url.Values) string { return v.Encode() }

// substituteJSONBody rewrites any JSON string leaf equal to from. Non-JSON
// bodies and parse failures are left untouched.
func substituteJSONBody(req *model.CapturedRequest, from, to string) bool {
	if len(req.Body) == 0 {
		return false
	}
	if !looksJSON(req.ContentType, req.Body) {
		return false
	}
	var doc interface{}
	if err := json.Unmarshal(req.Body, &doc); err != nil {
		return false
	}
	changed := false
	walked := walkJSON(doc, from, to, &changed)
	if !changed {
		return false
	}
	out, err := json.Marshal(walked)
	if err != nil {
		return false
	}
	req.Body = out
	return true
}

// walkJSON recursively rewrites every string leaf equal to from.
func walkJSON(node interface{}, from, to string, changed *bool) interface{} {
	switch n := node.(type) {
	case map[string]interface{}:
		for k, v := range n {
			if s, ok := v.(string); ok && s == from {
				n[k] = to
				*changed = true
				continue
			}
			n[k] = walkJSON(v, from, to, changed)
		}
		return n
	case []interface{}:
		for i, v := range n {
			if s, ok := v.(string); ok && s == from {
				n[i] = to
				*changed = true
				continue
			}
			n[i] = walkJSON(v, from, to, changed)
		}
		return n
	default:
		return node
	}
}

// looksJSON returns true when the content type or the body shape indicates JSON.
func looksJSON(contentType string, body []byte) bool {
	if strings.Contains(strings.ToLower(contentType), "json") {
		return true
	}
	trimmed := strings.TrimSpace(string(body))
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

// cloneURL gives req its own deep copy of the baseline URL so path/query
// mutations never alias the shared baseline (CloneRequest shares the URL
// pointer because most mutators never touch it).
func cloneURL(req, base *model.CapturedRequest) {
	if base.URL == nil {
		return
	}
	u := *base.URL
	if base.URL.User != nil {
		uu := *base.URL.User
		u.User = &uu
	}
	req.URL = &u
}
