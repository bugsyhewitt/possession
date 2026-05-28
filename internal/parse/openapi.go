package parse

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/bugsyhewitt/possession/internal/model"
)

// OpenAPI parses an OpenAPI/Swagger 3.x document (JSON or YAML) from r and
// synthesizes one CapturedRequest per operation. Each request uses the
// document's first server URL (or a relative URL if none is given), with path
// parameters filled from spec examples, required query/header parameters
// appended, and a minimal JSON body synthesized from the requestBody schema.
//
// This is a pragmatic subset of OpenAPI 3.x: it resolves local `$ref`
// pointers within the document, honors `example`/`examples`/`default` values
// and `enum` first-values, and synthesizes example objects from `properties`.
// It does not evaluate `allOf`/`oneOf`/`anyOf` composition beyond a shallow
// merge of `allOf`, and it does not fetch external references.
//
// A malformed document returns a descriptive error. Individual operations
// that cannot be turned into a replayable request are skipped without failing
// the whole parse, so one bad operation does not poison a useful spec.
func OpenAPI(r io.Reader) ([]*model.CapturedRequest, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("openapi: read: %w", err)
	}
	doc, err := decodeSpec(data)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, errors.New("openapi: empty document")
	}

	p := &openapiParser{doc: doc}

	if v, ok := stringField(doc, "openapi"); ok {
		if !strings.HasPrefix(v, "3.") {
			return nil, fmt.Errorf("openapi: unsupported version %q (only 3.x is supported)", v)
		}
	} else if _, hasSwagger := doc["swagger"]; hasSwagger {
		return nil, errors.New("openapi: Swagger 2.0 is not supported (only OpenAPI 3.x)")
	} else {
		return nil, errors.New("openapi: missing \"openapi\" version field")
	}

	base := p.baseURL()

	paths, _ := doc["paths"].(map[string]interface{})
	if len(paths) == 0 {
		return nil, errors.New("openapi: document has no paths")
	}

	// Iterate in deterministic order so output is stable across runs.
	pathKeys := sortedKeys(paths)
	out := make([]*model.CapturedRequest, 0, len(pathKeys))
	for _, rawPath := range pathKeys {
		item, ok := paths[rawPath].(map[string]interface{})
		if !ok {
			continue
		}
		item = p.deref(item)

		// Path-level parameters apply to every operation under this item.
		pathParams := toParamList(item["parameters"], p)

		for _, method := range methodKeys(item) {
			op, ok := item[method].(map[string]interface{})
			if !ok {
				continue
			}
			op = p.deref(op)
			req := p.buildRequest(base, strings.ToUpper(method), rawPath, op, pathParams)
			if req != nil {
				out = append(out, req)
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("openapi: no usable operations found")
	}
	return out, nil
}

type openapiParser struct {
	doc map[string]interface{}
}

// httpMethods is the set of OpenAPI operation keys under a path item.
var httpMethods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

func methodKeys(item map[string]interface{}) []string {
	var out []string
	for _, m := range httpMethods {
		if _, ok := item[m]; ok {
			out = append(out, m)
		}
	}
	return out
}

func (p *openapiParser) buildRequest(base, method, rawPath string, op map[string]interface{}, pathParams []param) *model.CapturedRequest {
	// Merge operation parameters over path-level ones (operation wins on
	// in+name collision).
	params := mergeParams(pathParams, toParamList(op["parameters"], p))

	path, query, headers, ok := fillPath(rawPath, params)
	if !ok {
		// A required path param had no usable value and we could not fill the
		// template — skip rather than emit an unreplayable URL.
		return nil
	}

	rawURL := joinURL(base, path)
	if len(query) > 0 {
		rawURL += "?" + query.Encode()
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	hdr := http.Header{}
	for name, vals := range headers {
		for _, v := range vals {
			hdr.Add(name, v)
		}
	}

	var body []byte
	var contentType string
	if rb, ok := op["requestBody"].(map[string]interface{}); ok {
		rb = p.deref(rb)
		body, contentType = p.synthBody(rb)
		if contentType != "" {
			hdr.Set("Content-Type", contentType)
		}
	}

	req := &model.CapturedRequest{
		Method:      method,
		URL:         u,
		Headers:     hdr,
		Body:        body,
		ContentType: contentType,
		Source:      fmt.Sprintf("openapi:%s %s", method, rawPath),
	}
	req.ID = stableOpenAPIID(req)
	return req
}

// param is the resolved, value-bearing form of an OpenAPI parameter object.
type param struct {
	name     string
	in       string // "path" | "query" | "header" | "cookie"
	required bool
	value    string
	hasValue bool
}

func toParamList(v interface{}, p *openapiParser) []param {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]param, 0, len(arr))
	for _, raw := range arr {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		m = p.deref(m)
		name, _ := stringField(m, "name")
		in, _ := stringField(m, "in")
		if name == "" || in == "" {
			continue
		}
		req, _ := m["required"].(bool)
		val, has := p.paramValue(m)
		out = append(out, param{
			name:     name,
			in:       strings.ToLower(in),
			required: req,
			value:    val,
			hasValue: has,
		})
	}
	return out
}

// mergeParams overlays op params on top of path params, keyed by (in,name).
func mergeParams(base, over []param) []param {
	idx := map[string]int{}
	out := make([]param, 0, len(base)+len(over))
	add := func(pr param) {
		key := pr.in + "\x00" + pr.name
		if i, ok := idx[key]; ok {
			out[i] = pr
			return
		}
		idx[key] = len(out)
		out = append(out, pr)
	}
	for _, pr := range base {
		add(pr)
	}
	for _, pr := range over {
		add(pr)
	}
	return out
}

// paramValue resolves a usable string value for a parameter, preferring an
// explicit example, then the schema example/default/enum, then a synthesized
// placeholder derived from the schema type.
func (p *openapiParser) paramValue(m map[string]interface{}) (string, bool) {
	if v, ok := m["example"]; ok {
		return scalarToString(v), true
	}
	if exs, ok := m["examples"].(map[string]interface{}); ok {
		for _, k := range sortedKeys(exs) {
			if ex, ok := exs[k].(map[string]interface{}); ok {
				if v, ok := ex["value"]; ok {
					return scalarToString(v), true
				}
			}
		}
	}
	if sch, ok := m["schema"].(map[string]interface{}); ok {
		sch = p.deref(sch)
		if v, ok := schemaScalarExample(sch); ok {
			return v, true
		}
	}
	return "", false
}

// fillPath substitutes {param} segments and collects required query/header
// values. Returns ok=false if a required path parameter cannot be filled.
func fillPath(rawPath string, params []param) (path string, query url.Values, headers http.Header, ok bool) {
	query = url.Values{}
	headers = http.Header{}

	byName := map[string]param{}
	for _, pr := range params {
		if pr.in == "path" {
			byName[pr.name] = pr
		}
	}

	path = rawPath
	// Replace each {name} placeholder with its value or a stable default.
	for {
		i := strings.IndexByte(path, '{')
		if i < 0 {
			break
		}
		j := strings.IndexByte(path[i:], '}')
		if j < 0 {
			break
		}
		j += i
		name := path[i+1 : j]
		val := ""
		if pr, found := byName[name]; found && pr.hasValue && pr.value != "" {
			val = pr.value
		} else {
			// No example for a path param: fall back to a stable placeholder
			// so the URL is still replayable and the normalize stage can
			// template it back to {id}. We use "1" for id-shaped names and the
			// param name otherwise.
			val = defaultPathValue(name)
		}
		path = path[:i] + url.PathEscape(val) + path[j+1:]
	}

	for _, pr := range params {
		switch pr.in {
		case "query":
			if pr.required || pr.hasValue {
				if pr.hasValue {
					query.Set(pr.name, pr.value)
				} else {
					query.Set(pr.name, defaultPathValue(pr.name))
				}
			}
		case "header":
			if pr.required || pr.hasValue {
				v := pr.value
				if !pr.hasValue {
					v = defaultPathValue(pr.name)
				}
				headers.Set(pr.name, v)
			}
		}
	}
	return path, query, headers, true
}

func defaultPathValue(name string) string {
	lower := strings.ToLower(name)
	if lower == "id" || strings.HasSuffix(lower, "id") || strings.HasSuffix(lower, "_id") {
		return "1"
	}
	return name
}

// synthBody picks a JSON request-body media type and synthesizes a body from
// its example or schema. Returns nil body if no JSON content is described.
func (p *openapiParser) synthBody(rb map[string]interface{}) ([]byte, string) {
	content, ok := rb["content"].(map[string]interface{})
	if !ok || len(content) == 0 {
		return nil, ""
	}
	// Prefer application/json, then any */json, then the first content type.
	mediaType := pickJSONMediaType(content)
	if mediaType == "" {
		return nil, ""
	}
	mt, ok := content[mediaType].(map[string]interface{})
	if !ok {
		return nil, ""
	}
	mt = p.deref(mt)

	// Explicit example wins.
	if v, ok := mt["example"]; ok {
		if b, err := json.Marshal(v); err == nil {
			return b, mediaType
		}
	}
	if exs, ok := mt["examples"].(map[string]interface{}); ok {
		for _, k := range sortedKeys(exs) {
			if ex, ok := exs[k].(map[string]interface{}); ok {
				if v, ok := ex["value"]; ok {
					if b, err := json.Marshal(v); err == nil {
						return b, mediaType
					}
				}
			}
		}
	}
	if sch, ok := mt["schema"].(map[string]interface{}); ok {
		sch = p.deref(sch)
		val := p.synthFromSchema(sch, 0)
		if val != nil {
			if b, err := json.Marshal(val); err == nil {
				return b, mediaType
			}
		}
	}
	// JSON content type with no usable schema: emit an empty object so the
	// request still carries the declared content type.
	return []byte("{}"), mediaType
}

func pickJSONMediaType(content map[string]interface{}) string {
	keys := sortedKeys(content)
	for _, k := range keys {
		if strings.EqualFold(k, "application/json") {
			return k
		}
	}
	for _, k := range keys {
		base := k
		if i := strings.IndexByte(base, ';'); i >= 0 {
			base = base[:i]
		}
		if strings.HasSuffix(strings.ToLower(strings.TrimSpace(base)), "json") {
			return k
		}
	}
	return ""
}

// synthFromSchema builds an example Go value from a schema. depth guards
// against runaway recursion through self-referential schemas.
func (p *openapiParser) synthFromSchema(sch map[string]interface{}, depth int) interface{} {
	if depth > 8 || sch == nil {
		return nil
	}
	sch = p.deref(sch)

	// Shallow allOf merge: combine member properties into one object schema.
	if allOf, ok := sch["allOf"].([]interface{}); ok {
		merged := map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}
		props := merged["properties"].(map[string]interface{})
		for _, raw := range allOf {
			if m, ok := raw.(map[string]interface{}); ok {
				m = p.deref(m)
				if mp, ok := m["properties"].(map[string]interface{}); ok {
					for k, v := range mp {
						props[k] = v
					}
				}
			}
		}
		// Carry over any direct properties on the schema itself.
		if mp, ok := sch["properties"].(map[string]interface{}); ok {
			for k, v := range mp {
				props[k] = v
			}
		}
		return p.synthFromSchema(merged, depth)
	}
	if oneOf := firstComposite(sch, "oneOf", "anyOf"); oneOf != nil {
		return p.synthFromSchema(p.deref(oneOf), depth+1)
	}

	if v, ok := sch["example"]; ok {
		return v
	}
	if v, ok := sch["default"]; ok {
		return v
	}
	if enum, ok := sch["enum"].([]interface{}); ok && len(enum) > 0 {
		return enum[0]
	}

	typ, _ := stringField(sch, "type")
	switch typ {
	case "object", "":
		props, ok := sch["properties"].(map[string]interface{})
		if !ok {
			return map[string]interface{}{}
		}
		obj := map[string]interface{}{}
		for _, name := range sortedKeys(props) {
			ps, ok := props[name].(map[string]interface{})
			if !ok {
				continue
			}
			obj[name] = p.synthFromSchema(ps, depth+1)
		}
		return obj
	case "array":
		items, ok := sch["items"].(map[string]interface{})
		if !ok {
			return []interface{}{}
		}
		return []interface{}{p.synthFromSchema(items, depth+1)}
	case "string":
		if f, _ := stringField(sch, "format"); f != "" {
			return placeholderForFormat(f)
		}
		return "string"
	case "integer":
		return 0
	case "number":
		return 0
	case "boolean":
		return false
	default:
		return nil
	}
}

func firstComposite(sch map[string]interface{}, keys ...string) map[string]interface{} {
	for _, k := range keys {
		if arr, ok := sch[k].([]interface{}); ok && len(arr) > 0 {
			if m, ok := arr[0].(map[string]interface{}); ok {
				return m
			}
		}
	}
	return nil
}

// schemaScalarExample returns a string form of a scalar example/default/enum
// value, or a type-derived placeholder, for parameter filling.
func schemaScalarExample(sch map[string]interface{}) (string, bool) {
	if v, ok := sch["example"]; ok {
		return scalarToString(v), true
	}
	if v, ok := sch["default"]; ok {
		return scalarToString(v), true
	}
	if enum, ok := sch["enum"].([]interface{}); ok && len(enum) > 0 {
		return scalarToString(enum[0]), true
	}
	typ, _ := stringField(sch, "type")
	switch typ {
	case "integer", "number":
		return "1", true
	case "boolean":
		return "true", true
	case "string":
		if f, _ := stringField(sch, "format"); f != "" {
			return placeholderForFormat(f), true
		}
		return "", false
	}
	return "", false
}

func placeholderForFormat(f string) string {
	switch strings.ToLower(f) {
	case "uuid":
		return "00000000-0000-0000-0000-000000000000"
	case "date":
		return "2020-01-01"
	case "date-time":
		return "2020-01-01T00:00:00Z"
	case "email":
		return "user@example.com"
	default:
		return "string"
	}
}

// deref resolves a single local "$ref" pointer (e.g.
// "#/components/schemas/User") into the referenced object. Non-local or
// missing refs return the input unchanged. Only one level is resolved per
// call; callers that recurse will resolve chains.
func (p *openapiParser) deref(m map[string]interface{}) map[string]interface{} {
	seen := map[string]struct{}{}
	for {
		ref, ok := stringField(m, "$ref")
		if !ok {
			return m
		}
		if _, dup := seen[ref]; dup {
			return m // cycle guard
		}
		seen[ref] = struct{}{}
		target := p.resolveRef(ref)
		if target == nil {
			return m
		}
		m = target
	}
}

func (p *openapiParser) resolveRef(ref string) map[string]interface{} {
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(ref, "#/"), "/")
	var cur interface{} = p.doc
	for _, raw := range parts {
		seg := unescapeRefToken(raw)
		node, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		cur, ok = node[seg]
		if !ok {
			return nil
		}
	}
	if m, ok := cur.(map[string]interface{}); ok {
		return m
	}
	return nil
}

func unescapeRefToken(s string) string {
	s = strings.ReplaceAll(s, "~1", "/")
	s = strings.ReplaceAll(s, "~0", "~")
	return s
}

// baseURL returns the host+base-path prefix to prepend to operation paths,
// taken from the first servers[] entry. Returns "" when none is declared, in
// which case operations get relative URLs (still parseable, still templated).
func (p *openapiParser) baseURL() string {
	servers, ok := p.doc["servers"].([]interface{})
	if !ok || len(servers) == 0 {
		return ""
	}
	s, ok := servers[0].(map[string]interface{})
	if !ok {
		return ""
	}
	raw, _ := stringField(s, "url")
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Substitute server variable defaults (e.g. {basePath}).
	if vars, ok := s["variables"].(map[string]interface{}); ok {
		for name, rawVar := range vars {
			if vm, ok := rawVar.(map[string]interface{}); ok {
				if def, ok := stringField(vm, "default"); ok {
					raw = strings.ReplaceAll(raw, "{"+name+"}", def)
				}
			}
		}
	}
	return strings.TrimRight(raw, "/")
}

// joinURL concatenates a server base with an operation path, handling the
// empty-base case and avoiding double slashes.
func joinURL(base, path string) string {
	if base == "" {
		if strings.HasPrefix(path, "/") {
			return path
		}
		return "/" + path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

// decodeSpec parses raw bytes as JSON, falling back to YAML. YAML maps are
// normalized to map[string]interface{} so the rest of the parser can treat
// JSON and YAML inputs identically.
func decodeSpec(data []byte) (map[string]interface{}, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") {
		var m map[string]interface{}
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("openapi: decode json: %w", err)
		}
		return m, nil
	}
	var raw interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("openapi: decode yaml: %w", err)
	}
	norm := normalizeYAML(raw)
	m, ok := norm.(map[string]interface{})
	if !ok {
		return nil, errors.New("openapi: top-level document is not a mapping")
	}
	return m, nil
}

// normalizeYAML converts yaml.v3's map[string]interface{} / []interface{}
// trees (which already use string keys for our inputs) into a form with
// consistent map[string]interface{} typing, coercing any non-string keys to
// strings defensively.
func normalizeYAML(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, val := range t {
			out[k] = normalizeYAML(val)
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, val := range t {
			out[fmt.Sprintf("%v", k)] = normalizeYAML(val)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, val := range t {
			out[i] = normalizeYAML(val)
		}
		return out
	default:
		return v
	}
}

func stringField(m map[string]interface{}, key string) (string, bool) {
	if m == nil {
		return "", false
	}
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// scalarToString renders a JSON/YAML scalar as a URL/header-safe string.
func scalarToString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		// Render integers without a trailing ".0".
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	case int:
		return fmt.Sprintf("%d", t)
	case int64:
		return fmt.Sprintf("%d", t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func sortedKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func stableOpenAPIID(r *model.CapturedRequest) string {
	h := sha1.New()
	h.Write([]byte(r.Method))
	h.Write([]byte{0})
	if r.URL != nil {
		h.Write([]byte(r.URL.String()))
	}
	h.Write([]byte{0})
	h.Write(r.Body)
	return hex.EncodeToString(h.Sum(nil))
}
