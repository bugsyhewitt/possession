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
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// Postman parses a Postman Collection v2.0 / v2.1 export (JSON) from r and
// synthesizes one CapturedRequest per request item. Folders are walked
// recursively. Collection-, folder-, and request-level variables are resolved
// into the URL, headers, and body via {{var}} substitution.
//
// This is a pragmatic subset of the Postman Collection schema:
//   - URL is read from the request's structured `url` object (raw/host/path/
//     query/protocol) or a bare string URL.
//   - Headers come from `request.header[]`, skipping entries marked disabled.
//   - The body is read from `request.body` for the raw, urlencoded, and
//     formdata modes; file/graphql modes synthesize no body.
//   - {{variables}} are resolved from the collection's top-level `variable[]`
//     array and any `variable[]` arrays on enclosing folders/requests, with
//     the innermost scope winning.
//
// Requests that cannot be turned into a replayable URL are skipped without
// failing the whole parse, so one malformed item does not poison a useful
// collection. A document that is not a recognizable Postman v2 collection
// returns a descriptive error.
func Postman(r io.Reader) ([]*model.CapturedRequest, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("postman: read: %w", err)
	}

	var coll postmanCollection
	if err := json.Unmarshal(data, &coll); err != nil {
		return nil, fmt.Errorf("postman: decode json: %w", err)
	}

	// Validate this is actually a Postman v2 collection. The schema URL and the
	// presence of info.name + an item array are the canonical markers.
	schema := strings.ToLower(coll.Info.Schema)
	hasV2Schema := strings.Contains(schema, "collection/v2")
	if !hasV2Schema {
		if coll.Info.Schema == "" && len(coll.Item) == 0 {
			return nil, errors.New("postman: not a Postman v2 collection (missing info.schema and item)")
		}
		if strings.Contains(schema, "collection/v1") {
			return nil, errors.New("postman: Postman Collection v1 is not supported (export as v2.1)")
		}
		// No recognizable schema marker but it has items: proceed leniently so
		// hand-written or lightly-edited collections still parse.
		if len(coll.Item) == 0 {
			return nil, errors.New("postman: not a Postman v2 collection (no items)")
		}
	}

	p := &postmanParser{}
	rootVars := varMap(coll.Variable)
	p.walk(coll.Item, rootVars, "")

	if len(p.out) == 0 {
		return nil, errors.New("postman: no usable requests found")
	}
	return p.out, nil
}

type postmanParser struct {
	out []*model.CapturedRequest
}

// walk recursively descends the item tree. items may be folders (with their
// own nested item arrays and optional variable scopes) or request items.
// vars carries the merged variable scope from all enclosing levels; path is a
// breadcrumb used only for the Source provenance string.
func (p *postmanParser) walk(items []postmanItem, vars map[string]string, path string) {
	for i, it := range items {
		name := it.Name
		crumb := joinCrumb(path, name, i)

		// Folder: it has nested items. Merge any folder-scope variables and
		// recurse.
		if len(it.Item) > 0 {
			scope := mergeVars(vars, varMap(it.Variable))
			p.walk(it.Item, scope, crumb)
			continue
		}

		// Request item.
		if it.Request == nil {
			continue
		}
		scope := mergeVars(vars, varMap(it.Variable))
		if req := p.buildRequest(it.Request, scope, crumb); req != nil {
			p.out = append(p.out, req)
		}
	}
}

func (p *postmanParser) buildRequest(pr *postmanRequest, vars map[string]string, crumb string) *model.CapturedRequest {
	rawURL := pr.rawURL(vars)
	if rawURL == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	method := strings.ToUpper(strings.TrimSpace(pr.Method))
	if method == "" {
		method = "GET"
	}

	hdr := http.Header{}
	for _, h := range pr.Header {
		if h.Disabled {
			continue
		}
		name := strings.TrimSpace(substVars(h.Key, vars))
		if name == "" {
			continue
		}
		hdr.Add(name, substVars(h.Value, vars))
	}

	body, ctFromBody := pr.bodyBytes(vars)
	contentType := hdr.Get("Content-Type")
	if contentType == "" && ctFromBody != "" {
		hdr.Set("Content-Type", ctFromBody)
		contentType = ctFromBody
	}

	var cookies []*http.Cookie
	if ch := hdr.Get("Cookie"); ch != "" {
		synthetic := &http.Request{Header: http.Header{"Cookie": []string{ch}}}
		cookies = synthetic.Cookies()
	}

	req := &model.CapturedRequest{
		Method:      method,
		URL:         u,
		Headers:     hdr,
		Cookies:     cookies,
		Body:        body,
		ContentType: contentType,
		Source:      "postman:" + crumb,
	}
	req.ID = stablePostmanID(req)
	return req
}

// ---- Postman schema types (minimal) ----

type postmanCollection struct {
	Info     postmanInfo   `json:"info"`
	Item     []postmanItem `json:"item"`
	Variable []postmanVar  `json:"variable"`
}

type postmanInfo struct {
	Name   string `json:"name"`
	Schema string `json:"schema"`
}

type postmanItem struct {
	Name     string          `json:"name"`
	Item     []postmanItem   `json:"item"`     // present on folders
	Request  *postmanRequest `json:"request"`  // present on requests
	Variable []postmanVar    `json:"variable"` // optional folder/request scope
}

type postmanVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type postmanHeader struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Disabled bool   `json:"disabled"`
}

type postmanRequest struct {
	Method string          `json:"method"`
	Header []postmanHeader `json:"header"`
	URL    postmanURL      `json:"url"`
	Body   *postmanBody    `json:"body"`
}

// postmanURL is either a bare string ("https://x/y") or a structured object.
// We capture both forms via a custom unmarshaler.
type postmanURL struct {
	Raw      string
	Protocol string
	Host     []string
	Path     []string
	Query    []postmanQuery
}

type postmanQuery struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Disabled bool   `json:"disabled"`
}

func (u *postmanURL) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "null" || trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "\"") {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		u.Raw = s
		return nil
	}
	// Structured object. Use an alias to avoid recursing into this method.
	type rawURL struct {
		Raw      string         `json:"raw"`
		Protocol string         `json:"protocol"`
		Host     []string       `json:"host"`
		Path     []string       `json:"path"`
		Query    []postmanQuery `json:"query"`
	}
	var ru rawURL
	if err := json.Unmarshal(data, &ru); err != nil {
		return err
	}
	u.Raw = ru.Raw
	u.Protocol = ru.Protocol
	u.Host = ru.Host
	u.Path = ru.Path
	u.Query = ru.Query
	return nil
}

type postmanBody struct {
	Mode       string            `json:"mode"`
	Raw        string            `json:"raw"`
	URLEncoded []postmanKV       `json:"urlencoded"`
	FormData   []postmanFormData `json:"formdata"`
	Options    *postmanBodyOpts  `json:"options"`
}

type postmanBodyOpts struct {
	Raw struct {
		Language string `json:"language"`
	} `json:"raw"`
}

type postmanKV struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Disabled bool   `json:"disabled"`
}

type postmanFormData struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Type     string `json:"type"` // "text" | "file"
	Disabled bool   `json:"disabled"`
}

// ---- URL synthesis ----

// rawURL resolves the request's URL to a replayable string with variables
// substituted. It prefers the structured fields (host/path/query); if those
// are empty it falls back to the raw string form.
func (pr *postmanRequest) rawURL(vars map[string]string) string {
	u := pr.URL
	hasStructured := len(u.Host) > 0 || len(u.Path) > 0

	if !hasStructured {
		return strings.TrimSpace(substVars(u.Raw, vars))
	}

	scheme := substVars(u.Protocol, vars)
	if scheme == "" {
		scheme = "https"
	}

	host := joinSubst(u.Host, ".", vars)
	pathSegs := make([]string, 0, len(u.Path))
	for _, seg := range u.Path {
		pathSegs = append(pathSegs, substVars(seg, vars))
	}
	pathStr := strings.Join(pathSegs, "/")
	if pathStr != "" && !strings.HasPrefix(pathStr, "/") {
		pathStr = "/" + pathStr
	}

	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(host)
	b.WriteString(pathStr)

	q := url.Values{}
	for _, qp := range u.Query {
		if qp.Disabled {
			continue
		}
		key := substVars(qp.Key, vars)
		if key == "" {
			continue
		}
		q.Add(key, substVars(qp.Value, vars))
	}
	if enc := q.Encode(); enc != "" {
		b.WriteString("?")
		b.WriteString(enc)
	}
	return b.String()
}

// ---- Body synthesis ----

// bodyBytes returns the request body and a default Content-Type for the body
// mode (callers prefer an explicit Content-Type header over this). Unsupported
// modes (file, graphql, none) return a nil body.
func (pr *postmanRequest) bodyBytes(vars map[string]string) ([]byte, string) {
	b := pr.Body
	if b == nil {
		return nil, ""
	}
	switch strings.ToLower(b.Mode) {
	case "raw":
		raw := substVars(b.Raw, vars)
		if raw == "" {
			return nil, ""
		}
		ct := ""
		if b.Options != nil && strings.EqualFold(b.Options.Raw.Language, "json") {
			ct = "application/json"
		}
		return []byte(raw), ct
	case "urlencoded":
		form := url.Values{}
		for _, kv := range b.URLEncoded {
			if kv.Disabled {
				continue
			}
			key := substVars(kv.Key, vars)
			if key == "" {
				continue
			}
			form.Add(key, substVars(kv.Value, vars))
		}
		if len(form) == 0 {
			return nil, ""
		}
		return []byte(form.Encode()), "application/x-www-form-urlencoded"
	case "formdata":
		// Only text fields are replayable without multipart encoding; render
		// them as urlencoded pairs so the authz signal (the values) survives.
		// File parts are skipped.
		form := url.Values{}
		for _, fd := range b.FormData {
			if fd.Disabled || strings.EqualFold(fd.Type, "file") {
				continue
			}
			key := substVars(fd.Key, vars)
			if key == "" {
				continue
			}
			form.Add(key, substVars(fd.Value, vars))
		}
		if len(form) == 0 {
			return nil, ""
		}
		return []byte(form.Encode()), "application/x-www-form-urlencoded"
	default:
		return nil, ""
	}
}

// ---- variable resolution ----

func varMap(vs []postmanVar) map[string]string {
	if len(vs) == 0 {
		return nil
	}
	m := make(map[string]string, len(vs))
	for _, v := range vs {
		if v.Key == "" {
			continue
		}
		m[v.Key] = v.Value
	}
	return m
}

// mergeVars overlays over on top of base, returning a new map. Inner scopes
// (over) win over outer scopes (base).
func mergeVars(base, over map[string]string) map[string]string {
	if len(over) == 0 {
		return base
	}
	out := make(map[string]string, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

// substVars replaces every {{name}} occurrence with its resolved value. Names
// with no binding are left intact ({{unknown}} stays literal) so missing
// variables are visible rather than silently blanked. Substitution is
// single-pass (resolved values are not re-scanned) to avoid recursion loops.
func substVars(s string, vars map[string]string) string {
	if s == "" || !strings.Contains(s, "{{") {
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(s, "{{")
		if i < 0 {
			b.WriteString(s)
			break
		}
		j := strings.Index(s[i:], "}}")
		if j < 0 {
			b.WriteString(s)
			break
		}
		j += i
		b.WriteString(s[:i])
		name := strings.TrimSpace(s[i+2 : j])
		if val, ok := vars[name]; ok {
			b.WriteString(val)
		} else {
			b.WriteString(s[i : j+2]) // leave {{name}} literal
		}
		s = s[j+2:]
	}
	return b.String()
}

func joinSubst(parts []string, sep string, vars map[string]string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, substVars(p, vars))
	}
	return strings.Join(out, sep)
}

func joinCrumb(path, name string, idx int) string {
	if name == "" {
		name = fmt.Sprintf("item[%d]", idx)
	}
	if path == "" {
		return name
	}
	return path + "/" + name
}

func stablePostmanID(r *model.CapturedRequest) string {
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
