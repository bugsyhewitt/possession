package detect

import (
	"encoding/json"
	"sort"
	"strings"
)

// NormalizeBody returns a canonical form of body suitable for similarity
// comparison. Pure and deterministic: same input ⇒ same output.
//
// Two paths:
//   - JSON (Content-Type matches application/json OR body parses cleanly
//     as JSON): unmarshal, recursively blank values whose KEY matches any
//     entry in VolatileJSONKeys (case-insensitive substring), then
//     re-marshal with sorted keys. Stable across map-iteration order.
//   - Otherwise (HTML/text): strip CSRF hidden inputs and meta tags,
//     ISO-8601 timestamps, long hex/UUID blobs, then collapse whitespace.
//
// An empty body normalizes to "".
func NormalizeBody(body []byte, contentType string) string {
	if len(body) == 0 {
		return ""
	}
	if looksJSON(body, contentType) {
		var doc any
		if err := json.Unmarshal(body, &doc); err == nil {
			scrubJSON(doc)
			out, err := marshalSorted(doc)
			if err == nil {
				return string(out)
			}
		}
		// Fall through to text path on parse failure.
	}
	return normalizeText(string(body))
}

func looksJSON(body []byte, contentType string) bool {
	if strings.Contains(strings.ToLower(contentType), "json") {
		return true
	}
	// Cheap prefix check before trying to parse.
	for _, b := range body {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		return b == '{' || b == '['
	}
	return false
}

// scrubJSON recursively blanks values whose key matches a volatile pattern.
// Operates in place on the JSON object/array tree produced by
// json.Unmarshal into interface{}.
func scrubJSON(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			if isVolatileKey(k) {
				t[k] = ""
				continue
			}
			scrubJSON(vv)
		}
	case []any:
		for _, vv := range t {
			scrubJSON(vv)
		}
	}
}

func isVolatileKey(k string) bool {
	low := strings.ToLower(k)
	for _, pat := range VolatileJSONKeys {
		if strings.Contains(low, pat) {
			return true
		}
	}
	return false
}

// marshalSorted marshals v to JSON with sorted object keys. Uses
// encoding/json's recursion via a custom sortedJSON wrapper.
func marshalSorted(v any) ([]byte, error) {
	canon := canonicalize(v)
	return json.Marshal(canon)
}

// canonicalize rebuilds the value tree so that every map[string]any is
// replaced with a sortedJSON struct that marshals with sorted keys.
func canonicalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(sortedJSON, 0, len(keys))
		for _, k := range keys {
			out = append(out, sortedJSONEntry{K: k, V: canonicalize(t[k])})
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, vv := range t {
			out[i] = canonicalize(vv)
		}
		return out
	default:
		return v
	}
}

type sortedJSONEntry struct {
	K string
	V any
}

type sortedJSON []sortedJSONEntry

func (s sortedJSON) MarshalJSON() ([]byte, error) {
	var buf strings.Builder
	buf.WriteByte('{')
	for i, e := range s {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := json.Marshal(e.K)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := json.Marshal(e.V)
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return []byte(buf.String()), nil
}

func normalizeText(s string) string {
	s = HTMLCSRFInput.ReplaceAllString(s, "")
	s = HTMLCSRFMeta.ReplaceAllString(s, "")
	s = HTMLISO8601.ReplaceAllString(s, "")
	s = HTMLUUID.ReplaceAllString(s, "")
	s = HTMLLongHex.ReplaceAllString(s, "")
	s = HTMLWhitespace.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}
