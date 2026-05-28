package parse

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// Mitmproxy parses a mitmproxy JSON flow dump from r and returns one
// CapturedRequest per HTTP flow. It accepts the two stable text serializations
// mitmproxy emits:
//
//   - A JSON array of flow objects: `[ {flow}, {flow}, ... ]`. This is what the
//     mitmproxy `jsondump`/`mitmproxy2json` addons write, and what
//     `flow.get_state()` produces when collected into a list.
//   - JSON Lines (one flow object per line): `{flow}\n{flow}\n...`. This is the
//     streaming shape `mitmdump`'s json addons emit.
//
// mitmproxy's native binary `.flow`/`.mitm` files (length-prefixed tnetstrings)
// are intentionally NOT supported: they are version-fragile and require a
// binary decoder. The documented path is `mitmdump -r capture.flow --set
// dumper_... ` / the jsondump addon, which produces the JSON handled here. HAR
// export (mitmproxy "File > Export > HAR") is covered by the HAR parser.
//
// The flow shape consumed is the stable subset of mitmproxy's request state:
//
//	{ "request": { "method", "scheme", "host", "port", "path",
//	               "headers": [["name","value"], ...], "content": "..." } }
//
// Non-HTTP flows (no "request" object), static assets, font/image/css/js
// content types, and well-known analytics hosts are filtered out, matching the
// HAR parser's hygiene so the two inputs dedup identically. One malformed flow
// is skipped without failing the whole parse; a document that is not a
// recognizable mitmproxy JSON dump returns a descriptive error.
func Mitmproxy(r io.Reader) ([]*model.CapturedRequest, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("mitmproxy: read: %w", err)
	}

	flows, err := decodeFlows(data)
	if err != nil {
		return nil, err
	}
	if len(flows) == 0 {
		return nil, nil
	}

	out := make([]*model.CapturedRequest, 0, len(flows))
	for i, fl := range flows {
		req, ok := mitmFlowToCaptured(fl, i)
		if !ok {
			continue
		}
		out = append(out, req)
	}
	return out, nil
}

// decodeFlows accepts either a JSON array of flow objects or JSON Lines (one
// flow object per line). It sniffs the first non-space byte: '[' => array,
// '{' => JSONL.
func decodeFlows(data []byte) ([]mitmFlow, error) {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, errors.New("mitmproxy: empty input")
	}

	switch trimmed[0] {
	case '[':
		var flows []mitmFlow
		if err := json.Unmarshal(data, &flows); err != nil {
			return nil, fmt.Errorf("mitmproxy: decode json array: %w", err)
		}
		return flows, nil
	case '{':
		return decodeFlowLines(data)
	default:
		return nil, errors.New("mitmproxy: not a mitmproxy JSON dump (expected '[' array or '{' JSON-lines)")
	}
}

// decodeFlowLines decodes a JSON Lines stream. Blank lines are skipped. A line
// that fails to decode is skipped (one corrupt line does not poison the
// capture) unless no line decodes at all, in which case the input is rejected.
func decodeFlowLines(data []byte) ([]mitmFlow, error) {
	var flows []mitmFlow
	sc := bufio.NewScanner(bytes.NewReader(data))
	// mitmproxy flow bodies can be large; raise the line cap from the 64K default.
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	any := false
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		any = true
		var fl mitmFlow
		if err := json.Unmarshal(line, &fl); err != nil {
			continue // skip the bad line, keep the rest
		}
		flows = append(flows, fl)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("mitmproxy: scan json-lines: %w", err)
	}
	if !any {
		return nil, errors.New("mitmproxy: no JSON-lines flows found")
	}
	if len(flows) == 0 {
		return nil, errors.New("mitmproxy: no decodable flows (none matched the mitmproxy flow shape)")
	}
	return flows, nil
}

func mitmFlowToCaptured(fl mitmFlow, idx int) (*model.CapturedRequest, bool) {
	rq := fl.Request
	if rq == nil {
		return nil, false // non-HTTP flow (tcp/websocket/dns) — no request object
	}
	method := strings.ToUpper(strings.TrimSpace(rq.Method))
	if method == "" {
		return nil, false
	}

	u, ok := rq.url()
	if !ok {
		return nil, false
	}
	if isFilteredHost(u.Host) {
		return nil, false
	}
	if isStaticPath(u.Path) {
		return nil, false
	}

	hdr := http.Header{}
	var contentType string
	for _, h := range rq.Headers {
		name, value, ok := h.pair()
		if !ok || name == "" {
			continue
		}
		hdr.Add(name, value)
		if strings.EqualFold(name, "Content-Type") && contentType == "" {
			contentType = value
		}
	}
	if isStaticContentType(contentType) {
		return nil, false
	}

	var cookies []*http.Cookie
	if ch := hdr.Get("Cookie"); ch != "" {
		synthetic := &http.Request{Header: http.Header{"Cookie": []string{ch}}}
		cookies = synthetic.Cookies()
	}

	body := rq.body()

	req := &model.CapturedRequest{
		Method:      method,
		URL:         u,
		Headers:     hdr,
		Cookies:     cookies,
		Body:        body,
		ContentType: contentType,
		Source:      fmt.Sprintf("mitmproxy:flows[%d]", idx),
	}
	req.ID = stableMitmID(req)
	return req, true
}

// ---- mitmproxy flow state types (minimal, stable subset) ----

type mitmFlow struct {
	Request *mitmRequest `json:"request"`
}

type mitmRequest struct {
	Method string `json:"method"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	// Port is encoded as a JSON number in mitmproxy state; tolerate a string too.
	Port    mitmPort     `json:"port"`
	Path    string       `json:"path"`
	Headers []mitmHeader `json:"headers"`
	// Content is the request body. mitmproxy renders it as a (lossy-decoded)
	// string; some addons base64 it, but the common json dumps use a plain
	// string. We take it verbatim. Some exporters use "text" instead.
	Content string `json:"content"`
	Text    string `json:"text"`
}

// url reconstructs the absolute request URL. mitmproxy stores scheme/host/port
// separately from the (origin-form, query-bearing) path. If host is absent but
// the path is already absolute, fall back to parsing the path directly.
func (rq *mitmRequest) url() (*url.URL, bool) {
	pathPart := rq.Path
	if pathPart == "" {
		pathPart = "/"
	}

	if rq.Host == "" {
		// Absolute-form path (e.g. a proxied "GET http://h/p" line) — parse it.
		u, err := url.Parse(pathPart)
		if err != nil || u.Host == "" {
			return nil, false
		}
		return u, true
	}

	scheme := strings.ToLower(strings.TrimSpace(rq.Scheme))
	if scheme == "" {
		scheme = "https"
	}

	host := rq.Host
	port := rq.Port.value()
	if port != 0 && !isDefaultPort(scheme, port) {
		host = host + ":" + strconv.Itoa(port)
	}

	if !strings.HasPrefix(pathPart, "/") {
		pathPart = "/" + pathPart
	}

	u, err := url.Parse(scheme + "://" + host + pathPart)
	if err != nil {
		return nil, false
	}
	return u, true
}

func (rq *mitmRequest) body() []byte {
	if rq.Content != "" {
		return []byte(rq.Content)
	}
	if rq.Text != "" {
		return []byte(rq.Text)
	}
	return nil
}

func isDefaultPort(scheme string, port int) bool {
	return (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}

// mitmPort tolerates the port arriving as a JSON number (the norm) or a string.
type mitmPort int

func (p *mitmPort) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	if strings.HasPrefix(trimmed, "\"") {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			return nil // non-numeric string port: ignore
		}
		*p = mitmPort(n)
		return nil
	}
	var n int
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	*p = mitmPort(n)
	return nil
}

func (p mitmPort) value() int { return int(p) }

// mitmHeader tolerates both header serializations mitmproxy exporters use:
//   - a two-element array ["Name", "Value"]   (flow state / get_state)
//   - an object {"name": "...", "value": "..."} (some json addons)
type mitmHeader struct {
	name  string
	value string
}

func (h *mitmHeader) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var pair []string
		if err := json.Unmarshal(data, &pair); err != nil {
			return err
		}
		if len(pair) >= 1 {
			h.name = pair[0]
		}
		if len(pair) >= 2 {
			h.value = pair[1]
		}
		return nil
	}
	var obj struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	h.name = obj.Name
	h.value = obj.Value
	return nil
}

func (h mitmHeader) pair() (string, string, bool) {
	if h.name == "" {
		return "", "", false
	}
	return h.name, h.value, true
}

func stableMitmID(r *model.CapturedRequest) string {
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
