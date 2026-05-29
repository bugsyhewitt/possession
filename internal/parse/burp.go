package parse

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// Burp parses a Burp Suite XML export ("Save items" / proxy-history /
// site-map export) from r and returns one CapturedRequest per <item>. This is
// the most common capture format in the bug-bounty and pentest workflow that
// possession targets: hunters live in Burp, and "right-click → Save items"
// (or the proxy history "Save selected items") writes exactly this XML.
//
// The document shape consumed is the stable subset Burp has emitted across
// 1.x/2.x/Pro:
//
//	<?xml version="1.0"?>
//	<items burpVersion="...">
//	  <item>
//	    <url><![CDATA[https://api.example.com/api/orders/9001]]></url>
//	    <host ip="93.184.216.34">api.example.com</host>
//	    <port>443</port>
//	    <protocol>https</protocol>
//	    <method><![CDATA[GET]]></method>
//	    <path><![CDATA[/api/orders/9001]]></path>
//	    <request base64="true">R0VUIC9hcGkv...  (raw HTTP request, often base64)</request>
//	    <response base64="true">...</response>
//	  </item>
//	</items>
//
// The <request> element carries the full raw HTTP request — request line,
// headers, and body — and is authoritative when present: Burp's structured
// <method>/<path>/<host> fields are convenience copies, but the raw request is
// what actually went on the wire (and is what the user expects to replay). We
// parse the raw request for method, path, headers, cookies, and body, and use
// the structured <protocol>/<host>/<port>/<url> fields to reconstruct the
// absolute URL (the raw request line is usually origin-form: "GET /path").
//
// When base64="true" the element is base64-decoded; otherwise it is taken
// verbatim (Burp escapes non-base64 raw requests as XML/CDATA text). An item
// with no usable <request> falls back to the structured fields alone.
//
// Static assets, font/image/css/js content types, and well-known analytics
// hosts are filtered out, matching the HAR/mitmproxy parsers so the inputs
// dedup identically. One malformed item is skipped without failing the whole
// parse; a document that is not a recognizable Burp items export returns a
// descriptive error.
func Burp(r io.Reader) ([]*model.CapturedRequest, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("burp: read: %w", err)
	}

	var doc burpItems
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("burp: decode xml: %w", err)
	}
	if doc.XMLName.Local != "items" {
		return nil, fmt.Errorf("burp: not a Burp items export (root element is %q, want <items>)", doc.XMLName.Local)
	}
	if len(doc.Items) == 0 {
		return nil, nil
	}

	out := make([]*model.CapturedRequest, 0, len(doc.Items))
	for i, it := range doc.Items {
		req, ok := burpItemToCaptured(it, i)
		if !ok {
			continue
		}
		out = append(out, req)
	}
	return out, nil
}

func burpItemToCaptured(it burpItem, idx int) (*model.CapturedRequest, bool) {
	u, ok := it.url()
	if !ok {
		return nil, false
	}
	if isFilteredHost(u.Host) {
		return nil, false
	}
	if isStaticPath(u.Path) {
		return nil, false
	}

	method := strings.ToUpper(strings.TrimSpace(it.Method))

	hdr := http.Header{}
	var body []byte
	var contentType string

	// The raw request is authoritative when present.
	if raw, ok := it.rawRequest(); ok {
		rm, rhdr, rbody, ok := parseRawHTTPRequest(raw)
		if ok {
			if rm != "" {
				method = rm
			}
			hdr = rhdr
			body = rbody
		}
	}

	if method == "" {
		return nil, false
	}

	for k := range hdr {
		if strings.EqualFold(k, "Content-Type") {
			contentType = hdr.Get(k)
			break
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

	req := &model.CapturedRequest{
		Method:      method,
		URL:         u,
		Headers:     hdr,
		Cookies:     cookies,
		Body:        body,
		ContentType: contentType,
		Source:      fmt.Sprintf("burp:items[%d]", idx),
	}
	req.ID = stableID(req)
	return req, true
}

// url reconstructs the absolute request URL for a Burp item. The explicit
// <url> field is preferred (Burp writes the full absolute URL there); if it is
// absent or unparseable, the URL is assembled from <protocol>/<host>/<port>/<path>.
func (it *burpItem) url() (*url.URL, bool) {
	if raw := strings.TrimSpace(it.URL); raw != "" {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			return u, true
		}
	}

	host := strings.TrimSpace(it.Host)
	if host == "" {
		return nil, false
	}

	scheme := strings.ToLower(strings.TrimSpace(it.Protocol))
	if scheme == "" {
		scheme = "https"
	}

	if port := strings.TrimSpace(it.Port); port != "" {
		if n, err := strconv.Atoi(port); err == nil && n != 0 && !isDefaultPort(scheme, n) {
			host = host + ":" + port
		}
	}

	pathPart := strings.TrimSpace(it.Path)
	if pathPart == "" {
		pathPart = "/"
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

// rawRequest returns the decoded raw HTTP request bytes for the item, honoring
// the base64="true" attribute. Returns ok=false when there is no request body.
func (it *burpItem) rawRequest() ([]byte, bool) {
	raw := it.Request.Value
	if strings.TrimSpace(raw) == "" {
		return nil, false
	}
	if strings.EqualFold(strings.TrimSpace(it.Request.Base64), "true") {
		dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
		if err != nil {
			return nil, false
		}
		return dec, true
	}
	return []byte(raw), true
}

// parseRawHTTPRequest splits a raw HTTP/1.x request (request line + CRLF/LF
// headers + blank line + body) into method, headers, and body. The request
// line's path is intentionally NOT returned: the absolute URL is assembled
// from the item's structured fields (the raw request line is origin-form and
// loses scheme/host). Returns ok=false if no request line is present.
func parseRawHTTPRequest(raw []byte) (method string, hdr http.Header, body []byte, ok bool) {
	// Normalize to make the header/body split robust to LF-only exports.
	br := bufio.NewReader(bytes.NewReader(raw))

	line, err := br.ReadString('\n')
	if err != nil && line == "" {
		return "", nil, nil, false
	}
	line = strings.TrimRight(line, "\r\n")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", nil, nil, false
	}
	method = strings.ToUpper(fields[0])

	hdr = http.Header{}
	for {
		hl, err := br.ReadString('\n')
		trimmed := strings.TrimRight(hl, "\r\n")
		if trimmed == "" {
			// Blank line: end of headers. Whatever remains is the body.
			break
		}
		if i := strings.IndexByte(trimmed, ':'); i > 0 {
			name := strings.TrimSpace(trimmed[:i])
			val := strings.TrimSpace(trimmed[i+1:])
			if name != "" {
				hdr.Add(name, val)
			}
		}
		if err != nil {
			// EOF with no trailing blank line — no body follows.
			return method, hdr, nil, true
		}
	}

	rest, _ := io.ReadAll(br)
	if len(rest) > 0 {
		body = rest
	}
	return method, hdr, body, true
}

// ---- Burp items XML types (minimal, stable subset) ----

type burpItems struct {
	XMLName xml.Name   `xml:"items"`
	Items   []burpItem `xml:"item"`
}

type burpItem struct {
	URL      string      `xml:"url"`
	Host     string      `xml:"host"`
	Port     string      `xml:"port"`
	Protocol string      `xml:"protocol"`
	Method   string      `xml:"method"`
	Path     string      `xml:"path"`
	Request  burpPayload `xml:"request"`
}

// burpPayload models the <request>/<response> elements, which carry a
// base64="true|false" attribute and CDATA/text content.
type burpPayload struct {
	Base64 string `xml:"base64,attr"`
	Value  string `xml:",chardata"`
}
