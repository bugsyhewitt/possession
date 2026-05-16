// Package parse converts HAR files and curl commands into a uniform stream
// of model.CapturedRequest values for the normalize stage.
package parse

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// staticExtensions is the set of file extensions we always treat as
// non-API assets and drop during HAR import. Lower-case, leading dot.
var staticExtensions = map[string]struct{}{
	".js":    {},
	".css":   {},
	".png":   {},
	".jpg":   {},
	".jpeg":  {},
	".gif":   {},
	".svg":   {},
	".ico":   {},
	".woff":  {},
	".woff2": {},
	".ttf":   {},
	".map":   {},
}

// staticContentTypes is the set of content-type prefixes we drop when the
// HAR record provides a content-type header.
var staticContentTypes = []string{
	"image/",
	"font/",
	"text/css",
	"application/javascript",
}

// AnalyticsHosts is the extensible list of analytics/telemetry hosts we
// always drop. Exported so that future code (or tests) can extend it.
var AnalyticsHosts = []string{
	"google-analytics.com",
	"googletagmanager.com",
	"doubleclick.net",
	"segment.io",
	"sentry.io",
}

// HAR parses a HAR 1.2 document from r and returns one CapturedRequest per
// surviving entry. Static assets, font/image/css/js responses, and
// well-known analytics hosts are filtered out.
//
// A malformed document returns a descriptive error rather than panicking;
// individual entries with unparseable URLs are skipped with no error so
// that one bad entry does not poison an otherwise useful capture.
func HAR(r io.Reader) ([]*model.CapturedRequest, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("har: read: %w", err)
	}
	var f harFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("har: decode: %w", err)
	}
	if len(f.Log.Entries) == 0 {
		return nil, nil
	}
	out := make([]*model.CapturedRequest, 0, len(f.Log.Entries))
	for i, e := range f.Log.Entries {
		req, ok := harEntryToCaptured(e, i)
		if !ok {
			continue
		}
		out = append(out, req)
	}
	return out, nil
}

func harEntryToCaptured(e harEntry, idx int) (*model.CapturedRequest, bool) {
	if e.Request.URL == "" || e.Request.Method == "" {
		return nil, false
	}
	u, err := url.Parse(e.Request.URL)
	if err != nil {
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
	for _, h := range e.Request.Headers {
		hdr.Add(h.Name, h.Value)
		if strings.EqualFold(h.Name, "Content-Type") && contentType == "" {
			contentType = h.Value
		}
	}
	if isStaticContentType(contentType) {
		return nil, false
	}

	cookies := make([]*http.Cookie, 0, len(e.Request.Cookies))
	for _, c := range e.Request.Cookies {
		cookies = append(cookies, &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Path:     c.Path,
			Domain:   c.Domain,
			HttpOnly: c.HTTPOnly,
			Secure:   c.Secure,
		})
	}

	var body []byte
	if e.Request.PostData != nil && e.Request.PostData.Text != "" {
		body = []byte(e.Request.PostData.Text)
		if contentType == "" {
			contentType = e.Request.PostData.MimeType
		}
	}

	req := &model.CapturedRequest{
		Method:      e.Request.Method,
		URL:         u,
		Headers:     hdr,
		Cookies:     cookies,
		Body:        body,
		ContentType: contentType,
		Source:      fmt.Sprintf("har:entries[%d]", idx),
	}
	req.ID = stableID(req)
	return req, true
}

// isFilteredHost reports whether host matches one of the known analytics
// hosts (suffix-match so that `www.google-analytics.com` is also dropped).
func isFilteredHost(host string) bool {
	host = strings.ToLower(host)
	for _, a := range AnalyticsHosts {
		if host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

func isStaticPath(p string) bool {
	ext := strings.ToLower(path.Ext(p))
	_, ok := staticExtensions[ext]
	return ok
}

func isStaticContentType(ct string) bool {
	if ct == "" {
		return false
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	// Strip charset / boundary parameters.
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	for _, prefix := range staticContentTypes {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	return false
}

// stableID produces a deterministic identifier for a captured request based
// on the fields that define its replay identity: method, full URL, and
// body. Identical captures from different sources collapse to the same ID.
func stableID(r *model.CapturedRequest) string {
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
