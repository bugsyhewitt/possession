package model

import (
	"net/http"
	"net/url"
)

// CapturedRequest is a single observed HTTP request — the unit produced by
// the parse stage and consumed by the normalize stage. It is meant to be
// replayable: all data needed to re-issue the request must be present.
//
// PathTemplate is populated by the normalize stage; parsers should leave it
// empty.
type CapturedRequest struct {
	// ID is a stable identifier derived from method + URL + body, used to
	// deduplicate logically identical captures across input sources.
	ID string

	Method       string
	URL          *url.URL
	PathTemplate string // filled by normalize stage
	Headers      http.Header
	Cookies      []*http.Cookie
	Body         []byte
	ContentType  string

	// Source describes provenance (e.g. "har:entries[3]" or "curl").
	Source string
}
