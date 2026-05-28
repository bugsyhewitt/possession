package report

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// ReproOptions controls how a finding's reproduction is rendered.
//
// By default credentials are redacted to placeholders so a report can be
// pasted into a public PR comment or bug-bounty submission without leaking
// live tokens. Set ShowCreds to emit real credential values for local
// triage (wired to the --repro-creds CLI flag).
type ReproOptions struct {
	ShowCreds bool
}

// reproHeaderNames lists request headers whose *values* are credential
// material and must be redacted unless ShowCreds is set. Matching is
// case-insensitive. Kept local to the report package so the reporter layer
// does not import mutate (which would pull in the detect/mutate import
// cycle the model package was carefully split to avoid).
var reproHeaderNames = []string{
	"Authorization",
	"Proxy-Authorization",
	"Cookie",
	"X-Api-Key",
	"X-Auth-Token",
	"X-Access-Token",
	"X-Session-Token",
	"X-Csrf-Token",
	"X-Csrftoken",
	"X-Xsrf-Token",
}

// isReproSensitive reports whether a header's value should be redacted.
func isReproSensitive(name string) bool {
	for _, h := range reproHeaderNames {
		if strings.EqualFold(name, h) {
			return true
		}
	}
	return false
}

// reproPlaceholder is the redaction token for a sensitive header value. The
// identity name (when known) is embedded so the reader can see *which*
// identity's credential triggered the bypass without exposing the secret —
// e.g. "<bearer:bob>". Falls back to "<redacted>" when no identity is known.
func reproPlaceholder(identity string) string {
	if identity == "" {
		return "<redacted>"
	}
	return "<bearer:" + identity + ">"
}

// Repro is the rendered reproduction for a single finding: the exact mutated
// request that triggered the bypass plus a one-line differential of the
// owner-baseline vs. variant response.
//
// Both HTTP and Curl describe the same request; reporters pick whichever
// format suits their medium. Differential is a compact, human-readable
// status/size summary suitable for an inline caption.
type Repro struct {
	HTTP         string // raw HTTP request block
	Curl         string // single-line curl command
	Differential string // "baseline 200 → variant 200 · similarity 0.97 · Δsize 0"
}

// BuildRepro renders a copy-paste reproduction for a finding. It reads the
// fully-mutated request from f.Variant.Base — which the mutate stage already
// produced as a clone of the captured request with the swap/strip applied,
// so it IS the request that was sent on the wire — and the finding's Evidence
// for the differential.
//
// When opts.ShowCreds is false (the default) every credential-bearing header
// value is replaced with an identity-tagged placeholder, so the output is
// safe to paste into a public report.
//
// Returns (zero Repro, false) when the finding carries no recoverable request
// (e.g. deserialized JSON findings where Variant was dropped) so callers can
// skip the repro block without emitting an empty section.
func BuildRepro(f model.Finding, opts ReproOptions) (Repro, bool) {
	if f.Variant == nil || f.Variant.Base == nil {
		return Repro{}, false
	}
	req := f.Variant.Base
	if req.URL == nil {
		return Repro{}, false
	}
	identity := f.Identity

	return Repro{
		HTTP:         buildHTTPBlock(req, identity, opts),
		Curl:         buildCurl(req, identity, opts),
		Differential: buildDifferential(f.Evidence),
	}, true
}

// buildHTTPBlock renders a raw HTTP/1.1 request block in canonical wire-ish
// form: request line, sorted headers, a Cookie header synthesized from the
// request's cookie jar, then the body.
func buildHTTPBlock(req *model.CapturedRequest, identity string, opts ReproOptions) string {
	var b strings.Builder
	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\n", methodOf(req), path)
	if host := req.URL.Host; host != "" {
		fmt.Fprintf(&b, "Host: %s\n", host)
	}
	for _, kv := range sortedHeaders(req.Headers, identity, opts) {
		fmt.Fprintf(&b, "%s: %s\n", kv[0], kv[1])
	}
	if cookieLine := cookieHeader(req.Cookies, identity, opts); cookieLine != "" {
		fmt.Fprintf(&b, "Cookie: %s\n", cookieLine)
	}
	if len(req.Body) > 0 {
		b.WriteString("\n")
		b.Write(req.Body)
	}
	return b.String()
}

// buildCurl renders a single-line curl command equivalent to the request,
// shell-quoting values so it can be pasted directly into a terminal.
func buildCurl(req *model.CapturedRequest, identity string, opts ReproOptions) string {
	var parts []string
	parts = append(parts, "curl", "-X", methodOf(req))
	for _, kv := range sortedHeaders(req.Headers, identity, opts) {
		parts = append(parts, "-H", shellQuote(kv[0]+": "+kv[1]))
	}
	if cookieLine := cookieHeader(req.Cookies, identity, opts); cookieLine != "" {
		parts = append(parts, "-b", shellQuote(cookieLine))
	}
	if len(req.Body) > 0 {
		parts = append(parts, "--data-raw", shellQuote(string(req.Body)))
	}
	parts = append(parts, shellQuote(req.URL.String()))
	return strings.Join(parts, " ")
}

// buildDifferential renders the owner-baseline vs. variant response summary.
func buildDifferential(ev model.Evidence) string {
	parts := []string{
		fmt.Sprintf("baseline %d → variant %d", ev.BaselineStatus, ev.VariantStatus),
	}
	if ev.SimilarityScore > 0 {
		parts = append(parts, fmt.Sprintf("similarity %.2f", ev.SimilarityScore))
	}
	parts = append(parts, fmt.Sprintf("Δsize %d", ev.SizeDelta))
	return strings.Join(parts, " · ")
}

// methodOf returns the request method, defaulting to GET when unset.
func methodOf(req *model.CapturedRequest) string {
	if req.Method == "" {
		return "GET"
	}
	return req.Method
}

// sortedHeaders returns header (name, value) pairs in deterministic order,
// redacting credential values unless opts.ShowCreds is set. The synthetic
// "Cookie" header is omitted here because cookies are rendered from the jar
// (req.Cookies) by cookieHeader to keep a single canonical source.
func sortedHeaders(h http.Header, identity string, opts ReproOptions) [][2]string {
	names := make([]string, 0, len(h))
	for name := range h {
		if strings.EqualFold(name, "Cookie") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([][2]string, 0, len(names))
	for _, name := range names {
		val := strings.Join(h.Values(name), ", ")
		if !opts.ShowCreds && isReproSensitive(name) {
			val = reproPlaceholder(identity)
		}
		out = append(out, [2]string{name, val})
	}
	return out
}

// cookieHeader renders the request's cookie jar as a single Cookie-header
// value. Cookie values are redacted unless ShowCreds is set (cookies are
// credential material as a class). Returns "" when there are no cookies.
func cookieHeader(cookies []*http.Cookie, identity string, opts ReproOptions) string {
	if len(cookies) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if c == nil {
			continue
		}
		val := c.Value
		if !opts.ShowCreds {
			val = reproPlaceholder(identity)
		}
		pairs = append(pairs, c.Name+"="+val)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "; ")
}

// shellQuote wraps s in single quotes, escaping any embedded single quote by
// closing the quote, adding an escaped quote, and reopening — the standard
// POSIX idiom — so the result is a single safe shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
