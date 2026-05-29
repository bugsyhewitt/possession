package mutate

import (
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// ForbiddenBypass is the 403/401 access-control bypass mutator (the "4xx
// bypass" / "forbidden bypass" technique). It targets the case where the
// caller's own credentials are correctly rejected for a protected resource
// (the endpoint returns 401/403, or a deny redirect), and tests whether that
// access-control decision can be circumvented by mutating the request itself —
// without changing identity.
//
// Where SwapIdentity attacks *who* the caller is, SwapObject attacks *which*
// object is referenced, and MassAssign attacks *which properties* are bound,
// ForbiddenBypass attacks *how the access-control layer routes and matches the
// request*. Authorization is frequently enforced by a fronting proxy / API
// gateway / WAF or by a path-prefix rule in the app, and that layer can be
// fooled into routing a request to the protected handler while believing it
// targets an allowed path. The two canonical families:
//
//   - path mutation: equivalent-but-different path encodings the access-control
//     layer normalizes differently than the upstream handler — a trailing
//     slash, a `;` matrix-param segment, `//` doubling, `/.`/`/..;/` segments,
//     a `.json`/`%2e` suffix, case toggling, etc. The gateway's allow/deny rule
//     matches the literal mutated path (and lets it through) while the
//     application router still resolves it to the protected handler.
//   - rewrite/override headers: `X-Original-URL`, `X-Rewrite-URL`,
//     `X-Forwarded-For: 127.0.0.1`, `X-Forwarded-Host`, etc. A reverse proxy
//     enforces access control on the request line but then hands a
//     header-supplied URL/host to the backend, which honours it.
//
// Every variant keeps the caller's own credentials (Identity == nil): this is
// emphatically NOT an identity swap. The bug being tested is "the same
// rejected caller slips past the gate by reshaping the request."
//
// Detection rides the existing comparative ladder unchanged. The caller's own
// baseline against the unmutated, protected endpoint is (expected to be) a
// denial; a variant that returns an owner-shaped 2xx where the baseline was
// denied is the bypass. Findings are class "authz-bypass" (ASVS V8.3.x,
// severity high).
//
// Like every mutator, Generate is pure and deterministic: techniques are
// emitted in a fixed (sorted-by-name) order, so identical inputs yield an
// identical variant slice.
//
// ForbiddenBypass is OFF by default (Enabled == false). The path-mutation and
// header-injection payloads are active probes against the routing/access-control
// layer (and the rewrite-header variants can reach internal-only paths on a
// misconfigured proxy), so it only fires when the operator explicitly opts in
// via --forbidden-bypass. This mirrors the off-by-default gating of XXE
// (parser probing), MassAssign (state-mutating), EnumerateID (rate-sensitive),
// and JWTAuth (forgery).
type ForbiddenBypass struct {
	Enabled bool
}

func (ForbiddenBypass) Name() string { return "forbidden-bypass" }

// pathTransform reshapes a URL path into an equivalent-but-different form that
// an access-control layer may match differently than the upstream router. fn
// returns the *decoded* path (url.URL.Path) and the *escaped* wire form
// (url.URL.RawPath), plus false if the transform does not apply (e.g. nothing
// to change) so a no-op transform never emits a variant.
//
// Returning both forms matters: net/http issues the request via
// url.URL.String(), which emits RawPath verbatim ONLY when RawPath is a valid
// escaping of Path. Transforms that inject percent-encoding (e.g. %2e) must
// therefore set Path to the decoded byte and RawPath to the literal escape, or
// Go double-encodes the '%' (%2e → %252e) and the technique is neutered.
type pathTransform struct {
	name string
	// fn returns (decodedPath, escapedPath, ok). For transforms that inject no
	// percent-encoding the two paths are identical.
	fn func(path string) (decoded, escaped string, ok bool)
}

// pathTransforms is the built-in path-mutation set. Kept small and high-signal —
// the transforms most consistently effective at desynchronising a proxy's
// access-control matcher from the application router. Each is emitted as a
// separate variant so a confirmed bypass is attributable to the precise reshape
// that worked.
//
// Sorted by name so generation order is deterministic without a sort at call
// time; the order test covers this.
var pathTransforms = []pathTransform{
	{
		// /admin -> /admin/  : a trailing slash often misses a prefix deny rule
		// while the router still matches the handler.
		name: "trailing-slash",
		fn: func(p string) (string, string, bool) {
			if p == "" || strings.HasSuffix(p, "/") {
				return "", "", false
			}
			return p + "/", p + "/", true
		},
	},
	{
		// /admin -> //admin : doubled leading slash; some matchers collapse it,
		// some don't.
		name: "double-leading-slash",
		fn: func(p string) (string, string, bool) {
			if !strings.HasPrefix(p, "/") {
				return "", "", false
			}
			return "/" + p, "/" + p, true
		},
	},
	{
		// /admin -> /./admin : a single-dot segment that the router normalises
		// away but the matcher may treat literally.
		name: "dot-segment",
		fn: func(p string) (string, string, bool) {
			if !strings.HasPrefix(p, "/") {
				return "", "", false
			}
			return "/." + p, "/." + p, true
		},
	},
	{
		// /admin -> /admin;foo=bar : a matrix-parameter segment appended to the
		// last path component. Many gateways strip it before routing, the
		// matcher does not.
		name: "matrix-param",
		fn: func(p string) (string, string, bool) {
			if p == "" || strings.HasSuffix(p, "/") {
				return "", "", false
			}
			return p + ";a=b", p + ";a=b", true
		},
	},
	{
		// /admin -> /admin/..;/admin : the classic Tomcat/Spring `/..;/` path
		// traversal that defeats a prefix matcher while resolving back to the
		// protected handler.
		name: "traversal-semicolon",
		fn: func(p string) (string, string, bool) {
			if p == "" || p == "/" {
				return "", "", false
			}
			last := lastSegment(p)
			if last == "" {
				return "", "", false
			}
			out := p + "/..;/" + last
			return out, out, true
		},
	},
	{
		// /admin -> /admin%2e : a percent-encoded trailing dot the matcher
		// compares literally but the router URL-decodes. The decoded form ends
		// in a literal '.', the escaped wire form keeps %2e — see pathTransform.
		name: "encoded-trailing-dot",
		fn: func(p string) (string, string, bool) {
			if p == "" || strings.HasSuffix(p, "/") {
				return "", "", false
			}
			return p + ".", p + "%2e", true
		},
	},
	{
		// /admin -> /Admin : case toggle of the first letter of the last
		// segment. Case-sensitive matchers deny, case-insensitive routers serve.
		name: "case-toggle",
		fn:   caseTogglePath,
	},
}

// rewriteHeader is one access-control-bypass header keyed by its value template;
// the value is rendered from the request's own path/host so the proxy is told
// the request really targets the protected resource via a side channel.
type rewriteHeader struct {
	// name is the header name and the technique identifier.
	name string
	// value renders the header value from the original path. Returns false if
	// the header does not apply (e.g. no path to rewrite).
	value func(path, host string) (string, bool)
}

// rewriteHeaders is the built-in rewrite/override header set. Each spoofs a
// fronting proxy into believing the access-control-relevant attribute (the URL
// or the client IP) is something it is not. Emitted as separate variants for
// attribution. Sorted by name for deterministic order.
var rewriteHeaders = []rewriteHeader{
	{
		name: "X-Forwarded-For",
		value: func(_, _ string) (string, bool) {
			return "127.0.0.1", true
		},
	},
	{
		name: "X-Original-URL",
		value: func(path, _ string) (string, bool) {
			if path == "" {
				return "", false
			}
			return path, true
		},
	},
	{
		name: "X-Rewrite-URL",
		value: func(path, _ string) (string, bool) {
			if path == "" {
				return "", false
			}
			return path, true
		},
	},
}

func (fb ForbiddenBypass) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !fb.Enabled || base == nil || base.URL == nil {
		return nil
	}

	origPath := base.URL.Path
	if origPath == "" {
		origPath = "/"
	}

	var out []model.Variant

	// ── path-mutation variants ──────────────────────────────────────────
	transforms := append([]pathTransform(nil), pathTransforms...)
	sort.Slice(transforms, func(i, j int) bool { return transforms[i].name < transforms[j].name })
	for _, t := range transforms {
		decoded, escaped, ok := t.fn(origPath)
		if !ok || escaped == origPath {
			continue
		}
		req := CloneRequest(base)
		cloneURL(req, base)
		req.URL.Path = decoded
		// RawPath is honoured by url.URL.String() only when it is a valid
		// escaping of Path; transforms set it deliberately so percent-encoded
		// payloads (e.g. %2e) reach the wire un-double-encoded.
		req.URL.RawPath = escaped

		out = append(out, model.Variant{
			Base:     req,
			Identity: nil, // credentials unchanged — same rejected caller
			Mutation: model.Mutation{
				Type:        "forbidden-bypass",
				Description: "reshape path (" + t.name + ") to bypass access-control matcher",
				Detail: map[string]string{
					"technique": "path:" + t.name,
					"path_from": origPath,
					"path_to":   escaped,
				},
				Class: "authz-bypass",
			},
		})
	}

	// ── rewrite/override-header variants ─────────────────────────────────
	host := base.URL.Host
	headers := append([]rewriteHeader(nil), rewriteHeaders...)
	sort.Slice(headers, func(i, j int) bool { return headers[i].name < headers[j].name })
	for _, h := range headers {
		val, ok := h.value(origPath, host)
		if !ok {
			continue
		}
		req := CloneRequest(base)
		if req.Headers == nil {
			continue
		}
		req.Headers.Set(h.name, val)

		out = append(out, model.Variant{
			Base:     req,
			Identity: nil, // credentials unchanged — same rejected caller
			Mutation: model.Mutation{
				Type:        "forbidden-bypass",
				Description: "inject " + h.name + " to bypass proxy access control",
				Detail: map[string]string{
					"technique": "header:" + h.name,
					"header":    h.name,
					"value":     val,
				},
				Class: "authz-bypass",
			},
		})
	}

	return out
}

// lastSegment returns the final non-empty path segment of p (without slashes).
func lastSegment(p string) string {
	trimmed := strings.TrimRight(p, "/")
	idx := strings.LastIndexByte(trimmed, '/')
	if idx < 0 {
		return trimmed
	}
	return trimmed[idx+1:]
}

// caseTogglePath toggles the case of the first alphabetic byte in the last path
// segment. The toggled byte is plain ASCII (no percent-encoding), so the
// decoded and escaped forms are identical. Returns false if there is no
// alphabetic byte to toggle (e.g. a numeric-only segment), so a no-op never
// emits a variant.
func caseTogglePath(p string) (string, string, bool) {
	trimmed := strings.TrimRight(p, "/")
	idx := strings.LastIndexByte(trimmed, '/')
	segStart := idx + 1
	bs := []byte(p)
	for i := segStart; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z':
			bs[i] = c - 32
			return string(bs), string(bs), true
		case c >= 'A' && c <= 'Z':
			bs[i] = c + 32
			return string(bs), string(bs), true
		}
	}
	return "", "", false
}
