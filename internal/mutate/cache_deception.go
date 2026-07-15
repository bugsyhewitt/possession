package mutate

import (
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// CacheDeception is the Web Cache Deception (WCD) access-control bypass
// mutator (Omer Gil, BlackHat 2017; refreshed coverage in the 2024-2026
// BlackHat Cache-Confusion / CDN-Confusion research). It targets the very
// common deployment shape where a CDN / edge cache (CloudFront, Fastly,
// Akamai, Cloudflare, Varnish, nginx proxy_cache) is wired to cache responses
// whose URL "looks static" — typically by file-extension allowlist (.css,
// .js, .png, .jpg, .ico, .gif, .svg) or by literal-path rules
// (/static/...), and at most lightly varies by query string — while the
// upstream application router strips, ignores, or normalises away the
// "static" decoration and still routes the request to a dynamic handler
// that returns the caller's *personal* response.
//
// The bug being tested: the application returns alice's personalised content
// (her email, her balance, her API key) at a URL the CDN considers cacheable.
// The cache stores alice's personal response under that key. Any subsequent
// caller fetching the same URL — possibly unauthenticated — gets alice's
// cached response served straight from the edge. This is authorisation
// failure by transport-layer leak: the application did the right thing
// authorising alice, the cache cheerfully serves the result to bob (or to
// the anonymous internet) because the gateway and the handler disagree on
// what the URL means. The technique recurs continuously in real bug-bounty
// programs — including the original PayPal disclosure that named the class —
// because the gateway/handler split is structural rather than a coding bug.
//
// Where SwapIdentity attacks *who* the caller is, SwapObject attacks *which*
// object is referenced, ForbiddenBypass attacks *how* the access-control
// layer routes the request (to slip past a deny rule), and HostHeader
// attacks *which* host the gate believes the request targets, CacheDeception
// attacks *which storage tier* sees the response — a fronting cache stores a
// personalised, owner-shaped response under a URL the cache rule considers
// public/static, exposing it to every later caller. The technique is
// disjoint from ForbiddenBypass (which mutates the path to defeat a deny
// match) and from HostHeader (which spoofs the host the gate evaluates): the
// caller here is *already permitted* to fetch their own personal endpoint;
// the probe asks whether decorating that fetch with cacheable-looking URL
// shape causes the upstream to *still* serve their personal data while the
// cache decides to store it.
//
// Every variant keeps the caller's own credentials (Identity == nil): this
// is emphatically NOT an identity swap. The bug being tested is "the same
// permitted caller receives their own personal response under a cacheable
// URL shape" — possession's comparative ladder fires when that response
// looks shaped like the caller's own baseline (owner-2xx, owner-reflected
// markers, similar body to the un-decorated baseline). Confirming the cache
// actually stored and served the response to *other* callers is a
// follow-up step a human operator does with a cold cache key; possession's
// job is to surface the candidate URL shapes that warrant that follow-up.
// This mirrors how the existing ForbiddenBypass mutator surfaces candidate
// bypass paths the operator confirms by hand.
//
// Four technique families, each emitted as a separate variant for
// attribution. Generation order is fixed (sorted-by-technique-name) so
// identical inputs yield an identical variant slice (--dry-run and the
// offline corpus cover it):
//
//   - path-suffix: append a cacheable extension as a sibling segment after a
//     slash, e.g. /api/me → /api/me/possession.css. Many frameworks
//     (Express, Rails route-globbing, Spring path-variable greedy match,
//     Django catch-alls) route the request to the original handler ignoring
//     the trailing segment, while the cache sees a .css URL and stores the
//     personal response. This is the original Omer-Gil shape; the
//     intermediate path component prevents collision with a real static
//     file at /api/me.css and is the form most consistently observed in
//     write-ups.
//
//   - path-extension: append the extension directly to the last path
//     segment, e.g. /api/me → /api/me.css. Frameworks that strip a known
//     extension before routing (Rails respond_to format, ASP.NET Core
//     content-negotiation, some Spring config) still hit the personal
//     handler, while the cache stores the .css URL. Disjoint from
//     path-suffix because no intermediate "/" appears.
//
//   - semicolon-suffix: append the cacheable extension after a `;`
//     matrix-parameter segment, e.g. /api/me → /api/me;.css. Tomcat /
//     Spring strip the matrix segment when matching the handler; many
//     caches treat the literal URL (including the `;`) as the cache key and
//     see a .css response. Variant of path-suffix that targets specifically
//     the JEE/Spring matrix-parameter convention; emitted separately so a
//     confirmed bypass attributes the exact mechanism.
//
//   - encoded-suffix: append the cacheable extension after a
//     percent-encoded path separator, e.g. /api/me → /api/me%2fpossession.css.
//     A cache normalising the URL before key-construction collapses the
//     %2f to /, sees a .css extension, and caches; an upstream router that
//     does NOT normalise treats the whole thing as one segment and still
//     routes to /api/me (or to a NotFound that some misconfigured handlers
//     fall through to the original). This is the gateway/handler URL
//     normalisation desync — the same class as ForbiddenBypass's encoded
//     path tricks, but applied to *post-path* cache-shape decoration rather
//     than *pre-path* deny-rule evasion.
//
// For each of those four shapes, one variant is emitted per cacheable
// extension. The extension set is kept small and high-signal: the file
// types every CDN / edge cache rule lists by default, sorted alphabetically.
// Cross-product is (4 shapes × len(cacheableExtensions)) variants — bounded
// and deterministic. The variant ID derived by the planner from the
// mutation Detail carries both the shape and the extension so the offline
// corpus tests pin every cross-product cell.
//
// Endpoints whose path already ends in a cacheable extension are skipped:
// the response is already at a cacheable URL by intent and a probe would
// produce a no-op (or a byte-identical response that the comparative ladder
// would mark inconclusive). This is the same no-op-skip pattern HostHeader
// uses for spoof == original-host.
//
// Detection rides the existing comparative ladder unchanged. The caller's
// own baseline against the original (un-decorated) path is the reference; a
// variant that returns an owner-shaped 2xx (or whose body remains highly
// similar to that baseline, or which reflects the owner's markers) under a
// cacheable URL shape is the candidate cache-deception finding. Findings
// are class "authz-bypass" (ASVS V8.3.x, severity HIGH) — the same class
// ForbiddenBypass, HostHeader, MethodOverride, CSRFHeader, CookieTamper,
// HeaderInjection, ParamPollution, OriginSpoof, and ContentTypeConfusion
// use. The mutation Detail carries the shape and the cacheable extension so
// the reporter (and any future repro-snippet generator) can quote both the
// original URL and the cacheable shape the operator should re-fetch from a
// cold cache to confirm the leak.
//
// CacheDeception is OFF by default (Enabled == false). The decorated
// variants reach the *target's own* personal endpoints by design (this is
// the whole point of the test) and therefore observably warm the upstream
// cache at the decorated URL on the caller's behalf; the operator must
// explicitly opt in via --cache-deception. This mirrors the off-by-default
// gating of XXE, MassAssign, EnumerateID, ForbiddenBypass, WSHijack,
// CSRFHeader, MethodOverride, HostHeader, CookieTamper, HeaderInjection,
// ParamPollution, OriginSpoof, and ContentTypeConfusion.
type CacheDeception struct {
	Enabled bool
}

func (CacheDeception) Name() string { return "cache-deception" }

// cacheableExtensions is the cache-extension allowlist most consistently
// observed in CDN default rules and operator-written cache-control configs.
// Kept narrow and high-signal — the file types every edge cache stores by
// extension. Sorted alphabetically so generation order is deterministic
// (the order test asserts this directly); .ico is included because
// favicon.ico is a near-universal cache-by-extension hit and a common WCD
// payload in surveyed write-ups.
var cacheableExtensions = []string{
	"css",
	"gif",
	"ico",
	"jpg",
	"js",
	"png",
	"svg",
}

// cacheableSegmentName is the intermediate segment for the path-suffix and
// encoded-suffix shapes. It is a deliberate, recognisably-attacker-supplied
// token (the project name) so the request is traceable in an upstream log
// and never collides with a real static asset name. Kept as a package
// constant rather than a generated value so the variant ID is stable across
// runs and across builds — the offline corpus depends on that stability.
const cacheableSegmentName = "possession"

func (cd CacheDeception) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !cd.Enabled || base == nil || base.URL == nil {
		return nil
	}

	origPath := base.URL.Path
	if origPath == "" {
		origPath = "/"
	}

	// Skip endpoints whose path already ends in a cacheable extension: the
	// response is already at a cacheable URL by intent and the probe would
	// be a no-op (the decorated URL is identical or the upstream sees the
	// same handler twice). This mirrors HostHeader's no-op-skip for
	// spoof == original-host.
	if pathHasCacheableExtension(origPath) {
		return nil
	}

	// Both slices are declared in sorted order at package level so no
	// copy or re-sort is needed here; iterating the package-level vars
	// directly keeps generation deterministic without per-call allocation.
	//
	// The four shape names are sorted so the cross-product emission order is
	// deterministic regardless of insertion order below. Pinned by the
	// order test.
	shapes := []string{
		"encoded-suffix",
		"path-extension",
		"path-suffix",
		"semicolon-suffix",
	}

	var out []model.Variant
	for _, shape := range shapes {
		for _, ext := range cacheableExtensions {
			decoded, escaped, ok := buildCacheDeceptionPath(shape, origPath, ext)
			if !ok {
				continue
			}
			// Guard against a transform that happened to produce the same
			// wire path as the original (e.g. a degenerate input). The
			// comparative ladder cannot distinguish a byte-identical
			// variant from the baseline, so emitting one would produce a
			// false inconclusive.
			if escaped == origPath {
				continue
			}
			req := CloneRequest(base)
			cloneURL(req, base)
			req.URL.Path = decoded
			// RawPath is honoured by url.URL.String() only when it is a
			// valid escaping of Path; the encoded-suffix shape relies on
			// this to reach the wire with %2f un-double-encoded (the same
			// invariant ForbiddenBypass's encoded path transforms rely on).
			req.URL.RawPath = escaped

			out = append(out, model.Variant{
				Base:     req,
				Identity: nil, // credentials unchanged — same permitted caller
				Mutation: model.Mutation{
					Type: "cache-deception",
					Description: "decorate URL (" + shape + ":" + ext +
						") so a fronting cache stores the personal response at a cacheable key",
					Detail: map[string]string{
						"cache-deception": shape + ":" + ext,
						"technique":       shape + ":" + ext,
						"shape":           shape,
						"extension":       ext,
						"path_from":       origPath,
						"path_to":         escaped,
					},
					Class: "authz-bypass",
				},
			})
		}
	}

	return out
}

// buildCacheDeceptionPath returns (decoded, escaped, ok) for a given shape +
// origPath + extension. The decoded form is what url.URL.Path holds; the
// escaped form is what goes on the wire via url.URL.RawPath. The two are
// identical for shapes that inject no percent-encoding; the encoded-suffix
// shape sets them deliberately so %2f survives un-double-encoded.
//
// The function is pure — no I/O, no time-dependent state — and is exported
// (lowercase, package-private) to the test file so individual shapes can be
// unit-tested without going through Generate.
func buildCacheDeceptionPath(shape, origPath, ext string) (decoded, escaped string, ok bool) {
	if origPath == "" || ext == "" {
		return "", "", false
	}
	switch shape {
	case "path-suffix":
		// /api/me -> /api/me/<segment>.<ext>
		// Ensure exactly one "/" between origPath and the appended segment.
		joiner := "/"
		if strings.HasSuffix(origPath, "/") {
			joiner = ""
		}
		p := origPath + joiner + cacheableSegmentName + "." + ext
		return p, p, true

	case "path-extension":
		// /api/me -> /api/me.<ext>
		// A trailing slash makes the "last segment" empty; the technique
		// targets a real terminal segment, so skip when the path ends in
		// "/" (the path-suffix shape covers that case).
		if strings.HasSuffix(origPath, "/") {
			return "", "", false
		}
		p := origPath + "." + ext
		return p, p, true

	case "semicolon-suffix":
		// /api/me -> /api/me;.<ext>
		// Tomcat/Spring strip the matrix-parameter segment; many caches
		// keep it in the key. Skip on a trailing slash for the same reason
		// path-extension does.
		if strings.HasSuffix(origPath, "/") {
			return "", "", false
		}
		p := origPath + ";." + ext
		return p, p, true

	case "encoded-suffix":
		// /api/me -> /api/me%2f<segment>.<ext>
		// A cache that URL-normalises before key-construction collapses
		// %2f→/ and sees a .<ext> extension; a router that does NOT
		// normalise treats the whole tail as one path segment. If the
		// origPath already ends in "/", strip it from the decoded form so
		// the decoded view does not double-slash (the escaped form is
		// what reaches the wire and is unambiguous regardless).
		trimmed := strings.TrimRight(origPath, "/")
		if trimmed == "" {
			trimmed = ""
		}
		decodedPath := trimmed + "/" + cacheableSegmentName + "." + ext
		escapedPath := origPath + "%2f" + cacheableSegmentName + "." + ext
		return decodedPath, escapedPath, true
	}
	return "", "", false
}

// pathHasCacheableExtension reports whether the path's final segment already
// ends in one of the cacheableExtensions (case-insensitive). Used to skip
// endpoints whose response is already at a cacheable URL by intent — a
// further extension-decoration probe would be a no-op or near-no-op the
// comparative ladder can't usefully classify.
func pathHasCacheableExtension(path string) bool {
	// The final segment is everything after the last "/".
	last := path
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		last = path[i+1:]
	}
	dot := strings.LastIndexByte(last, '.')
	if dot < 0 || dot == len(last)-1 {
		return false
	}
	suffix := strings.ToLower(last[dot+1:])
	for _, ext := range cacheableExtensions {
		if suffix == ext {
			return true
		}
	}
	return false
}

// cacheDeceptionTechnique is a small helper used in tests to assert a
// mutation's technique without depending on the Detail map layout from
// outside the package. Kept here so the technique-key contract lives next
// to its producer (the same pattern hostHeaderTechnique and
// originSpoofTechnique establish).
func cacheDeceptionTechnique(m model.Mutation) string {
	if m.Detail == nil {
		return ""
	}
	return strings.TrimSpace(m.Detail["technique"])
}
