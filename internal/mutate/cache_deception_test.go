package mutate

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// cdReq builds a captured GET request authenticated as alice against her
// personal endpoint. Used as the canonical input across the cache-deception
// tests.
func cdReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/api/me")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	return &model.CapturedRequest{
		ID:      "alice-me",
		Method:  "GET",
		URL:     u,
		Headers: h,
	}
}

// cdTechniques indexes variants by their technique string for assertion
// lookup. Mirrors hhTechniques / originSpoofTechnique-style helpers from
// the sibling mutator tests.
func cdTechniques(vs []model.Variant) map[string]model.Variant {
	out := make(map[string]model.Variant, len(vs))
	for _, v := range vs {
		out[cacheDeceptionTechnique(v.Mutation)] = v
	}
	return out
}

func TestCacheDeception_DisabledByDefault(t *testing.T) {
	if vs := (CacheDeception{}).Generate(cdReq(t), nil); len(vs) != 0 {
		t.Fatalf("cache-deception must be off by default; got %d variants", len(vs))
	}
}

func TestCacheDeception_NilBaseSafe(t *testing.T) {
	if vs := (CacheDeception{Enabled: true}).Generate(nil, nil); vs != nil {
		t.Errorf("nil base must yield nil variants; got %v", vs)
	}
}

// A request whose URL carries no path is treated as "/" and still emits
// variants — there is nothing pathological about a root endpoint as a
// cache-deception target.
func TestCacheDeception_EmptyPathTreatedAsRoot(t *testing.T) {
	req := cdReq(t)
	req.URL = &url.URL{Host: "api.example.com"} // empty Path
	vs := (CacheDeception{Enabled: true}).Generate(req, nil)
	if len(vs) == 0 {
		t.Fatal("empty path must be treated as / and still produce variants")
	}
	for _, v := range vs {
		if !strings.HasPrefix(v.Base.URL.Path, "/") {
			t.Errorf("path %q should start with /", v.Base.URL.Path)
		}
	}
}

// Every variant must keep the caller's own credentials (Identity == nil):
// this is a same-caller cache-shape probe, NOT an identity swap. Mirrors
// the equivalent assertion in host_header_test.go and origin_spoof_test.go.
func TestCacheDeception_KeepsCallerCredentials(t *testing.T) {
	vs := (CacheDeception{Enabled: true}).Generate(cdReq(t), nil)
	if len(vs) == 0 {
		t.Fatal("expected variants for an enabled cache-deception mutator")
	}
	for _, v := range vs {
		tech := cacheDeceptionTechnique(v.Mutation)
		if v.Identity != nil {
			t.Errorf("technique %q: Identity must be nil (same caller); got %v", tech, v.Identity)
		}
		if v.Base.Headers.Get("Authorization") != "Bearer alice-token" {
			t.Errorf("technique %q: caller credentials altered; Authorization=%q",
				tech, v.Base.Headers.Get("Authorization"))
		}
		if v.Mutation.Type != "cache-deception" {
			t.Errorf("technique %q: Type = %q; want cache-deception", tech, v.Mutation.Type)
		}
		if v.Mutation.Class != "authz-bypass" {
			t.Errorf("technique %q: Class = %q; want authz-bypass", tech, v.Mutation.Class)
		}
	}
}

// The full cross-product is (4 shapes × 7 cacheable extensions) = 28
// variants for a clean path with no trailing slash and no existing
// extension. Pins both the shape count and the extension set; either
// drifting silently is the failure mode this test is here to prevent.
func TestCacheDeception_FullCrossProduct(t *testing.T) {
	vs := (CacheDeception{Enabled: true}).Generate(cdReq(t), nil)
	wantShapes := 4
	wantExts := len(cacheableExtensions)
	want := wantShapes * wantExts
	if len(vs) != want {
		t.Errorf("variant count = %d; want %d (%d shapes × %d extensions)",
			len(vs), want, wantShapes, wantExts)
	}
	// Each shape must appear exactly len(extensions) times.
	shapeCounts := map[string]int{}
	for _, v := range vs {
		shapeCounts[v.Mutation.Detail["shape"]]++
	}
	for _, s := range []string{"path-suffix", "path-extension", "semicolon-suffix", "encoded-suffix"} {
		if shapeCounts[s] != wantExts {
			t.Errorf("shape %q: %d variants; want %d (one per extension)",
				s, shapeCounts[s], wantExts)
		}
	}
	// Each extension must appear exactly wantShapes times.
	extCounts := map[string]int{}
	for _, v := range vs {
		extCounts[v.Mutation.Detail["extension"]]++
	}
	for _, e := range cacheableExtensions {
		if extCounts[e] != wantShapes {
			t.Errorf("extension %q: %d variants; want %d (one per shape)",
				e, extCounts[e], wantShapes)
		}
	}
}

// path-suffix decorates the URL as /<orig>/possession.<ext>. The decoded
// and escaped forms are identical (no percent-encoding injected) and the
// wire path is what a CDN sees as a static asset.
func TestCacheDeception_PathSuffixShape(t *testing.T) {
	vs := (CacheDeception{Enabled: true}).Generate(cdReq(t), nil)
	tech := cdTechniques(vs)
	v, ok := tech["path-suffix:css"]
	if !ok {
		t.Fatal("missing path-suffix:css variant")
	}
	wantPath := "/api/me/possession.css"
	if v.Base.URL.Path != wantPath {
		t.Errorf("Path = %q; want %q", v.Base.URL.Path, wantPath)
	}
	if v.Base.URL.RawPath != wantPath {
		t.Errorf("RawPath = %q; want %q (no encoding injected)", v.Base.URL.RawPath, wantPath)
	}
	if v.Mutation.Detail["path_from"] != "/api/me" {
		t.Errorf("path_from = %q; want /api/me", v.Mutation.Detail["path_from"])
	}
	if v.Mutation.Detail["path_to"] != wantPath {
		t.Errorf("path_to = %q; want %q", v.Mutation.Detail["path_to"], wantPath)
	}
}

// path-extension decorates the URL as /<orig>.<ext>. Disjoint from
// path-suffix because no intermediate slash appears.
func TestCacheDeception_PathExtensionShape(t *testing.T) {
	vs := (CacheDeception{Enabled: true}).Generate(cdReq(t), nil)
	tech := cdTechniques(vs)
	v, ok := tech["path-extension:js"]
	if !ok {
		t.Fatal("missing path-extension:js variant")
	}
	wantPath := "/api/me.js"
	if v.Base.URL.Path != wantPath {
		t.Errorf("Path = %q; want %q", v.Base.URL.Path, wantPath)
	}
	if v.Base.URL.RawPath != wantPath {
		t.Errorf("RawPath = %q; want %q", v.Base.URL.RawPath, wantPath)
	}
}

// semicolon-suffix decorates the URL as /<orig>;.<ext> — the Tomcat/Spring
// matrix-parameter form. The literal `;` MUST appear on the wire (the
// cache key relies on it).
func TestCacheDeception_SemicolonSuffixShape(t *testing.T) {
	vs := (CacheDeception{Enabled: true}).Generate(cdReq(t), nil)
	tech := cdTechniques(vs)
	v, ok := tech["semicolon-suffix:png"]
	if !ok {
		t.Fatal("missing semicolon-suffix:png variant")
	}
	wantPath := "/api/me;.png"
	if v.Base.URL.Path != wantPath {
		t.Errorf("Path = %q; want %q", v.Base.URL.Path, wantPath)
	}
	if !strings.Contains(v.Base.URL.RawPath, ";") {
		t.Errorf("RawPath = %q; expected literal ';' to survive to the wire", v.Base.URL.RawPath)
	}
}

// encoded-suffix decorates the URL as /<orig>%2fpossession.<ext>. The Path
// field holds the decoded form (with a real "/"); the RawPath field holds
// the literal %2f escape so url.URL.String() emits it un-double-encoded —
// the same invariant the ForbiddenBypass encoded transforms rely on.
func TestCacheDeception_EncodedSuffixShape(t *testing.T) {
	vs := (CacheDeception{Enabled: true}).Generate(cdReq(t), nil)
	tech := cdTechniques(vs)
	v, ok := tech["encoded-suffix:ico"]
	if !ok {
		t.Fatal("missing encoded-suffix:ico variant")
	}
	wantDecoded := "/api/me/possession.ico"
	wantEscaped := "/api/me%2fpossession.ico"
	if v.Base.URL.Path != wantDecoded {
		t.Errorf("Path = %q; want %q (decoded form)", v.Base.URL.Path, wantDecoded)
	}
	if v.Base.URL.RawPath != wantEscaped {
		t.Errorf("RawPath = %q; want %q (literal %%2f survives)", v.Base.URL.RawPath, wantEscaped)
	}
	// Sanity: url.URL.String() must emit the escaped form on the wire.
	if !strings.Contains(v.Base.URL.String(), "%2f") {
		t.Errorf("URL.String() = %q; want literal %%2f on the wire", v.Base.URL.String())
	}
}

// A path that already ends in one of the cacheable extensions is a no-op
// target — the response is already at a cacheable URL by intent. Skipping
// it prevents byte-identical or near-identical probes the comparative
// ladder cannot classify.
func TestCacheDeception_SkipsAlreadyCacheable(t *testing.T) {
	req := cdReq(t)
	for _, p := range []string{"/static/app.css", "/img/photo.JPG", "/icon.ico", "/scripts/lib.js"} {
		u, _ := url.Parse("https://api.example.com" + p)
		req.URL = u
		if vs := (CacheDeception{Enabled: true}).Generate(req, nil); len(vs) != 0 {
			t.Errorf("path %q already has cacheable extension; want 0 variants, got %d", p, len(vs))
		}
	}
}

// A path with a trailing slash collapses path-extension and semicolon-suffix
// (which can't meaningfully extend an empty terminal segment); only
// path-suffix and encoded-suffix fire.
func TestCacheDeception_TrailingSlashHandling(t *testing.T) {
	req := cdReq(t)
	u, _ := url.Parse("https://api.example.com/api/me/")
	req.URL = u
	vs := (CacheDeception{Enabled: true}).Generate(req, nil)
	if len(vs) == 0 {
		t.Fatal("trailing-slash path must still produce path-suffix and encoded-suffix variants")
	}
	gotShapes := map[string]bool{}
	for _, v := range vs {
		gotShapes[v.Mutation.Detail["shape"]] = true
	}
	for _, want := range []string{"path-suffix", "encoded-suffix"} {
		if !gotShapes[want] {
			t.Errorf("trailing-slash path: missing shape %q", want)
		}
	}
	for _, notWant := range []string{"path-extension", "semicolon-suffix"} {
		if gotShapes[notWant] {
			t.Errorf("trailing-slash path: shape %q must not fire on an empty terminal segment", notWant)
		}
	}
	// path-suffix on /api/me/ must not double-slash to /api/me//possession.css.
	for _, v := range vs {
		if strings.Contains(v.Base.URL.Path, "//") {
			t.Errorf("variant Path = %q contains double slash", v.Base.URL.Path)
		}
	}
}

// Generate must be deterministic: identical input yields an identical
// variant slice (same techniques in the same order). Pins the
// "sorted-by-name" emission contract.
func TestCacheDeception_Deterministic(t *testing.T) {
	a := (CacheDeception{Enabled: true}).Generate(cdReq(t), nil)
	b := (CacheDeception{Enabled: true}).Generate(cdReq(t), nil)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic length: %d vs %d", len(a), len(b))
	}
	for i := range a {
		ta := cacheDeceptionTechnique(a[i].Mutation)
		tb := cacheDeceptionTechnique(b[i].Mutation)
		if ta != tb {
			t.Errorf("pos %d: non-deterministic technique %q vs %q", i, ta, tb)
		}
		if a[i].Mutation.Description != b[i].Mutation.Description {
			t.Errorf("pos %d: non-deterministic description %q vs %q",
				i, a[i].Mutation.Description, b[i].Mutation.Description)
		}
	}
}

// Shape names are emitted in sorted order (the outer loop of the
// cross-product) so generation order is stable across builds. Within a
// shape, extensions are emitted in sorted order; both invariants are
// pinned here.
func TestCacheDeception_SortedShapesAndExtensions(t *testing.T) {
	vs := (CacheDeception{Enabled: true}).Generate(cdReq(t), nil)
	var seenShapes []string
	last := ""
	for _, v := range vs {
		s := v.Mutation.Detail["shape"]
		if s != last {
			seenShapes = append(seenShapes, s)
			last = s
		}
	}
	if !sort.StringsAreSorted(seenShapes) {
		t.Errorf("shapes emitted out of order: %v", seenShapes)
	}
	// Within each shape, extensions must be sorted.
	byShape := map[string][]string{}
	for _, v := range vs {
		byShape[v.Mutation.Detail["shape"]] = append(byShape[v.Mutation.Detail["shape"]], v.Mutation.Detail["extension"])
	}
	for shape, exts := range byShape {
		if !sort.StringsAreSorted(exts) {
			t.Errorf("shape %q: extensions emitted out of order: %v", shape, exts)
		}
	}
}

// The Name() string is the public identifier used by the registry, by the
// reporter, and by allowlist suppressions. It must be stable — changing it
// silently invalidates existing allowlist entries operators have written
// against the tool's output. Mirrors the equivalent assertion in
// origin_spoof_test.go and content_type_confusion_test.go.
func TestCacheDeception_Name(t *testing.T) {
	if got := (CacheDeception{}).Name(); got != "cache-deception" {
		t.Errorf("Name() = %q; want cache-deception", got)
	}
}

// cache-deception must NOT be in the DefaultRegistry — it is registered
// separately by buildRegistry as an opt-in mutator. Mirrors the equivalent
// assertion every other off-by-default mutator has against DefaultRegistry.
func TestCacheDeception_NotInDefaultRegistry(t *testing.T) {
	for _, n := range DefaultRegistry().Names() {
		if n == "cache-deception" {
			t.Fatalf("cache-deception must NOT be in DefaultRegistry() (off-by-default mutator)")
		}
	}
}

// buildCacheDeceptionPath returns ok=false for an unknown shape so the
// caller (Generate) skips emission silently rather than synthesising a
// degenerate variant.
func TestCacheDeception_UnknownShapeSkipped(t *testing.T) {
	if _, _, ok := buildCacheDeceptionPath("nonsense-shape", "/api/me", "css"); ok {
		t.Error("unknown shape must return ok=false")
	}
}

// An empty path or empty extension yields ok=false: defensive guards
// against degenerate inputs the caller could otherwise propagate to the
// wire.
func TestCacheDeception_DegenerateInputsSkipped(t *testing.T) {
	if _, _, ok := buildCacheDeceptionPath("path-suffix", "", "css"); ok {
		t.Error("empty origPath must return ok=false")
	}
	if _, _, ok := buildCacheDeceptionPath("path-suffix", "/api/me", ""); ok {
		t.Error("empty extension must return ok=false")
	}
}

// pathHasCacheableExtension is case-insensitive and only checks the final
// path segment, so a directory-name fragment like /css-experiments/list
// does NOT trip the guard.
func TestCacheDeception_PathHasCacheableExtensionMatchesFinalSegmentOnly(t *testing.T) {
	if !pathHasCacheableExtension("/static/app.CSS") {
		t.Error("case-insensitive match: /static/app.CSS should be cacheable")
	}
	if pathHasCacheableExtension("/css-experiments/list") {
		t.Error("non-final-segment dot must not trip the guard")
	}
	if pathHasCacheableExtension("/api/me") {
		t.Error("no extension at all must not trip the guard")
	}
	if pathHasCacheableExtension("/file.") {
		t.Error("trailing dot with empty suffix must not trip the guard")
	}
}
