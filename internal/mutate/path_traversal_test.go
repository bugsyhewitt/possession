package mutate

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// ptReq builds a captured GET request authenticated as alice against a
// per-user file endpoint. Used as the canonical input across the
// path-traversal tests.
func ptReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/api/files/photo.jpg")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	return &model.CapturedRequest{
		ID:      "alice-photo",
		Method:  "GET",
		URL:     u,
		Headers: h,
	}
}

// ptTechniques indexes variants by their technique string for assertion
// lookup. Mirrors hhTechniques / cdTechniques from sibling mutator tests.
func ptTechniques(vs []model.Variant) map[string]model.Variant {
	out := make(map[string]model.Variant, len(vs))
	for _, v := range vs {
		out[pathTraversalTechnique(v.Mutation)] = v
	}
	return out
}

func TestPathTraversal_DisabledByDefault(t *testing.T) {
	if vs := (PathTraversal{}).Generate(ptReq(t), nil); len(vs) != 0 {
		t.Fatalf("path-traversal must be off by default; got %d variants", len(vs))
	}
}

func TestPathTraversal_NilBaseSafe(t *testing.T) {
	if vs := (PathTraversal{Enabled: true}).Generate(nil, nil); vs != nil {
		t.Errorf("nil base must yield nil variants; got %v", vs)
	}
}

func TestPathTraversal_NilURLSafe(t *testing.T) {
	req := ptReq(t)
	req.URL = nil
	if vs := (PathTraversal{Enabled: true}).Generate(req, nil); vs != nil {
		t.Errorf("nil URL must yield nil variants; got %v", vs)
	}
}

// Root or empty path produces no variants — there is no trailing
// segment to reshape, and the comparative ladder cannot classify a
// root-against-root probe. Mirrors the no-op-skip pattern HostHeader
// and CacheDeception use.
func TestPathTraversal_RootPathSkipped(t *testing.T) {
	for _, p := range []string{"", "/"} {
		req := ptReq(t)
		u, _ := url.Parse("https://api.example.com" + p)
		req.URL = u
		if vs := (PathTraversal{Enabled: true}).Generate(req, nil); len(vs) != 0 {
			t.Errorf("path %q must yield 0 variants; got %d", p, len(vs))
		}
	}
}

// Every variant must keep the caller's own credentials (Identity == nil):
// this is a same-caller scope-escape probe, NOT an identity swap.
// Mirrors the equivalent assertion in cache_deception_test.go and
// host_header_test.go.
func TestPathTraversal_KeepsCallerCredentials(t *testing.T) {
	vs := (PathTraversal{Enabled: true}).Generate(ptReq(t), nil)
	if len(vs) == 0 {
		t.Fatal("expected variants for an enabled path-traversal mutator")
	}
	for _, v := range vs {
		tech := pathTraversalTechnique(v.Mutation)
		if v.Identity != nil {
			t.Errorf("technique %q: Identity must be nil (same caller); got %v", tech, v.Identity)
		}
		if v.Base.Headers.Get("Authorization") != "Bearer alice-token" {
			t.Errorf("technique %q: caller credentials altered; Authorization=%q",
				tech, v.Base.Headers.Get("Authorization"))
		}
		if v.Mutation.Type != "path-traversal" {
			t.Errorf("technique %q: Type = %q; want path-traversal", tech, v.Mutation.Type)
		}
		if v.Mutation.Class != "authz-bypass" {
			t.Errorf("technique %q: Class = %q; want authz-bypass", tech, v.Mutation.Class)
		}
	}
}

// The full cross-product is (6 techniques × 3 traversal targets) = 18
// variants. Pins both the technique count and the target set; either
// drifting silently is the failure mode this test is here to prevent.
func TestPathTraversal_FullCrossProduct(t *testing.T) {
	vs := (PathTraversal{Enabled: true}).Generate(ptReq(t), nil)
	wantTechs := 6
	wantTargets := len(traversalTargets)
	want := wantTechs * wantTargets
	if len(vs) != want {
		t.Errorf("variant count = %d; want %d (%d techniques × %d targets)",
			len(vs), want, wantTechs, wantTargets)
	}
	// Each technique must appear exactly len(targets) times.
	techCounts := map[string]int{}
	for _, v := range vs {
		techCounts[v.Mutation.Detail["shape"]]++
	}
	for _, s := range []string{"dot-dot-slash", "dot-dot-encoded", "dot-dot-double-encoded", "nested-dot-dot", "null-byte-suffix", "absolute-path"} {
		if techCounts[s] != wantTargets {
			t.Errorf("technique %q: %d variants; want %d (one per target)",
				s, techCounts[s], wantTargets)
		}
	}
	// Each target must appear exactly wantTechs times.
	tgtCounts := map[string]int{}
	for _, v := range vs {
		tgtCounts[v.Mutation.Detail["target"]]++
	}
	for _, tgt := range traversalTargets {
		if tgtCounts[tgt] != wantTechs {
			t.Errorf("target %q: %d variants; want %d (one per technique)",
				tgt, tgtCounts[tgt], wantTechs)
		}
	}
}

// dot-dot-slash decorates the URL as <base>/../../...<target>. Decoded
// and escaped forms are identical (no percent-encoding injected).
func TestPathTraversal_DotDotSlashShape(t *testing.T) {
	vs := (PathTraversal{Enabled: true}).Generate(ptReq(t), nil)
	tech := ptTechniques(vs)
	v, ok := tech["dot-dot-slash:etc/passwd"]
	if !ok {
		t.Fatal("missing dot-dot-slash:etc/passwd variant")
	}
	wantPath := "/api/files/" + strings.Repeat("../", traversalDepth) + "etc/passwd"
	if v.Base.URL.Path != wantPath {
		t.Errorf("Path = %q; want %q", v.Base.URL.Path, wantPath)
	}
	if v.Base.URL.RawPath != wantPath {
		t.Errorf("RawPath = %q; want %q (no encoding injected)", v.Base.URL.RawPath, wantPath)
	}
	if v.Mutation.Detail["path_from"] != "/api/files/photo.jpg" {
		t.Errorf("path_from = %q", v.Mutation.Detail["path_from"])
	}
}

// dot-dot-encoded decorates the URL with %2f-encoded path separators in
// the traversal chain. The Path field holds the decoded view (real "/"),
// the RawPath field holds the literal %2f escape so url.URL.String()
// emits it un-double-encoded on the wire.
func TestPathTraversal_DotDotEncodedShape(t *testing.T) {
	vs := (PathTraversal{Enabled: true}).Generate(ptReq(t), nil)
	tech := ptTechniques(vs)
	v, ok := tech["dot-dot-encoded:etc/passwd"]
	if !ok {
		t.Fatal("missing dot-dot-encoded:etc/passwd variant")
	}
	if !strings.Contains(v.Base.URL.RawPath, "..%2f") {
		t.Errorf("RawPath = %q; want literal ..%%2f on the wire", v.Base.URL.RawPath)
	}
	// Sanity: url.URL.String() must emit the %2f form un-double-encoded.
	if strings.Contains(v.Base.URL.String(), "%252f") {
		t.Errorf("URL.String() = %q; %%2f was double-encoded to %%252f", v.Base.URL.String())
	}
	if !strings.Contains(v.Base.URL.String(), "%2f") {
		t.Errorf("URL.String() = %q; want literal %%2f on the wire", v.Base.URL.String())
	}
}

// dot-dot-double-encoded carries `..%252f` on the wire. The decoded
// view contains `..%2f` (the single-decoded form a comparator would
// see); the escaped form keeps `..%252f` so url.URL.String() emits the
// double-encoded payload verbatim — a downstream handler that decodes
// twice recovers `../`.
func TestPathTraversal_DotDotDoubleEncodedShape(t *testing.T) {
	vs := (PathTraversal{Enabled: true}).Generate(ptReq(t), nil)
	tech := ptTechniques(vs)
	v, ok := tech["dot-dot-double-encoded:windows/win.ini"]
	if !ok {
		t.Fatal("missing dot-dot-double-encoded:windows/win.ini variant")
	}
	if !strings.Contains(v.Base.URL.RawPath, "..%252f") {
		t.Errorf("RawPath = %q; want literal ..%%252f on the wire", v.Base.URL.RawPath)
	}
	if !strings.Contains(v.Base.URL.String(), "%252f") {
		t.Errorf("URL.String() = %q; want literal %%252f on the wire", v.Base.URL.String())
	}
}

// nested-dot-dot decorates the URL with `....//` repeats — the form
// that defeats single-pass filters which strip `../` literals.
// Decoded and escaped forms are identical (no percent-encoding).
func TestPathTraversal_NestedDotDotShape(t *testing.T) {
	vs := (PathTraversal{Enabled: true}).Generate(ptReq(t), nil)
	tech := ptTechniques(vs)
	v, ok := tech["nested-dot-dot:etc/passwd"]
	if !ok {
		t.Fatal("missing nested-dot-dot:etc/passwd variant")
	}
	wantPath := "/api/files/" + strings.Repeat("....//", traversalDepth) + "etc/passwd"
	if v.Base.URL.Path != wantPath {
		t.Errorf("Path = %q; want %q", v.Base.URL.Path, wantPath)
	}
	if v.Base.URL.RawPath != wantPath {
		t.Errorf("RawPath = %q; want %q", v.Base.URL.RawPath, wantPath)
	}
}

// null-byte-suffix appends %00 to the target. The decoded view carries
// a literal NUL byte (the form a downstream handler sees after URL
// decoding); the escaped view carries the literal %00 so the wire form
// is unambiguous.
func TestPathTraversal_NullByteSuffixShape(t *testing.T) {
	vs := (PathTraversal{Enabled: true}).Generate(ptReq(t), nil)
	tech := ptTechniques(vs)
	v, ok := tech["null-byte-suffix:proc/self/environ"]
	if !ok {
		t.Fatal("missing null-byte-suffix:proc/self/environ variant")
	}
	if !strings.HasSuffix(v.Base.URL.RawPath, "proc/self/environ%00") {
		t.Errorf("RawPath = %q; want suffix proc/self/environ%%00", v.Base.URL.RawPath)
	}
	if !strings.HasSuffix(v.Base.URL.Path, "proc/self/environ\x00") {
		t.Errorf("Path = %q; want literal NUL suffix on the decoded view", v.Base.URL.Path)
	}
	if !strings.Contains(v.Base.URL.String(), "%00") {
		t.Errorf("URL.String() = %q; want literal %%00 on the wire", v.Base.URL.String())
	}
}

// absolute-path replaces the entire path with the absolute target.
// Decoded and escaped forms are identical (no percent-encoding); the
// payload has no `..` segments at all — distinct from every other
// technique in this set.
func TestPathTraversal_AbsolutePathShape(t *testing.T) {
	vs := (PathTraversal{Enabled: true}).Generate(ptReq(t), nil)
	tech := ptTechniques(vs)
	v, ok := tech["absolute-path:etc/passwd"]
	if !ok {
		t.Fatal("missing absolute-path:etc/passwd variant")
	}
	wantPath := "/etc/passwd"
	if v.Base.URL.Path != wantPath {
		t.Errorf("Path = %q; want %q", v.Base.URL.Path, wantPath)
	}
	if v.Base.URL.RawPath != wantPath {
		t.Errorf("RawPath = %q; want %q", v.Base.URL.RawPath, wantPath)
	}
	if strings.Contains(v.Base.URL.Path, "..") {
		t.Errorf("absolute-path payload must contain no `..`; got %q", v.Base.URL.Path)
	}
}

// A path with a trailing slash (a directory-shaped endpoint) still
// produces variants — the base directory IS the path itself, and the
// traversal hangs off it cleanly with no double-slash.
func TestPathTraversal_TrailingSlashHandling(t *testing.T) {
	req := ptReq(t)
	u, _ := url.Parse("https://api.example.com/api/files/")
	req.URL = u
	vs := (PathTraversal{Enabled: true}).Generate(req, nil)
	if len(vs) == 0 {
		t.Fatal("trailing-slash path must still produce traversal variants")
	}
	for _, v := range vs {
		if strings.Contains(v.Base.URL.Path, "//") &&
			v.Mutation.Detail["shape"] != "nested-dot-dot" {
			// nested-dot-dot intentionally contains `//` as part of its
			// payload (`....//`); every other technique must not double-slash.
			t.Errorf("technique %q: variant Path = %q contains double slash",
				v.Mutation.Detail["shape"], v.Base.URL.Path)
		}
	}
}

// The baseline URL is NEVER mutated by Generate — every variant gets
// its own URL via cloneURL. Mirrors the equivalent invariant tested in
// host_header_test.go and cache_deception_test.go.
func TestPathTraversal_BaselineURLNotMutated(t *testing.T) {
	req := ptReq(t)
	origPath := req.URL.Path
	origRawPath := req.URL.RawPath
	_ = (PathTraversal{Enabled: true}).Generate(req, nil)
	if req.URL.Path != origPath {
		t.Errorf("baseline URL.Path mutated: %q → %q", origPath, req.URL.Path)
	}
	if req.URL.RawPath != origRawPath {
		t.Errorf("baseline URL.RawPath mutated: %q → %q", origRawPath, req.URL.RawPath)
	}
}

// Generate must be deterministic: identical input yields an identical
// variant slice (same techniques in the same order). Pins the
// "sorted-by-name" emission contract.
func TestPathTraversal_Deterministic(t *testing.T) {
	a := (PathTraversal{Enabled: true}).Generate(ptReq(t), nil)
	b := (PathTraversal{Enabled: true}).Generate(ptReq(t), nil)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic length: %d vs %d", len(a), len(b))
	}
	for i := range a {
		ta := pathTraversalTechnique(a[i].Mutation)
		tb := pathTraversalTechnique(b[i].Mutation)
		if ta != tb {
			t.Errorf("pos %d: non-deterministic technique %q vs %q", i, ta, tb)
		}
		if a[i].Mutation.Description != b[i].Mutation.Description {
			t.Errorf("pos %d: non-deterministic description %q vs %q",
				i, a[i].Mutation.Description, b[i].Mutation.Description)
		}
	}
}

// Technique names are emitted in sorted order (the outer loop of the
// cross-product) so generation order is stable across builds. Within a
// technique, targets are emitted in sorted order; both invariants are
// pinned here.
func TestPathTraversal_SortedTechniquesAndTargets(t *testing.T) {
	vs := (PathTraversal{Enabled: true}).Generate(ptReq(t), nil)
	var seenTechs []string
	last := ""
	for _, v := range vs {
		s := v.Mutation.Detail["shape"]
		if s != last {
			seenTechs = append(seenTechs, s)
			last = s
		}
	}
	if !sort.StringsAreSorted(seenTechs) {
		t.Errorf("techniques emitted out of order: %v", seenTechs)
	}
	byTech := map[string][]string{}
	for _, v := range vs {
		byTech[v.Mutation.Detail["shape"]] = append(byTech[v.Mutation.Detail["shape"]], v.Mutation.Detail["target"])
	}
	for tech, tgts := range byTech {
		if !sort.StringsAreSorted(tgts) {
			t.Errorf("technique %q: targets emitted out of order: %v", tech, tgts)
		}
	}
}

// The Name() string is the public identifier used by the registry, by the
// reporter, and by allowlist suppressions. It must be stable — changing it
// silently invalidates existing allowlist entries operators have written
// against the tool's output. Mirrors the equivalent assertion in every
// sibling mutator's test file.
func TestPathTraversal_Name(t *testing.T) {
	if got := (PathTraversal{}).Name(); got != "path-traversal" {
		t.Errorf("Name() = %q; want path-traversal", got)
	}
}

// path-traversal must NOT be in the DefaultRegistry — it is registered
// separately by buildRegistry as an opt-in mutator. Mirrors the
// equivalent assertion every other off-by-default mutator has against
// DefaultRegistry.
func TestPathTraversal_NotInDefaultRegistry(t *testing.T) {
	for _, n := range DefaultRegistry().Names() {
		if n == "path-traversal" {
			t.Fatalf("path-traversal must NOT be in DefaultRegistry() (off-by-default mutator)")
		}
	}
}

// buildTraversalPath returns ok=false for an unknown technique so the
// caller (Generate) skips emission silently rather than synthesising a
// degenerate variant.
func TestPathTraversal_UnknownTechniqueSkipped(t *testing.T) {
	if _, _, ok := buildTraversalPath("nonsense-technique", "/api/files/", "etc/passwd"); ok {
		t.Error("unknown technique must return ok=false")
	}
}

// An empty baseDir or empty target yields ok=false: defensive guards
// against degenerate inputs the caller could otherwise propagate to
// the wire.
func TestPathTraversal_DegenerateInputsSkipped(t *testing.T) {
	if _, _, ok := buildTraversalPath("dot-dot-slash", "", "etc/passwd"); ok {
		t.Error("empty baseDir must return ok=false")
	}
	if _, _, ok := buildTraversalPath("dot-dot-slash", "/api/files/", ""); ok {
		t.Error("empty target must return ok=false")
	}
}

// PathTraversal is disjoint from ForbiddenBypass's traversal-semicolon
// technique: ForbiddenBypass reshapes the path to resolve back to the
// SAME handler (`/admin/..;/admin`), PathTraversal escapes the resource
// scope entirely (`/admin/../../etc/passwd`). The mutation Type and
// the payload shape MUST differ.
func TestPathTraversal_DisjointFromForbiddenBypass(t *testing.T) {
	ptVariants := (PathTraversal{Enabled: true}).Generate(ptReq(t), nil)
	for _, v := range ptVariants {
		if v.Mutation.Type == "forbidden-bypass" {
			t.Errorf("path-traversal variant must not carry forbidden-bypass type; got %q",
				v.Mutation.Type)
		}
		// No path-traversal payload should resolve back to the original
		// resource collection (`/api/files/`): every payload either
		// escapes via `..` segments or jumps to an absolute path.
		if v.Mutation.Detail["shape"] == "absolute-path" {
			continue // absolute-path replaces the path wholesale
		}
		if !strings.Contains(v.Base.URL.Path, "..") &&
			!strings.Contains(v.Base.URL.RawPath, "..") {
			t.Errorf("technique %q: neither Path nor RawPath contains `..`; payload does not escape scope",
				v.Mutation.Detail["shape"])
		}
	}
}
