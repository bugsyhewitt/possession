package mutate

import (
	"net/http"
	"net/url"
	"sort"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// protectedReq returns a request authenticated as alice against a protected
// path. ForbiddenBypass is identity-agnostic (it never swaps creds), so the
// auth here only proves the mutator leaves it intact.
func protectedReq(t *testing.T, path string) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com" + path)
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	return &model.CapturedRequest{
		ID:      "alice-admin",
		Method:  "GET",
		URL:     u,
		Headers: h,
	}
}

func TestForbiddenBypass_DisabledByDefault(t *testing.T) {
	req := protectedReq(t, "/admin/users")
	// Zero-value ForbiddenBypass (Enabled == false) must emit nothing.
	if vs := (ForbiddenBypass{}).Generate(req, nil); len(vs) != 0 {
		t.Fatalf("ForbiddenBypass must be off by default; got %d variants", len(vs))
	}
}

func TestForbiddenBypass_NilSafety(t *testing.T) {
	if vs := (ForbiddenBypass{Enabled: true}).Generate(nil, nil); vs != nil {
		t.Fatalf("nil base must yield nil; got %d variants", len(vs))
	}
	// A request with no URL cannot have its path reshaped, but header
	// variants also depend on URL.Host — the whole mutator must no-op safely.
	noURL := &model.CapturedRequest{ID: "x", Method: "GET", Headers: http.Header{}}
	if vs := (ForbiddenBypass{Enabled: true}).Generate(noURL, nil); vs != nil {
		t.Fatalf("nil URL must yield nil; got %d variants", len(vs))
	}
}

func TestForbiddenBypass_EmitsPathAndHeaderFamilies(t *testing.T) {
	req := protectedReq(t, "/admin/users")
	vs := ForbiddenBypass{Enabled: true}.Generate(req, nil)

	// All seven path transforms apply to "/admin/users" (last segment "users"
	// has an alpha first char, path is non-root, etc.) plus three rewrite
	// headers.
	wantPath := len(pathTransforms)
	wantHeader := len(rewriteHeaders)
	if len(vs) != wantPath+wantHeader {
		t.Fatalf("want %d variants (%d path + %d header) got %d",
			wantPath+wantHeader, wantPath, wantHeader, len(vs))
	}

	pathCount, headerCount := 0, 0
	for _, v := range vs {
		if v.Mutation.Type != "forbidden-bypass" {
			t.Errorf("mutation type: want forbidden-bypass got %q", v.Mutation.Type)
		}
		if v.Mutation.Class != "authz-bypass" {
			t.Errorf("class: want authz-bypass got %q", v.Mutation.Class)
		}
		// Credentials must be untouched: Identity nil means the replay engine
		// keeps the captured auth (the same rejected caller).
		if v.Identity != nil {
			t.Errorf("Identity must be nil (creds unchanged); got %q", v.Identity.Name)
		}
		if v.Base == nil {
			t.Fatalf("variant has nil base")
		}
		if got := v.Base.Headers.Get("Authorization"); got != "Bearer alice-token" {
			t.Errorf("auth must be preserved; got %q", got)
		}
		switch {
		case hasPrefix(v.Mutation.Detail["technique"], "path:"):
			pathCount++
			// Path variants must actually change the path.
			if v.Base.URL == nil || v.Base.URL.Path == req.URL.Path {
				t.Errorf("path variant %q did not change path", v.Mutation.Detail["technique"])
			}
			// And must not touch the baseline URL (no aliasing).
			if v.Base.URL == req.URL {
				t.Errorf("path variant aliases baseline URL")
			}
		case hasPrefix(v.Mutation.Detail["technique"], "header:"):
			headerCount++
			name := v.Mutation.Detail["header"]
			if name == "" || v.Base.Headers.Get(name) == "" {
				t.Errorf("header variant %q did not set its header", v.Mutation.Detail["technique"])
			}
			// Header variants must leave the path identical to the baseline.
			if v.Base.URL.Path != req.URL.Path {
				t.Errorf("header variant must not change path; got %q", v.Base.URL.Path)
			}
		default:
			t.Errorf("unexpected technique %q", v.Mutation.Detail["technique"])
		}
	}
	if pathCount != wantPath {
		t.Errorf("path variants: want %d got %d", wantPath, pathCount)
	}
	if headerCount != wantHeader {
		t.Errorf("header variants: want %d got %d", wantHeader, headerCount)
	}
}

func TestForbiddenBypass_RewriteHeaderValues(t *testing.T) {
	req := protectedReq(t, "/admin/users")
	vs := ForbiddenBypass{Enabled: true}.Generate(req, nil)

	want := map[string]string{
		"X-Original-URL":  "/admin/users",
		"X-Rewrite-URL":   "/admin/users",
		"X-Forwarded-For": "127.0.0.1",
	}
	seen := map[string]bool{}
	for _, v := range vs {
		name := v.Mutation.Detail["header"]
		if name == "" {
			continue
		}
		expVal, ok := want[name]
		if !ok {
			t.Errorf("unexpected rewrite header %q", name)
			continue
		}
		if got := v.Base.Headers.Get(name); got != expVal {
			t.Errorf("%s value: want %q got %q", name, expVal, got)
		}
		seen[name] = true
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("missing rewrite header variant %q", name)
		}
	}
}

func TestForbiddenBypass_PathTransformShapes(t *testing.T) {
	req := protectedReq(t, "/admin/users")
	vs := ForbiddenBypass{Enabled: true}.Generate(req, nil)

	// Assert on the *wire* path (EscapedPath), which is what net/http issues
	// via url.URL.String() — this is the authoritative serialization and the
	// reason RawPath is set deliberately for percent-encoded payloads.
	got := map[string]string{} // technique name -> wire path
	for _, v := range vs {
		tech := v.Mutation.Detail["technique"]
		if !hasPrefix(tech, "path:") {
			continue
		}
		got[tech[len("path:"):]] = v.Base.URL.EscapedPath()
	}

	want := map[string]string{
		"trailing-slash":       "/admin/users/",
		"double-leading-slash": "//admin/users",
		"dot-segment":          "/./admin/users",
		"matrix-param":         "/admin/users;a=b",
		"traversal-semicolon":  "/admin/users/..;/users",
		"encoded-trailing-dot": "/admin/users%2e",
		"case-toggle":          "/admin/Users",
	}
	for name, exp := range want {
		if got[name] != exp {
			t.Errorf("path transform %q wire path: want %q got %q", name, exp, got[name])
		}
	}
	if len(got) != len(want) {
		t.Errorf("path transform count: want %d got %d", len(want), len(got))
	}

	// The encoded-trailing-dot variant must NOT double-encode the '%' — the
	// full serialized URL must carry %2e literally, never %252e.
	for _, v := range vs {
		if v.Mutation.Detail["technique"] == "path:encoded-trailing-dot" {
			s := v.Base.URL.String()
			if !hasSubstr(s, "%2e") || hasSubstr(s, "%252e") {
				t.Errorf("encoded-trailing-dot must serialize %%2e literally; got %s", s)
			}
		}
	}
}

func TestForbiddenBypass_RootPathSkipsInapplicableTransforms(t *testing.T) {
	// Root "/" can't get a trailing slash (already has one), a matrix param, a
	// traversal segment (no last segment), an encoded dot, or a case toggle (no
	// alpha char). Only double-leading-slash and dot-segment apply, plus all
	// three headers.
	req := protectedReq(t, "/")
	req.URL.Path = "/"
	vs := ForbiddenBypass{Enabled: true}.Generate(req, nil)

	pathTechs := map[string]bool{}
	for _, v := range vs {
		tech := v.Mutation.Detail["technique"]
		if hasPrefix(tech, "path:") {
			pathTechs[tech[len("path:"):]] = true
		}
	}
	if pathTechs["trailing-slash"] {
		t.Error("trailing-slash must not apply to root path")
	}
	if pathTechs["traversal-semicolon"] {
		t.Error("traversal-semicolon must not apply to root path")
	}
	if pathTechs["case-toggle"] {
		t.Error("case-toggle must not apply to a path with no alpha segment")
	}
	if !pathTechs["double-leading-slash"] {
		t.Error("double-leading-slash should apply to root path")
	}
}

func TestForbiddenBypass_NumericSegmentNoCaseToggle(t *testing.T) {
	// A numeric-only last segment has no alpha char to toggle: case-toggle must
	// not emit a variant for /orders/5523.
	req := protectedReq(t, "/orders/5523")
	vs := ForbiddenBypass{Enabled: true}.Generate(req, nil)
	for _, v := range vs {
		if v.Mutation.Detail["technique"] == "path:case-toggle" {
			t.Fatalf("case-toggle must not apply to numeric segment; got path %q", v.Base.URL.Path)
		}
	}
}

func TestForbiddenBypass_Deterministic(t *testing.T) {
	req := protectedReq(t, "/admin/users")
	a := ForbiddenBypass{Enabled: true}.Generate(req, nil)
	b := ForbiddenBypass{Enabled: true}.Generate(req, nil)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic count: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Mutation.Description != b[i].Mutation.Description {
			t.Errorf("position %d: %q vs %q", i, a[i].Mutation.Description, b[i].Mutation.Description)
		}
	}

	// Order within each family is sorted by technique name.
	var pathNames, headerNames []string
	for _, v := range a {
		tech := v.Mutation.Detail["technique"]
		switch {
		case hasPrefix(tech, "path:"):
			pathNames = append(pathNames, tech)
		case hasPrefix(tech, "header:"):
			headerNames = append(headerNames, tech)
		}
	}
	if !sort.StringsAreSorted(pathNames) {
		t.Errorf("path techniques not sorted: %v", pathNames)
	}
	if !sort.StringsAreSorted(headerNames) {
		t.Errorf("header techniques not sorted: %v", headerNames)
	}
}

func TestForbiddenBypass_DoesNotMutateBaseline(t *testing.T) {
	req := protectedReq(t, "/admin/users")
	origPath := req.URL.Path
	origAuth := req.Headers.Get("Authorization")
	_ = ForbiddenBypass{Enabled: true}.Generate(req, nil)
	if req.URL.Path != origPath {
		t.Errorf("baseline path mutated: want %q got %q", origPath, req.URL.Path)
	}
	if req.Headers.Get("Authorization") != origAuth {
		t.Errorf("baseline auth mutated")
	}
	if req.Headers.Get("X-Original-URL") != "" {
		t.Errorf("baseline gained a rewrite header")
	}
}

func TestForbiddenBypass_NotInDefaultRegistry(t *testing.T) {
	// ForbiddenBypass is gated and added only in buildRegistry; it must stay
	// out of DefaultRegistry so the canonical mutator order is unchanged.
	for _, n := range DefaultRegistry().Names() {
		if n == "forbidden-bypass" {
			t.Fatalf("forbidden-bypass must NOT be in DefaultRegistry()")
		}
	}
}

// hasPrefix is a tiny local helper to avoid importing strings purely for one
// call; keeps the test self-contained and readable.
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// hasSubstr reports whether sub occurs anywhere in s.
func hasSubstr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
