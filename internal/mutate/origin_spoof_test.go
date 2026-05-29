package mutate

import (
	"net/http"
	"net/url"
	"sort"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// osReq builds a captured state-changing request authenticated as alice against
// a protected endpoint on a public host, carrying its own legitimate Origin and
// Referer.
func osReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/account/transfer")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	h.Set("Origin", "https://api.example.com")
	h.Set("Referer", "https://api.example.com/account")
	return &model.CapturedRequest{
		ID:      "alice-transfer",
		Method:  "POST",
		URL:     u,
		Headers: h,
	}
}

// osTechniques indexes variants by their technique string.
func osTechniques(vs []model.Variant) map[string]model.Variant {
	out := make(map[string]model.Variant, len(vs))
	for _, v := range vs {
		out[originSpoofTechnique(v.Mutation)] = v
	}
	return out
}

func TestOriginSpoof_DisabledByDefault(t *testing.T) {
	if vs := (OriginSpoof{}).Generate(osReq(t), nil); len(vs) != 0 {
		t.Fatalf("origin-spoof must be off by default; got %d variants", len(vs))
	}
}

func TestOriginSpoof_NilBaseSafe(t *testing.T) {
	if vs := (OriginSpoof{Enabled: true}).Generate(nil, nil); vs != nil {
		t.Errorf("nil base must yield nil variants; got %v", vs)
	}
}

// A request whose URL carries no host produces no variants (nothing to craft a
// suffix-confusion host against, and no meaningful origin to spoof).
func TestOriginSpoof_NoHostNoVariants(t *testing.T) {
	req := osReq(t)
	req.URL = &url.URL{Path: "/account/transfer"} // empty Host
	if vs := (OriginSpoof{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Errorf("empty URL host must yield 0 variants; got %d", len(vs))
	}
}

// Every variant must keep the caller's own credentials (Identity == nil): this
// is a same-caller origin-spoof probe, NOT an identity swap.
func TestOriginSpoof_KeepsCallerCredentials(t *testing.T) {
	vs := (OriginSpoof{Enabled: true}).Generate(osReq(t), nil)
	if len(vs) == 0 {
		t.Fatal("expected variants for an enabled origin-spoof mutator")
	}
	for _, v := range vs {
		tech := originSpoofTechnique(v.Mutation)
		if v.Identity != nil {
			t.Errorf("technique %q: Identity must be nil (same caller); got %v", tech, v.Identity)
		}
		if v.Base.Headers.Get("Authorization") != "Bearer alice-token" {
			t.Errorf("technique %q: caller credentials altered; Authorization=%q",
				tech, v.Base.Headers.Get("Authorization"))
		}
		if v.Mutation.Type != "origin-spoof" {
			t.Errorf("technique %q: Type = %q; want origin-spoof", tech, v.Mutation.Type)
		}
		if v.Mutation.Class != "authz-bypass" {
			t.Errorf("technique %q: Class = %q; want authz-bypass", tech, v.Mutation.Class)
		}
	}
}

// The null-origin variant sets Origin: null and drops Referer so the two
// signals agree on "no real origin".
func TestOriginSpoof_NullOrigin(t *testing.T) {
	vs := (OriginSpoof{Enabled: true}).Generate(osReq(t), nil)
	v, ok := osTechniques(vs)["null-origin"]
	if !ok {
		t.Fatal("missing null-origin variant")
	}
	if got := v.Base.Headers.Get("Origin"); got != "null" {
		t.Errorf("null-origin: Origin = %q; want null", got)
	}
	if got := v.Base.Headers.Get("Referer"); got != "" {
		t.Errorf("null-origin: Referer must be dropped; got %q", got)
	}
	if v.Mutation.Detail["origin_from"] != "api.example.com" {
		t.Errorf("null-origin: origin_from = %q; want api.example.com", v.Mutation.Detail["origin_from"])
	}
}

// The cross-origin variant sets both Origin and Referer to a wholly-foreign
// attacker site.
func TestOriginSpoof_CrossOrigin(t *testing.T) {
	vs := (OriginSpoof{Enabled: true}).Generate(osReq(t), nil)
	v, ok := osTechniques(vs)["cross-origin"]
	if !ok {
		t.Fatal("missing cross-origin variant")
	}
	if got := v.Base.Headers.Get("Origin"); got != "https://attacker.example" {
		t.Errorf("cross-origin: Origin = %q; want https://attacker.example", got)
	}
	if got := v.Base.Headers.Get("Referer"); got != "https://attacker.example/" {
		t.Errorf("cross-origin: Referer = %q; want https://attacker.example/", got)
	}
}

// The suffix-confusion family crafts attacker hosts that embed the trusted host
// to defeat naive Contains / HasPrefix / HasSuffix / userinfo matchers. Each
// crafted Origin must be a foreign attacker authority, never the trusted host.
func TestOriginSpoof_SuffixConfusionVariants(t *testing.T) {
	vs := (OriginSpoof{Enabled: true}).Generate(osReq(t), nil)
	tech := osTechniques(vs)

	want := map[string]string{
		"suffix-confusion:prefix-match":       "https://api.example.com.attacker.example",
		"suffix-confusion:suffix-match":       "https://attacker-api-example-com.attacker.example",
		"suffix-confusion:userinfo-confusion": "https://api.example.com@attacker.example",
	}
	for technique, origin := range want {
		v, ok := tech[technique]
		if !ok {
			t.Fatalf("missing suffix-confusion variant %q", technique)
		}
		if got := v.Base.Headers.Get("Origin"); got != origin {
			t.Errorf("%s: Origin = %q; want %q", technique, got, origin)
		}
		if got := v.Base.Headers.Get("Referer"); got != origin+"/" {
			t.Errorf("%s: Referer = %q; want %q", technique, got, origin+"/")
		}
		if v.Mutation.Detail["origin_from"] != "api.example.com" {
			t.Errorf("%s: origin_from = %q; want api.example.com", technique, v.Mutation.Detail["origin_from"])
		}
	}
}

// A host carrying a port must have the port stripped from the crafted
// suffix-confusion labels (the host portion is what an allowlist matches on).
func TestOriginSpoof_PortStrippedFromCraftedHosts(t *testing.T) {
	req := osReq(t)
	u, _ := url.Parse("https://api.example.com:8443/account/transfer")
	req.URL = u
	vs := (OriginSpoof{Enabled: true}).Generate(req, nil)
	v, ok := osTechniques(vs)["suffix-confusion:prefix-match"]
	if !ok {
		t.Fatal("missing prefix-match variant")
	}
	if got := v.Base.Headers.Get("Origin"); got != "https://api.example.com.attacker.example" {
		t.Errorf("prefix-match with port: Origin = %q; want https://api.example.com.attacker.example", got)
	}
}

// The full variant set: 1 null-origin + 1 cross-origin + 3 suffix-confusion = 5.
func TestOriginSpoof_VariantCount(t *testing.T) {
	vs := (OriginSpoof{Enabled: true}).Generate(osReq(t), nil)
	if len(vs) != 5 {
		t.Errorf("variant count = %d; want 5 (1 null-origin + 1 cross-origin + 3 suffix-confusion)", len(vs))
	}
}

// Generate must be deterministic: identical input yields an identical variant
// slice (same techniques in the same order).
func TestOriginSpoof_Deterministic(t *testing.T) {
	a := (OriginSpoof{Enabled: true}).Generate(osReq(t), nil)
	b := (OriginSpoof{Enabled: true}).Generate(osReq(t), nil)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic length: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Mutation.Description != b[i].Mutation.Description {
			t.Errorf("pos %d: non-deterministic description %q vs %q",
				i, a[i].Mutation.Description, b[i].Mutation.Description)
		}
	}
}

// Within the suffix-confusion family, technique names are emitted in sorted
// order so generation order is stable without relying on map iteration.
func TestOriginSpoof_SortedSuffixConfusion(t *testing.T) {
	vs := (OriginSpoof{Enabled: true}).Generate(osReq(t), nil)
	var names []string
	for _, v := range vs {
		if m := v.Mutation.Detail["matcher"]; m != "" {
			names = append(names, m)
		}
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("suffix-confusion matcher families not in sorted order: %v", names)
	}
}

func TestOriginSpoof_NameAndType(t *testing.T) {
	if (OriginSpoof{}).Name() != "origin-spoof" {
		t.Errorf("Name(): got %q want origin-spoof", (OriginSpoof{}).Name())
	}
}

// OriginSpoof is gated and added only in buildRegistry; it must stay out of
// DefaultRegistry so the canonical mutator order is unchanged.
func TestOriginSpoof_NotInDefaultRegistry(t *testing.T) {
	for _, n := range DefaultRegistry().Names() {
		if n == "origin-spoof" {
			t.Fatalf("origin-spoof must NOT be in DefaultRegistry()")
		}
	}
}
