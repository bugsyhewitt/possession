package mutate

import (
	"net/http"
	"net/url"
	"sort"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// hiReq builds a captured request authenticated as alice against a protected
// admin path on a public host.
func hiReq(t *testing.T) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com/admin/users")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	return &model.CapturedRequest{
		ID:      "alice-admin",
		Method:  "GET",
		URL:     u,
		Headers: h,
	}
}

// hiTechniques indexes variants by their technique string.
func hiTechniques(vs []model.Variant) map[string]model.Variant {
	out := make(map[string]model.Variant, len(vs))
	for _, v := range vs {
		out[headerInjectionTechnique(v.Mutation)] = v
	}
	return out
}

func TestHeaderInjection_DisabledByDefault(t *testing.T) {
	if vs := (HeaderInjection{}).Generate(hiReq(t), nil); len(vs) != 0 {
		t.Fatalf("header-injection must be off by default; got %d variants", len(vs))
	}
}

func TestHeaderInjection_NilBaseSafe(t *testing.T) {
	if vs := (HeaderInjection{Enabled: true}).Generate(nil, nil); vs != nil {
		t.Errorf("nil base must yield nil variants; got %v", vs)
	}
}

// A request whose URL is nil produces no variants (nothing to mutate against).
func TestHeaderInjection_NilURLSafe(t *testing.T) {
	req := hiReq(t)
	req.URL = nil
	if vs := (HeaderInjection{Enabled: true}).Generate(req, nil); vs != nil {
		t.Errorf("nil URL must yield nil variants; got %v", vs)
	}
}

// Every variant must keep the caller's own credentials (Identity == nil): this is
// a same-caller trusted-header probe, NOT an identity swap.
func TestHeaderInjection_KeepsCallerCredentials(t *testing.T) {
	vs := (HeaderInjection{Enabled: true}).Generate(hiReq(t), nil)
	if len(vs) == 0 {
		t.Fatal("expected variants for an enabled header-injection mutator")
	}
	for _, v := range vs {
		tech := headerInjectionTechnique(v.Mutation)
		if v.Identity != nil {
			t.Errorf("technique %q: Identity must be nil (same caller); got %v", tech, v.Identity)
		}
		if v.Base.Headers.Get("Authorization") != "Bearer alice-token" {
			t.Errorf("technique %q: caller credentials altered; Authorization=%q",
				tech, v.Base.Headers.Get("Authorization"))
		}
		if v.Mutation.Type != "header-injection" {
			t.Errorf("technique %q: Type = %q; want header-injection", tech, v.Mutation.Type)
		}
		if v.Mutation.Class != "authz-bypass" {
			t.Errorf("technique %q: Class = %q; want authz-bypass", tech, v.Mutation.Class)
		}
	}
}

// Client-IP-spoof variants set each trusted-client-IP header to the loopback.
func TestHeaderInjection_ClientIPSpoofVariants(t *testing.T) {
	vs := (HeaderInjection{Enabled: true}).Generate(hiReq(t), nil)
	tech := hiTechniques(vs)

	wantHeaders := []string{
		"X-Client-IP",
		"X-Originating-IP",
		"X-Real-IP",
		"X-Remote-Addr",
		"X-Remote-IP",
	}
	for _, h := range wantHeaders {
		v, ok := tech["client-ip-spoof:"+h]
		if !ok {
			t.Fatalf("missing client-ip-spoof variant for %q", h)
		}
		if got := v.Base.Headers.Get(h); got != "127.0.0.1" {
			t.Errorf("%s: header value = %q; want 127.0.0.1", h, got)
		}
		if v.Mutation.Detail["family"] != "client-ip-spoof" {
			t.Errorf("%s: family = %q; want client-ip-spoof", h, v.Mutation.Detail["family"])
		}
		if v.Mutation.Detail["value"] != "127.0.0.1" {
			t.Errorf("%s: detail value = %q; want 127.0.0.1", h, v.Mutation.Detail["value"])
		}
	}
}

// Trusted-identity variants set each identity-assertion header to a privileged
// principal.
func TestHeaderInjection_TrustedIdentityVariants(t *testing.T) {
	vs := (HeaderInjection{Enabled: true}).Generate(hiReq(t), nil)
	tech := hiTechniques(vs)

	wantHeaders := []string{
		"X-Authenticated-User",
		"X-Forwarded-User",
		"X-Remote-User",
		"X-User",
		"X-WEBAUTH-USER",
	}
	for _, h := range wantHeaders {
		v, ok := tech["trusted-identity:"+h]
		if !ok {
			t.Fatalf("missing trusted-identity variant for %q", h)
		}
		if got := v.Base.Headers.Get(h); got != "admin" {
			t.Errorf("%s: header value = %q; want admin", h, got)
		}
		if v.Mutation.Detail["family"] != "trusted-identity" {
			t.Errorf("%s: family = %q; want trusted-identity", h, v.Mutation.Detail["family"])
		}
	}
}

// The header-injection set must be disjoint from the headers ForbiddenBypass and
// HostHeader already inject — no double-coverage, clean per-mutator attribution.
func TestHeaderInjection_DisjointFromExistingHeaderSets(t *testing.T) {
	vs := (HeaderInjection{Enabled: true}).Generate(hiReq(t), nil)
	overlap := map[string]bool{
		// ForbiddenBypass.rewriteHeaders
		"X-Forwarded-For": true,
		"X-Original-URL":  true,
		"X-Rewrite-URL":   true,
		// HostHeader.forwardedHostHeaders
		"Forwarded":            true,
		"X-Forwarded-Host":     true,
		"X-Forwarded-Server":   true,
		"X-HTTP-Host-Override": true,
		"X-Host":               true,
	}
	for _, v := range vs {
		h := v.Mutation.Detail["header"]
		if overlap[h] {
			t.Errorf("header-injection emits %q which overlaps an existing mutator's header set", h)
		}
	}
}

// The total variant count is the two header sets combined; each header emits
// exactly one variant.
func TestHeaderInjection_VariantCount(t *testing.T) {
	vs := (HeaderInjection{Enabled: true}).Generate(hiReq(t), nil)
	want := len(clientIPHeaders) + len(identityHeaders) // 5 + 5
	if len(vs) != want {
		t.Errorf("variant count = %d; want %d", len(vs), want)
	}
}

// Generate must be deterministic: identical input yields an identical variant
// slice (same techniques in the same order).
func TestHeaderInjection_Deterministic(t *testing.T) {
	a := (HeaderInjection{Enabled: true}).Generate(hiReq(t), nil)
	b := (HeaderInjection{Enabled: true}).Generate(hiReq(t), nil)
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

// Within each family the header names are emitted in sorted order so generation
// order is stable without relying on map iteration.
func TestHeaderInjection_SortedHeaders(t *testing.T) {
	vs := (HeaderInjection{Enabled: true}).Generate(hiReq(t), nil)
	var ipHeaders, idHeaders []string
	for _, v := range vs {
		switch v.Mutation.Detail["family"] {
		case "client-ip-spoof":
			ipHeaders = append(ipHeaders, v.Mutation.Detail["header"])
		case "trusted-identity":
			idHeaders = append(idHeaders, v.Mutation.Detail["header"])
		}
	}
	if !sort.StringsAreSorted(ipHeaders) {
		t.Errorf("client-ip-spoof headers not in sorted order: %v", ipHeaders)
	}
	if !sort.StringsAreSorted(idHeaders) {
		t.Errorf("trusted-identity headers not in sorted order: %v", idHeaders)
	}
}

// The original request must be untouched — variants clone, never alias the base.
func TestHeaderInjection_DoesNotMutateBase(t *testing.T) {
	req := hiReq(t)
	_ = (HeaderInjection{Enabled: true}).Generate(req, nil)
	for _, h := range append(append([]string{}, clientIPHeaders...), identityHeaders...) {
		if req.Headers.Get(h) != "" {
			t.Errorf("base request was mutated: %q is set on the original", h)
		}
	}
}
