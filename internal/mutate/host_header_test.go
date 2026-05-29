package mutate

import (
	"net/http"
	"net/url"
	"sort"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// hhReq builds a captured request authenticated as alice against a protected
// admin path on a public host.
func hhReq(t *testing.T) *model.CapturedRequest {
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

// hhTechniques indexes variants by their technique string.
func hhTechniques(vs []model.Variant) map[string]model.Variant {
	out := make(map[string]model.Variant, len(vs))
	for _, v := range vs {
		out[hostHeaderTechnique(v.Mutation)] = v
	}
	return out
}

func TestHostHeader_DisabledByDefault(t *testing.T) {
	if vs := (HostHeader{}).Generate(hhReq(t), nil); len(vs) != 0 {
		t.Fatalf("host-header must be off by default; got %d variants", len(vs))
	}
}

func TestHostHeader_NilBaseSafe(t *testing.T) {
	if vs := (HostHeader{Enabled: true}).Generate(nil, nil); vs != nil {
		t.Errorf("nil base must yield nil variants; got %v", vs)
	}
}

// A request whose URL carries no host produces no variants (nothing to spoof
// against).
func TestHostHeader_NoHostNoVariants(t *testing.T) {
	req := hhReq(t)
	req.URL = &url.URL{Path: "/admin/users"} // empty Host
	if vs := (HostHeader{Enabled: true}).Generate(req, nil); len(vs) != 0 {
		t.Errorf("empty URL host must yield 0 variants; got %d", len(vs))
	}
}

// Every variant must keep the caller's own credentials (Identity == nil): this
// is a same-caller host-spoof probe, NOT an identity swap.
func TestHostHeader_KeepsCallerCredentials(t *testing.T) {
	vs := (HostHeader{Enabled: true}).Generate(hhReq(t), nil)
	if len(vs) == 0 {
		t.Fatal("expected variants for an enabled host-header mutator")
	}
	for _, v := range vs {
		tech := hostHeaderTechnique(v.Mutation)
		if v.Identity != nil {
			t.Errorf("technique %q: Identity must be nil (same caller); got %v", tech, v.Identity)
		}
		if v.Base.Headers.Get("Authorization") != "Bearer alice-token" {
			t.Errorf("technique %q: caller credentials altered; Authorization=%q",
				tech, v.Base.Headers.Get("Authorization"))
		}
		if v.Mutation.Type != "host-header" {
			t.Errorf("technique %q: Type = %q; want host-header", tech, v.Mutation.Type)
		}
		if v.Mutation.Class != "authz-bypass" {
			t.Errorf("technique %q: Class = %q; want authz-bypass", tech, v.Mutation.Class)
		}
	}
}

// Host-override variants set a "Host" header naming each spoofed host. The
// engine (buildHTTPRequest) is responsible for promoting that header onto the
// wire Host; the mutator's contract is only that the header is present.
func TestHostHeader_HostOverrideVariants(t *testing.T) {
	vs := (HostHeader{Enabled: true}).Generate(hhReq(t), nil)
	tech := hhTechniques(vs)

	want := map[string]string{
		"host-override:loopback-ip":    "127.0.0.1",
		"host-override:localhost":      "localhost",
		"host-override:internal-vhost": "internal",
	}
	for technique, host := range want {
		v, ok := tech[technique]
		if !ok {
			t.Fatalf("missing host-override variant %q", technique)
		}
		if got := v.Base.Headers.Get("Host"); got != host {
			t.Errorf("%s: Host header = %q; want %q", technique, got, host)
		}
		if v.Mutation.Detail["host_from"] != "api.example.com" {
			t.Errorf("%s: host_from = %q; want api.example.com", technique, v.Mutation.Detail["host_from"])
		}
		if v.Mutation.Detail["host_to"] != host {
			t.Errorf("%s: host_to = %q; want %q", technique, v.Mutation.Detail["host_to"], host)
		}
	}
}

// Forwarded-host variants keep the real Host on the request and inject a
// forwarded-host override header. The "Forwarded" header uses the RFC 7239
// host= form; the others carry the bare host.
func TestHostHeader_ForwardedHostVariants(t *testing.T) {
	vs := (HostHeader{Enabled: true}).Generate(hhReq(t), nil)
	tech := hhTechniques(vs)

	// X-Forwarded-Host with the internal vhost.
	v, ok := tech["forwarded-host:X-Forwarded-Host"]
	if !ok {
		// There are multiple X-Forwarded-Host variants (one per spoof host);
		// the technique key collapses them, so look up via a direct scan.
		v = findForwardedVariant(t, vs, "X-Forwarded-Host", "internal")
	} else if v.Base.Headers.Get("X-Forwarded-Host") == "" {
		t.Fatal("X-Forwarded-Host variant did not set the header")
	}
	// The real Host must NOT be overridden by a forwarded-host variant.
	if v.Base.Headers.Get("Host") != "" {
		t.Errorf("forwarded-host variant must not set a Host header; got %q", v.Base.Headers.Get("Host"))
	}

	// The RFC 7239 Forwarded header must use the host= directive.
	fwd := findForwardedVariant(t, vs, "Forwarded", "internal")
	if got := fwd.Base.Headers.Get("Forwarded"); got != "host=internal" {
		t.Errorf("Forwarded header = %q; want host=internal", got)
	}
}

// findForwardedVariant locates the forwarded-host variant for a given header
// name and spoof host value.
func findForwardedVariant(t *testing.T, vs []model.Variant, header, hostVal string) model.Variant {
	t.Helper()
	for _, v := range vs {
		if v.Mutation.Detail["header"] == header && v.Mutation.Detail["host_to"] == hostVal {
			return v
		}
	}
	t.Fatalf("no forwarded-host variant for header %q host %q", header, hostVal)
	return model.Variant{}
}

// All five forwarded-host headers must each appear for every spoof host, and no
// host-override variant may emit a no-op (spoof == original host).
func TestHostHeader_HeaderCoverage(t *testing.T) {
	vs := (HostHeader{Enabled: true}).Generate(hhReq(t), nil)

	headers := map[string]int{}
	for _, v := range vs {
		if h := v.Mutation.Detail["header"]; h != "" {
			headers[h]++
		}
	}
	wantHeaders := []string{"Forwarded", "X-Forwarded-Host", "X-Forwarded-Server", "X-HTTP-Host-Override", "X-Host"}
	for _, h := range wantHeaders {
		// 3 spoof hosts → 3 variants per forwarded header.
		if headers[h] != 3 {
			t.Errorf("forwarded header %q appeared %d times; want 3", h, headers[h])
		}
	}

	// 3 host-override + (5 headers × 3 hosts) forwarded-host = 18 variants.
	if len(vs) != 18 {
		t.Errorf("variant count = %d; want 18 (3 host-override + 15 forwarded-host)", len(vs))
	}
}

// A spoof host identical to the request's own host must not emit a host-override
// no-op variant.
func TestHostHeader_NoSelfHostOverride(t *testing.T) {
	req := hhReq(t)
	u, _ := url.Parse("http://localhost/admin")
	req.URL = u
	vs := (HostHeader{Enabled: true}).Generate(req, nil)
	for _, v := range vs {
		if v.Mutation.Detail["technique"] == "host-override:localhost" {
			t.Error("host-override must not emit a no-op when spoof == original host (localhost)")
		}
	}
}

// Generate must be deterministic: identical input yields an identical variant
// slice (same techniques in the same order).
func TestHostHeader_Deterministic(t *testing.T) {
	a := (HostHeader{Enabled: true}).Generate(hhReq(t), nil)
	b := (HostHeader{Enabled: true}).Generate(hhReq(t), nil)
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

// Within the forwarded-host family, header names are emitted in sorted order so
// generation order is stable without relying on map iteration.
func TestHostHeader_SortedForwardedHeaders(t *testing.T) {
	vs := (HostHeader{Enabled: true}).Generate(hhReq(t), nil)
	var headers []string
	last := ""
	for _, v := range vs {
		h := v.Mutation.Detail["header"]
		if h == "" {
			continue // host-override variant
		}
		if h != last {
			headers = append(headers, h)
			last = h
		}
	}
	if !sort.StringsAreSorted(headers) {
		t.Errorf("forwarded header families not in sorted order: %v", headers)
	}
}
