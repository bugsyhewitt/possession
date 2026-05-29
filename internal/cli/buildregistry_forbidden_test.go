package cli

import (
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// protectedScanReq returns a captured request against a protected path,
// authenticated as alice. Used to prove forbidden-bypass gating end-to-end.
func protectedScanReq() *model.CapturedRequest {
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

// TestBuildRegistry_ForbiddenBypassGating proves the --forbidden-bypass flag
// flows through buildRegistry: the mutator is always registered, but only
// emits variants when the flag is set.
func TestBuildRegistry_ForbiddenBypassGating(t *testing.T) {
	regOff, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry off: %v", err)
	}
	if regOff.Get("forbidden-bypass") == nil {
		t.Fatalf("forbidden-bypass must always be registered, even when disabled")
	}

	regOn, err := buildRegistry("", 0, false, false, false, false, true, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry on: %v", err)
	}
	m := regOn.Get("forbidden-bypass")
	if m == nil {
		t.Fatalf("forbidden-bypass missing from registry when enabled")
	}

	req := protectedScanReq()
	if vs := regOff.Get("forbidden-bypass").Generate(req, nil); len(vs) != 0 {
		t.Errorf("disabled forbidden-bypass emitted %d variants; want 0", len(vs))
	}
	if vs := m.Generate(req, nil); len(vs) == 0 {
		t.Errorf("enabled forbidden-bypass emitted 0 variants; want > 0")
	}
}

// TestBuildRegistry_ForbiddenBypassWithWordlist verifies the alternate
// (wordlist) construction path also wires the gated mutator.
func TestBuildRegistry_ForbiddenBypassWithWordlist(t *testing.T) {
	f := t.TempDir() + "/wl.txt"
	if err := os.WriteFile(f, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	reg, err := buildRegistry(f, 0, false, false, false, false, true, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry with wordlist: %v", err)
	}
	if reg.Get("forbidden-bypass") == nil {
		t.Fatalf("forbidden-bypass missing from wordlist-path registry")
	}
	if vs := reg.Get("forbidden-bypass").Generate(protectedScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled forbidden-bypass (wordlist path) emitted 0 variants")
	}
}

// wsScanReq returns a captured WebSocket upgrade handshake authenticated as
// alice. Used to prove --ws-hijack gating end-to-end through buildRegistry.
func wsScanReq() *model.CapturedRequest {
	u, _ := url.Parse("https://api.example.com/ws/notifications")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	h.Set("Upgrade", "websocket")
	h.Set("Connection", "Upgrade")
	h.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	return &model.CapturedRequest{
		ID:      "alice-ws",
		Method:  "GET",
		URL:     u,
		Headers: h,
	}
}

// TestBuildRegistry_WSHijackGating proves the --ws-hijack flag flows through
// buildRegistry: the mutator is always registered, but only emits variants when
// the flag is set.
func TestBuildRegistry_WSHijackGating(t *testing.T) {
	regOff, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry off: %v", err)
	}
	if regOff.Get("ws-hijack") == nil {
		t.Fatalf("ws-hijack must always be registered, even when disabled")
	}
	if vs := regOff.Get("ws-hijack").Generate(wsScanReq(), nil); len(vs) != 0 {
		t.Errorf("disabled ws-hijack emitted %d variants; want 0", len(vs))
	}

	regOn, err := buildRegistry("", 0, false, false, false, false, false, true, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry on: %v", err)
	}
	m := regOn.Get("ws-hijack")
	if m == nil {
		t.Fatalf("ws-hijack missing from registry when enabled")
	}
	// nil matrix ⇒ only the strip-auth technique fires (1 variant).
	if vs := m.Generate(wsScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled ws-hijack emitted 0 variants; want > 0")
	}
}

// TestBuildRegistry_WSHijackWithWordlist verifies the alternate (wordlist)
// construction path also wires the gated ws-hijack mutator.
func TestBuildRegistry_WSHijackWithWordlist(t *testing.T) {
	f := t.TempDir() + "/wl.txt"
	if err := os.WriteFile(f, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	reg, err := buildRegistry(f, 0, false, false, false, false, false, true, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry with wordlist: %v", err)
	}
	if reg.Get("ws-hijack") == nil {
		t.Fatalf("ws-hijack missing from wordlist-path registry")
	}
	if vs := reg.Get("ws-hijack").Generate(wsScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled ws-hijack (wordlist path) emitted 0 variants")
	}
}

// TestBuildRegistry_MethodOverrideGating proves the --method-override flag flows
// through buildRegistry: the mutator is always registered, but only emits
// variants when the flag is set.
func TestBuildRegistry_MethodOverrideGating(t *testing.T) {
	regOff, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry off: %v", err)
	}
	if regOff.Get("method-override") == nil {
		t.Fatalf("method-override must always be registered, even when disabled")
	}
	if vs := regOff.Get("method-override").Generate(protectedScanReq(), nil); len(vs) != 0 {
		t.Errorf("disabled method-override emitted %d variants; want 0", len(vs))
	}

	regOn, err := buildRegistry("", 0, false, false, false, false, false, false, false, true, false, false)
	if err != nil {
		t.Fatalf("buildRegistry on: %v", err)
	}
	m := regOn.Get("method-override")
	if m == nil {
		t.Fatalf("method-override missing from registry when enabled")
	}
	if vs := m.Generate(protectedScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled method-override emitted 0 variants; want > 0")
	}
}

// TestBuildRegistry_MethodOverrideWithWordlist verifies the alternate (wordlist)
// construction path also wires the gated method-override mutator.
func TestBuildRegistry_MethodOverrideWithWordlist(t *testing.T) {
	f := t.TempDir() + "/wl.txt"
	if err := os.WriteFile(f, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	reg, err := buildRegistry(f, 0, false, false, false, false, false, false, false, true, false, false)
	if err != nil {
		t.Fatalf("buildRegistry with wordlist: %v", err)
	}
	if reg.Get("method-override") == nil {
		t.Fatalf("method-override missing from wordlist-path registry")
	}
	if vs := reg.Get("method-override").Generate(protectedScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled method-override (wordlist path) emitted 0 variants")
	}
}

// TestBuildRegistry_HostHeaderGating proves the --host-header flag flows through
// buildRegistry: the mutator is always registered, but only emits variants when
// the flag is set.
func TestBuildRegistry_HostHeaderGating(t *testing.T) {
	regOff, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry off: %v", err)
	}
	if regOff.Get("host-header") == nil {
		t.Fatalf("host-header must always be registered, even when disabled")
	}
	if vs := regOff.Get("host-header").Generate(protectedScanReq(), nil); len(vs) != 0 {
		t.Errorf("disabled host-header emitted %d variants; want 0", len(vs))
	}

	regOn, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, true, false)
	if err != nil {
		t.Fatalf("buildRegistry on: %v", err)
	}
	m := regOn.Get("host-header")
	if m == nil {
		t.Fatalf("host-header missing from registry when enabled")
	}
	if vs := m.Generate(protectedScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled host-header emitted 0 variants; want > 0")
	}
}

// TestBuildRegistry_HostHeaderWithWordlist verifies the alternate (wordlist)
// construction path also wires the gated host-header mutator.
func TestBuildRegistry_HostHeaderWithWordlist(t *testing.T) {
	f := t.TempDir() + "/wl.txt"
	if err := os.WriteFile(f, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	reg, err := buildRegistry(f, 0, false, false, false, false, false, false, false, false, true, false)
	if err != nil {
		t.Fatalf("buildRegistry with wordlist: %v", err)
	}
	if reg.Get("host-header") == nil {
		t.Fatalf("host-header missing from wordlist-path registry")
	}
	if vs := reg.Get("host-header").Generate(protectedScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled host-header (wordlist path) emitted 0 variants")
	}
}

// cookieScanReq returns a captured request authenticated by a session cookie
// whose value carries a flippable privilege claim (role=user). Used to prove
// cookie-tampering gating end-to-end.
func cookieScanReq() *model.CapturedRequest {
	u, _ := url.Parse("https://api.example.com/account")
	return &model.CapturedRequest{
		ID:      "alice-account",
		Method:  "GET",
		URL:     u,
		Headers: http.Header{},
		Cookies: []*http.Cookie{{Name: "session", Value: "role=user;tier=free"}},
	}
}

// TestBuildRegistry_CookieTamperGating proves the --cookie-tampering flag flows
// through buildRegistry: the mutator is always registered, but only emits
// variants when the flag is set.
func TestBuildRegistry_CookieTamperGating(t *testing.T) {
	regOff, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry off: %v", err)
	}
	if regOff.Get("cookie-tamper") == nil {
		t.Fatalf("cookie-tamper must always be registered, even when disabled")
	}
	if vs := regOff.Get("cookie-tamper").Generate(cookieScanReq(), nil); len(vs) != 0 {
		t.Errorf("disabled cookie-tamper emitted %d variants; want 0", len(vs))
	}

	regOn, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, true)
	if err != nil {
		t.Fatalf("buildRegistry on: %v", err)
	}
	m := regOn.Get("cookie-tamper")
	if m == nil {
		t.Fatalf("cookie-tamper missing from registry when enabled")
	}
	if vs := m.Generate(cookieScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled cookie-tamper emitted 0 variants; want > 0")
	}
}

// TestBuildRegistry_CookieTamperWithWordlist verifies the alternate (wordlist)
// construction path also wires the gated cookie-tamper mutator.
func TestBuildRegistry_CookieTamperWithWordlist(t *testing.T) {
	f := t.TempDir() + "/wl.txt"
	if err := os.WriteFile(f, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	reg, err := buildRegistry(f, 0, false, false, false, false, false, false, false, false, false, true)
	if err != nil {
		t.Fatalf("buildRegistry with wordlist: %v", err)
	}
	if reg.Get("cookie-tamper") == nil {
		t.Fatalf("cookie-tamper missing from wordlist-path registry")
	}
	if vs := reg.Get("cookie-tamper").Generate(cookieScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled cookie-tamper (wordlist path) emitted 0 variants")
	}
}
