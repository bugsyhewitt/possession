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
	regOff, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry off: %v", err)
	}
	if regOff.Get("forbidden-bypass") == nil {
		t.Fatalf("forbidden-bypass must always be registered, even when disabled")
	}

	regOn, err := buildRegistry("", 0, false, false, false, false, true, false, false, false, false, false, false, false, false, false, false, false, false)
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
	reg, err := buildRegistry(f, 0, false, false, false, false, true, false, false, false, false, false, false, false, false, false, false, false, false)
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
	regOff, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry off: %v", err)
	}
	if regOff.Get("ws-hijack") == nil {
		t.Fatalf("ws-hijack must always be registered, even when disabled")
	}
	if vs := regOff.Get("ws-hijack").Generate(wsScanReq(), nil); len(vs) != 0 {
		t.Errorf("disabled ws-hijack emitted %d variants; want 0", len(vs))
	}

	regOn, err := buildRegistry("", 0, false, false, false, false, false, true, false, false, false, false, false, false, false, false, false, false, false)
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
	reg, err := buildRegistry(f, 0, false, false, false, false, false, true, false, false, false, false, false, false, false, false, false, false, false)
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
	regOff, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry off: %v", err)
	}
	if regOff.Get("method-override") == nil {
		t.Fatalf("method-override must always be registered, even when disabled")
	}
	if vs := regOff.Get("method-override").Generate(protectedScanReq(), nil); len(vs) != 0 {
		t.Errorf("disabled method-override emitted %d variants; want 0", len(vs))
	}

	regOn, err := buildRegistry("", 0, false, false, false, false, false, false, false, true, false, false, false, false, false, false, false, false, false)
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
	reg, err := buildRegistry(f, 0, false, false, false, false, false, false, false, true, false, false, false, false, false, false, false, false, false)
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
	regOff, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry off: %v", err)
	}
	if regOff.Get("host-header") == nil {
		t.Fatalf("host-header must always be registered, even when disabled")
	}
	if vs := regOff.Get("host-header").Generate(protectedScanReq(), nil); len(vs) != 0 {
		t.Errorf("disabled host-header emitted %d variants; want 0", len(vs))
	}

	regOn, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, true, false, false, false, false, false, false, false, false)
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
	reg, err := buildRegistry(f, 0, false, false, false, false, false, false, false, false, true, false, false, false, false, false, false, false, false)
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
	regOff, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry off: %v", err)
	}
	if regOff.Get("cookie-tamper") == nil {
		t.Fatalf("cookie-tamper must always be registered, even when disabled")
	}
	if vs := regOff.Get("cookie-tamper").Generate(cookieScanReq(), nil); len(vs) != 0 {
		t.Errorf("disabled cookie-tamper emitted %d variants; want 0", len(vs))
	}

	regOn, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, true, false, false, false, false, false, false, false)
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
	reg, err := buildRegistry(f, 0, false, false, false, false, false, false, false, false, false, true, false, false, false, false, false, false, false)
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

// TestBuildRegistry_HeaderInjectionGating proves the --header-injection flag
// flows through buildRegistry: the mutator is always registered, but only emits
// variants when the flag is set.
func TestBuildRegistry_HeaderInjectionGating(t *testing.T) {
	regOff, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry off: %v", err)
	}
	if regOff.Get("header-injection") == nil {
		t.Fatalf("header-injection must always be registered, even when disabled")
	}
	if vs := regOff.Get("header-injection").Generate(protectedScanReq(), nil); len(vs) != 0 {
		t.Errorf("disabled header-injection emitted %d variants; want 0", len(vs))
	}

	regOn, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false, true, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry on: %v", err)
	}
	m := regOn.Get("header-injection")
	if m == nil {
		t.Fatalf("header-injection missing from registry when enabled")
	}
	if vs := m.Generate(protectedScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled header-injection emitted 0 variants; want > 0")
	}
}

// TestBuildRegistry_HeaderInjectionWithWordlist verifies the alternate (wordlist)
// construction path also wires the gated header-injection mutator.
func TestBuildRegistry_HeaderInjectionWithWordlist(t *testing.T) {
	f := t.TempDir() + "/wl.txt"
	if err := os.WriteFile(f, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	reg, err := buildRegistry(f, 0, false, false, false, false, false, false, false, false, false, false, true, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry with wordlist: %v", err)
	}
	if reg.Get("header-injection") == nil {
		t.Fatalf("header-injection missing from wordlist-path registry")
	}
	if vs := reg.Get("header-injection").Generate(protectedScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled header-injection (wordlist path) emitted 0 variants")
	}
}

// pollutionScanReq returns a captured request with a query parameter, so the
// parameter-pollution mutator has something to duplicate.
func pollutionScanReq() *model.CapturedRequest {
	u, _ := url.Parse("https://api.example.com/account?role=user")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	return &model.CapturedRequest{
		ID:      "alice-account",
		Method:  "GET",
		URL:     u,
		Headers: h,
	}
}

// TestBuildRegistry_ParamPollutionGating proves the --parameter-pollution flag
// flows through buildRegistry: the mutator is always registered, but only emits
// variants when the flag is set.
func TestBuildRegistry_ParamPollutionGating(t *testing.T) {
	regOff, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry off: %v", err)
	}
	if regOff.Get("parameter-pollution") == nil {
		t.Fatalf("parameter-pollution must always be registered, even when disabled")
	}
	if vs := regOff.Get("parameter-pollution").Generate(pollutionScanReq(), nil); len(vs) != 0 {
		t.Errorf("disabled parameter-pollution emitted %d variants; want 0", len(vs))
	}

	regOn, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false, false, true, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry on: %v", err)
	}
	m := regOn.Get("parameter-pollution")
	if m == nil {
		t.Fatalf("parameter-pollution missing from registry when enabled")
	}
	if vs := m.Generate(pollutionScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled parameter-pollution emitted 0 variants; want > 0")
	}
}

// TestBuildRegistry_ParamPollutionWithWordlist verifies the alternate (wordlist)
// construction path also wires the gated parameter-pollution mutator.
func TestBuildRegistry_ParamPollutionWithWordlist(t *testing.T) {
	f := t.TempDir() + "/wl.txt"
	if err := os.WriteFile(f, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	reg, err := buildRegistry(f, 0, false, false, false, false, false, false, false, false, false, false, false, true, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry with wordlist: %v", err)
	}
	if reg.Get("parameter-pollution") == nil {
		t.Fatalf("parameter-pollution missing from wordlist-path registry")
	}
	if vs := reg.Get("parameter-pollution").Generate(pollutionScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled parameter-pollution (wordlist path) emitted 0 variants")
	}
}

// ctcScanReq returns a captured request with a JSON object body, so the
// content-type-confusion mutator has something to relabel.
func ctcScanReq() *model.CapturedRequest {
	u, _ := url.Parse("https://api.example.com/account/update")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	h.Set("Content-Type", "application/json")
	return &model.CapturedRequest{
		ID:          "alice-ctc",
		Method:      "POST",
		URL:         u,
		Headers:     h,
		Body:        []byte(`{"name":"alice"}`),
		ContentType: "application/json",
	}
}

// TestBuildRegistry_ContentTypeConfusionGating proves the
// --content-type-confusion flag flows through buildRegistry: the mutator is
// always registered, but only emits variants when the flag is set.
func TestBuildRegistry_ContentTypeConfusionGating(t *testing.T) {
	regOff, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry off: %v", err)
	}
	if regOff.Get("content-type-confusion") == nil {
		t.Fatalf("content-type-confusion must always be registered, even when disabled")
	}
	if vs := regOff.Get("content-type-confusion").Generate(ctcScanReq(), nil); len(vs) != 0 {
		t.Errorf("disabled content-type-confusion emitted %d variants; want 0", len(vs))
	}

	regOn, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false, false, false, false, true, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry on: %v", err)
	}
	m := regOn.Get("content-type-confusion")
	if m == nil {
		t.Fatalf("content-type-confusion missing from registry when enabled")
	}
	if vs := m.Generate(ctcScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled content-type-confusion emitted 0 variants; want > 0")
	}
}

// TestBuildRegistry_ContentTypeConfusionWithWordlist verifies the alternate
// (wordlist) construction path also wires the gated content-type-confusion
// mutator.
func TestBuildRegistry_ContentTypeConfusionWithWordlist(t *testing.T) {
	f := t.TempDir() + "/wl.txt"
	if err := os.WriteFile(f, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	reg, err := buildRegistry(f, 0, false, false, false, false, false, false, false, false, false, false, false, false, false, true, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry with wordlist: %v", err)
	}
	if reg.Get("content-type-confusion") == nil {
		t.Fatalf("content-type-confusion missing from wordlist-path registry")
	}
	if vs := reg.Get("content-type-confusion").Generate(ctcScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled content-type-confusion (wordlist path) emitted 0 variants")
	}
}

// cdScanReq returns a captured GET request authenticated as alice against a
// personal endpoint, so the cache-deception mutator has a non-cacheable URL
// to decorate.
func cdScanReq() *model.CapturedRequest {
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

// TestBuildRegistry_CacheDeceptionGating proves the --cache-deception flag
// flows through buildRegistry: the mutator is always registered, but only
// emits variants when the flag is set.
func TestBuildRegistry_CacheDeceptionGating(t *testing.T) {
	regOff, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry off: %v", err)
	}
	if regOff.Get("cache-deception") == nil {
		t.Fatalf("cache-deception must always be registered, even when disabled")
	}
	if vs := regOff.Get("cache-deception").Generate(cdScanReq(), nil); len(vs) != 0 {
		t.Errorf("disabled cache-deception emitted %d variants; want 0", len(vs))
	}

	regOn, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, false, false)
	if err != nil {
		t.Fatalf("buildRegistry on: %v", err)
	}
	m := regOn.Get("cache-deception")
	if m == nil {
		t.Fatalf("cache-deception missing from registry when enabled")
	}
	if vs := m.Generate(cdScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled cache-deception emitted 0 variants; want > 0")
	}
}

// TestBuildRegistry_CacheDeceptionWithWordlist verifies the alternate
// (wordlist) construction path also wires the gated cache-deception mutator.
func TestBuildRegistry_CacheDeceptionWithWordlist(t *testing.T) {
	f := t.TempDir() + "/wl.txt"
	if err := os.WriteFile(f, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	reg, err := buildRegistry(f, 0, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, false, false)
	if err != nil {
		t.Fatalf("buildRegistry with wordlist: %v", err)
	}
	if reg.Get("cache-deception") == nil {
		t.Fatalf("cache-deception missing from wordlist-path registry")
	}
	if vs := reg.Get("cache-deception").Generate(cdScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled cache-deception (wordlist path) emitted 0 variants")
	}
}

// ppScanReq returns a captured PUT request authenticated as alice with a
// JSON object body, so the prototype-pollution mutator has something to
// pollute. Mirrors cdScanReq / ctcScanReq for the gating tests below.
func ppScanReq() *model.CapturedRequest {
	u, _ := url.Parse("https://api.example.com/api/users/1001")
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	h.Set("Content-Type", "application/json")
	return &model.CapturedRequest{
		ID:          "alice-update",
		Method:      "PUT",
		URL:         u,
		Headers:     h,
		Body:        []byte(`{"name":"alice"}`),
		ContentType: "application/json",
	}
}

// TestBuildRegistry_PrototypePollutionGating proves the --prototype-pollution
// flag flows through buildRegistry: the mutator is always registered, but
// only emits variants when the flag is set.
func TestBuildRegistry_PrototypePollutionGating(t *testing.T) {
	regOff, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry off: %v", err)
	}
	if regOff.Get("prototype-pollution") == nil {
		t.Fatalf("prototype-pollution must always be registered, even when disabled")
	}
	if vs := regOff.Get("prototype-pollution").Generate(ppScanReq(), nil); len(vs) != 0 {
		t.Errorf("disabled prototype-pollution emitted %d variants; want 0", len(vs))
	}

	regOn, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, false)
	if err != nil {
		t.Fatalf("buildRegistry on: %v", err)
	}
	m := regOn.Get("prototype-pollution")
	if m == nil {
		t.Fatalf("prototype-pollution missing from registry when enabled")
	}
	if vs := m.Generate(ppScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled prototype-pollution emitted 0 variants; want > 0")
	}
}

// TestBuildRegistry_PrototypePollutionWithWordlist verifies the alternate
// (wordlist) construction path also wires the gated prototype-pollution
// mutator.
func TestBuildRegistry_PrototypePollutionWithWordlist(t *testing.T) {
	f := t.TempDir() + "/wl.txt"
	if err := os.WriteFile(f, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	reg, err := buildRegistry(f, 0, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, false)
	if err != nil {
		t.Fatalf("buildRegistry with wordlist: %v", err)
	}
	if reg.Get("prototype-pollution") == nil {
		t.Fatalf("prototype-pollution missing from wordlist-path registry")
	}
	if vs := reg.Get("prototype-pollution").Generate(ppScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled prototype-pollution (wordlist path) emitted 0 variants")
	}
}

// ptScanReq returns a captured GET request authenticated as alice
// against a per-user file endpoint, so the path-traversal mutator has
// a trailing segment to reshape. Mirrors cdScanReq / ppScanReq for the
// gating tests below.
func ptScanReq() *model.CapturedRequest {
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

// TestBuildRegistry_PathTraversalGating proves the --path-traversal flag
// flows through buildRegistry: the mutator is always registered, but only
// emits variants when the flag is set.
func TestBuildRegistry_PathTraversalGating(t *testing.T) {
	regOff, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry off: %v", err)
	}
	if regOff.Get("path-traversal") == nil {
		t.Fatalf("path-traversal must always be registered, even when disabled")
	}
	if vs := regOff.Get("path-traversal").Generate(ptScanReq(), nil); len(vs) != 0 {
		t.Errorf("disabled path-traversal emitted %d variants; want 0", len(vs))
	}

	regOn, err := buildRegistry("", 0, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true)
	if err != nil {
		t.Fatalf("buildRegistry on: %v", err)
	}
	m := regOn.Get("path-traversal")
	if m == nil {
		t.Fatalf("path-traversal missing from registry when enabled")
	}
	if vs := m.Generate(ptScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled path-traversal emitted 0 variants; want > 0")
	}
}

// TestBuildRegistry_PathTraversalWithWordlist verifies the alternate
// (wordlist) construction path also wires the gated path-traversal
// mutator.
func TestBuildRegistry_PathTraversalWithWordlist(t *testing.T) {
	f := t.TempDir() + "/wl.txt"
	if err := os.WriteFile(f, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	reg, err := buildRegistry(f, 0, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true)
	if err != nil {
		t.Fatalf("buildRegistry with wordlist: %v", err)
	}
	if reg.Get("path-traversal") == nil {
		t.Fatalf("path-traversal missing from wordlist-path registry")
	}
	if vs := reg.Get("path-traversal").Generate(ptScanReq(), nil); len(vs) == 0 {
		t.Errorf("enabled path-traversal (wordlist path) emitted 0 variants")
	}
}
