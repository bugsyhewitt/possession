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
	regOff, err := buildRegistry("", 0, false, false, false, false, false)
	if err != nil {
		t.Fatalf("buildRegistry off: %v", err)
	}
	if regOff.Get("forbidden-bypass") == nil {
		t.Fatalf("forbidden-bypass must always be registered, even when disabled")
	}

	regOn, err := buildRegistry("", 0, false, false, false, false, true)
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
	reg, err := buildRegistry(f, 0, false, false, false, false, true)
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
