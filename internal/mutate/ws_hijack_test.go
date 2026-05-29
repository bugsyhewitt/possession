package mutate

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// wsReq returns a captured WebSocket upgrade handshake authenticated as alice,
// against the given path. The standard RFC 6455 handshake headers are present.
func wsReq(t *testing.T, path string) *model.CapturedRequest {
	t.Helper()
	u, _ := url.Parse("https://api.example.com" + path)
	h := http.Header{}
	h.Set("Authorization", "Bearer alice-token")
	h.Set("Upgrade", "websocket")
	h.Set("Connection", "keep-alive, Upgrade")
	h.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	h.Set("Sec-WebSocket-Version", "13")
	return &model.CapturedRequest{
		ID:      "alice-ws",
		Method:  "GET",
		URL:     u,
		Headers: h,
	}
}

// wsMatrix returns a two-identity matrix (alice owner-ish, bob a peer) for the
// cross-identity swap technique.
func wsMatrix() *model.RoleMatrix {
	return &model.RoleMatrix{
		Identities: []model.Identity{
			{Name: "alice", Rank: 1, Creds: &model.Credentials{Bearer: "alice-token"}},
			{Name: "bob", Rank: 1, Creds: &model.Credentials{Bearer: "bob-token"}},
		},
	}
}

func TestWSHijack_DisabledByDefault(t *testing.T) {
	req := wsReq(t, "/ws/notifications")
	if vs := (WSHijack{}).Generate(req, wsMatrix()); len(vs) != 0 {
		t.Fatalf("WSHijack must be off by default; got %d variants", len(vs))
	}
}

func TestWSHijack_EmitsStripAuthAndPerIdentity(t *testing.T) {
	req := wsReq(t, "/ws/notifications")
	m := wsMatrix()
	vs := WSHijack{Enabled: true}.Generate(req, m)

	// strip-auth (1) + one per identity (2) = 3
	if want := 1 + len(m.Identities); len(vs) != want {
		t.Fatalf("variant count: want %d got %d", want, len(vs))
	}

	// First variant must be the anonymous strip-auth handshake.
	first := vs[0]
	if first.Mutation.Type != "ws-hijack" {
		t.Errorf("type: want ws-hijack got %q", first.Mutation.Type)
	}
	if first.Mutation.Detail["ws-hijack"] != "strip-auth" {
		t.Errorf("first variant must be strip-auth; got %q", first.Mutation.Detail["ws-hijack"])
	}
	if first.Identity != nil {
		t.Errorf("strip-auth variant must have nil identity; got %+v", first.Identity)
	}
	if first.Mutation.Class != "authn-bypass" {
		t.Errorf("strip-auth class: want authn-bypass got %q", first.Mutation.Class)
	}
	// Credentials must be gone but the upgrade headers must survive.
	if first.Base.Headers.Get("Authorization") != "" {
		t.Errorf("strip-auth variant must drop Authorization; got %q", first.Base.Headers.Get("Authorization"))
	}
	if first.Base.Headers.Get("Upgrade") == "" || first.Base.Headers.Get("Sec-WebSocket-Key") == "" {
		t.Errorf("strip-auth variant must preserve the WebSocket upgrade headers")
	}

	// Remaining variants are the per-identity swaps, in canonical (rank,name) order.
	if vs[1].Mutation.Detail["swapped_to"] != "alice" {
		t.Errorf("variant 1 swapped_to: want alice got %q", vs[1].Mutation.Detail["swapped_to"])
	}
	if vs[2].Mutation.Detail["swapped_to"] != "bob" {
		t.Errorf("variant 2 swapped_to: want bob got %q", vs[2].Mutation.Detail["swapped_to"])
	}
	for _, v := range vs[1:] {
		if v.Mutation.Detail["ws-hijack"] != "swap-identity" {
			t.Errorf("swap variant must carry ws-hijack=swap-identity; got %q", v.Mutation.Detail["ws-hijack"])
		}
		if v.Mutation.Class != "idor" {
			t.Errorf("swap variant class: want idor got %q", v.Mutation.Class)
		}
		if v.Base.Headers.Get("Upgrade") == "" {
			t.Errorf("swap variant must preserve the Upgrade header")
		}
	}
	// bob's swap variant must carry bob's bearer.
	if got := vs[2].Base.Headers.Get("Authorization"); got != "Bearer bob-token" {
		t.Errorf("bob swap variant Authorization: want %q got %q", "Bearer bob-token", got)
	}
}

func TestWSHijack_CrossTenantClass(t *testing.T) {
	req := wsReq(t, "/ws/notifications")
	m := &model.RoleMatrix{
		Identities: []model.Identity{
			{Name: "alice", Rank: 1, Tenant: "acme", Creds: &model.Credentials{Bearer: "alice-token"}},
			{Name: "eve", Rank: 1, Tenant: "evilcorp", Creds: &model.Credentials{Bearer: "eve-token"}},
		},
	}
	vs := WSHijack{Enabled: true}.Generate(req, m)

	var eve *model.Variant
	for i := range vs {
		if vs[i].Mutation.Detail["swapped_to"] == "eve" {
			eve = &vs[i]
		}
	}
	if eve == nil {
		t.Fatal("expected an eve swap variant")
	}
	// Owner tenant resolves from alice's bearer (the captured request's token);
	// eve is in a different tenant ⇒ cross-tenant class.
	if eve.Mutation.Class != "idor-cross-tenant" {
		t.Errorf("eve cross-tenant class: want idor-cross-tenant got %q", eve.Mutation.Class)
	}
	if eve.Mutation.Detail["actor_tenant"] != "evilcorp" {
		t.Errorf("actor_tenant: want evilcorp got %q", eve.Mutation.Detail["actor_tenant"])
	}
}

func TestWSHijack_DetectsByUpgradeHeaders(t *testing.T) {
	// Only Upgrade + Connection, no Sec-WebSocket-Key, must still be recognized.
	u, _ := url.Parse("https://api.example.com/ws")
	h := http.Header{}
	h.Set("Upgrade", "WebSocket") // mixed case
	h.Set("Connection", "Upgrade")
	req := &model.CapturedRequest{ID: "x", Method: "GET", URL: u, Headers: h}
	if vs := (WSHijack{Enabled: true}).Generate(req, nil); len(vs) != 1 {
		// nil matrix ⇒ only the strip-auth technique fires.
		t.Fatalf("upgrade-header detection: want 1 variant (strip-auth, nil matrix) got %d", len(vs))
	}
}

func TestWSHijack_DetectsBySecWebSocketKeyAlone(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/ws")
	h := http.Header{}
	h.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req := &model.CapturedRequest{ID: "x", Method: "GET", URL: u, Headers: h}
	if vs := (WSHijack{Enabled: true}).Generate(req, nil); len(vs) != 1 {
		t.Fatalf("Sec-WebSocket-Key detection: want 1 variant got %d", len(vs))
	}
}

func TestWSHijack_SkipsNonWebSocket(t *testing.T) {
	cases := []struct {
		name string
		set  func(h http.Header)
	}{
		{"plain-request", func(h http.Header) {}},
		{"upgrade-but-no-connection", func(h http.Header) { h.Set("Upgrade", "websocket") }},
		{"connection-but-no-upgrade-header", func(h http.Header) { h.Set("Connection", "Upgrade") }},
		{"upgrade-h2c-not-websocket", func(h http.Header) {
			h.Set("Upgrade", "h2c")
			h.Set("Connection", "Upgrade")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse("https://api.example.com/api/x")
			h := http.Header{}
			h.Set("Authorization", "Bearer alice-token")
			c.set(h)
			req := &model.CapturedRequest{ID: "x", Method: "GET", URL: u, Headers: h}
			if vs := (WSHijack{Enabled: true}).Generate(req, wsMatrix()); len(vs) != 0 {
				t.Errorf("%s: want 0 variants got %d", c.name, len(vs))
			}
		})
	}
}

func TestWSHijack_Deterministic(t *testing.T) {
	req := wsReq(t, "/ws/notifications")
	m := wsMatrix()
	a := WSHijack{Enabled: true}.Generate(req, m)
	b := WSHijack{Enabled: true}.Generate(req, m)
	if len(a) != len(b) {
		t.Fatalf("variant count differs across runs: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Mutation.Detail["ws-hijack"] != b[i].Mutation.Detail["ws-hijack"] ||
			a[i].Mutation.Detail["swapped_to"] != b[i].Mutation.Detail["swapped_to"] {
			t.Errorf("variant %d order differs across runs", i)
		}
	}
}

func TestWSHijack_NilBaseSafe(t *testing.T) {
	if vs := (WSHijack{Enabled: true}).Generate(nil, wsMatrix()); vs != nil {
		t.Errorf("nil base must yield nil variants; got %v", vs)
	}
}

func TestWSHijack_NotInDefaultRegistry(t *testing.T) {
	for _, n := range DefaultRegistry().Names() {
		if n == "ws-hijack" {
			t.Fatalf("ws-hijack must NOT be in DefaultRegistry()")
		}
	}
}
