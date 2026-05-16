package detect

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

func mkReq(headers map[string]string, cookies map[string]string) *model.CapturedRequest {
	u, _ := url.Parse("https://api.example.com/x")
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	var cs []*http.Cookie
	for k, v := range cookies {
		cs = append(cs, &http.Cookie{Name: k, Value: v})
	}
	return &model.CapturedRequest{Method: "GET", URL: u, Headers: h, Cookies: cs}
}

func mkMatrix(ids ...model.Identity) *model.RoleMatrix {
	return &model.RoleMatrix{Version: "1", Identities: ids}
}

func TestAttributeOwner_ExactBearer(t *testing.T) {
	alice := model.Identity{Name: "alice", Rank: 10, Creds: &model.Credentials{Bearer: "alice-tok"}}
	bob := model.Identity{Name: "bob", Rank: 10, Creds: &model.Credentials{Bearer: "bob-tok"}}
	m := mkMatrix(alice, bob)
	req := mkReq(map[string]string{"Authorization": "Bearer bob-tok"}, nil)

	owner, attr, warn := AttributeOwner(req, m)
	if owner == nil || owner.Name != "bob" {
		t.Fatalf("want bob, got %v", owner)
	}
	if attr != AttrExactBearer {
		t.Errorf("attr: want %q got %q", AttrExactBearer, attr)
	}
	if len(warn) != 0 {
		t.Errorf("unexpected warnings: %v", warn)
	}
}

func TestAttributeOwner_ExactCookie(t *testing.T) {
	alice := model.Identity{Name: "alice", Rank: 10, Creds: &model.Credentials{Cookies: map[string]string{"session": "alice-sess"}}}
	bob := model.Identity{Name: "bob", Rank: 10, Creds: &model.Credentials{Cookies: map[string]string{"session": "bob-sess"}}}
	m := mkMatrix(alice, bob)
	req := mkReq(nil, map[string]string{"session": "alice-sess"})

	owner, attr, _ := AttributeOwner(req, m)
	if owner == nil || owner.Name != "alice" {
		t.Fatalf("want alice, got %v", owner)
	}
	if attr != AttrExactCookie {
		t.Errorf("attr: want %q got %q", AttrExactCookie, attr)
	}
}

func TestAttributeOwner_ExactHeader(t *testing.T) {
	alice := model.Identity{Name: "alice", Rank: 10, Creds: &model.Credentials{Headers: map[string]string{"X-Api-Key": "alice-key"}}}
	bob := model.Identity{Name: "bob", Rank: 10, Creds: &model.Credentials{Headers: map[string]string{"X-Api-Key": "bob-key"}}}
	m := mkMatrix(alice, bob)
	req := mkReq(map[string]string{"X-Api-Key": "bob-key"}, nil)

	owner, attr, _ := AttributeOwner(req, m)
	if owner == nil || owner.Name != "bob" {
		t.Fatalf("want bob, got %v", owner)
	}
	if attr != AttrExactHeader {
		t.Errorf("attr: want %q got %q", AttrExactHeader, attr)
	}
}

func TestAttributeOwner_BasicUsername(t *testing.T) {
	admin := model.Identity{Name: "admin", Rank: 100, Creds: &model.Credentials{Basic: &model.BasicAuth{Username: "admin", Password: "p"}}}
	m := mkMatrix(admin)
	enc := base64.StdEncoding.EncodeToString([]byte("admin:p"))
	req := mkReq(map[string]string{"Authorization": "Basic " + enc}, nil)

	owner, attr, _ := AttributeOwner(req, m)
	if owner == nil || owner.Name != "admin" {
		t.Fatalf("want admin, got %v", owner)
	}
	if attr != AttrBasicUsername {
		t.Errorf("attr: want %q got %q", AttrBasicUsername, attr)
	}
}

func TestAttributeOwner_FallbackHighestRank(t *testing.T) {
	alice := model.Identity{Name: "alice", Rank: 10, Creds: &model.Credentials{Bearer: "alice-tok"}}
	admin := model.Identity{Name: "admin", Rank: 100, Creds: &model.Credentials{Bearer: "admin-tok"}}
	m := mkMatrix(alice, admin)
	// Request with unrelated creds.
	req := mkReq(map[string]string{"Authorization": "Bearer who-dis"}, nil)

	owner, attr, _ := AttributeOwner(req, m)
	if owner == nil || owner.Name != "admin" {
		t.Fatalf("want admin (highest rank), got %v", owner)
	}
	if attr != AttrFallbackHighRank {
		t.Errorf("attr: want %q got %q", AttrFallbackHighRank, attr)
	}
}

func TestAttributeOwner_AmbiguityDeterministic(t *testing.T) {
	// Two identities share a cookie value — deterministic pick (rank asc, name asc) + warning.
	alice := model.Identity{Name: "alice", Rank: 10, Creds: &model.Credentials{Cookies: map[string]string{"session": "shared"}}}
	bob := model.Identity{Name: "bob", Rank: 10, Creds: &model.Credentials{Cookies: map[string]string{"session": "shared"}}}
	m := mkMatrix(bob, alice) // declared in reverse order
	req := mkReq(nil, map[string]string{"session": "shared"})

	owner, _, warn := AttributeOwner(req, m)
	if owner == nil || owner.Name != "alice" {
		t.Fatalf("want alice (deterministic tie-break by name asc), got %v", owner)
	}
	if len(warn) == 0 {
		t.Errorf("expected ambiguity warning, got none")
	}
}
