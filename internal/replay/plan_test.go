package replay

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
	"github.com/bugsyhewitt/possession/internal/mutate"
)

func mkEndpoint(method, host, tmpl string, sampleIDs ...string) *model.Endpoint {
	samples := make([]*model.CapturedRequest, 0, len(sampleIDs))
	for _, id := range sampleIDs {
		u, _ := url.Parse("https://" + host + tmpl)
		samples = append(samples, &model.CapturedRequest{
			ID:      id,
			Method:  method,
			URL:     u,
			Headers: http.Header{},
		})
	}
	return &model.Endpoint{
		Method:       method,
		Host:         host,
		PathTemplate: tmpl,
		Samples:      samples,
	}
}

func TestGenerate_DeterministicIDs(t *testing.T) {
	eps := []*model.Endpoint{
		mkEndpoint("GET", "api.example.com", "/api/users/{id}", "b", "a", "c"),
		mkEndpoint("POST", "api.example.com", "/api/orders", "x"),
	}
	m := &model.RoleMatrix{
		Identities: []model.Identity{
			{Name: "alice", Rank: 10},
			{Name: "bob", Rank: 10},
		},
	}
	p1 := Generate(eps, m, mutate.DefaultRegistry(), 0)
	p2 := Generate(eps, m, mutate.DefaultRegistry(), 0)
	if len(p1.Variants) != len(p2.Variants) {
		t.Fatalf("variant count mismatch: %d vs %d", len(p1.Variants), len(p2.Variants))
	}
	for i := range p1.Variants {
		if p1.Variants[i].ID != p2.Variants[i].ID {
			t.Errorf("non-deterministic ID at %d: %q vs %q", i, p1.Variants[i].ID, p2.Variants[i].ID)
		}
	}
	// Sample picked must be the smallest ID — "a", not "b".
	for _, v := range p1.Variants {
		if v.Base != nil && v.Base.ID == "b" || v.Base != nil && v.Base.ID == "c" {
			t.Errorf("wrong sample picked: %q (expected 'a')", v.Base.ID)
		}
	}
}

func TestGenerate_OrderingEndpointMethodPath(t *testing.T) {
	eps := []*model.Endpoint{
		mkEndpoint("POST", "h", "/z", "x"),
		mkEndpoint("GET", "h", "/a", "y"),
		mkEndpoint("GET", "h", "/b", "z"),
	}
	m := &model.RoleMatrix{Identities: []model.Identity{{Name: "alice", Rank: 10}}}
	p := Generate(eps, m, mutate.DefaultRegistry(), 0)
	if len(p.Variants) == 0 {
		t.Fatal("expected variants")
	}
	// First variant should be from GET /a
	if p.Variants[0].Base.Method != "GET" || p.Variants[0].Base.URL.Path != "/a" {
		t.Errorf("first variant should be GET /a, got %s %s",
			p.Variants[0].Base.Method, p.Variants[0].Base.URL.Path)
	}
}

func TestGenerate_MaxVariantsCap(t *testing.T) {
	eps := []*model.Endpoint{
		mkEndpoint("GET", "h", "/a", "1"),
		mkEndpoint("GET", "h", "/b", "2"),
		mkEndpoint("GET", "h", "/c", "3"),
	}
	m := &model.RoleMatrix{Identities: []model.Identity{
		{Name: "a", Rank: 1},
		{Name: "b", Rank: 2},
	}}
	p := Generate(eps, m, mutate.DefaultRegistry(), 4)
	if !p.Capped {
		t.Error("expected Capped=true")
	}
	if len(p.Variants) != 4 {
		t.Errorf("variants len: want 4 got %d", len(p.Variants))
	}
	if p.TotalBefore <= 4 {
		t.Errorf("TotalBefore should exceed cap, got %d", p.TotalBefore)
	}
}

func TestVariantID_Stable(t *testing.T) {
	a := variantID("GET host/x", "swap-identity", "alice",
		map[string]string{"swapped_to": "alice"})
	b := variantID("GET host/x", "swap-identity", "alice",
		map[string]string{"swapped_to": "alice"})
	if a != b {
		t.Errorf("same inputs ⇒ different IDs: %q vs %q", a, b)
	}
	if len(a) != 16 {
		t.Errorf("ID len: want 16 got %d", len(a))
	}
}

func TestVariantID_DifferentDetailsDiffer(t *testing.T) {
	a := variantID("GET h/x", "swap", "alice", map[string]string{"k": "v1"})
	b := variantID("GET h/x", "swap", "alice", map[string]string{"k": "v2"})
	if a == b {
		t.Error("different details should produce different IDs")
	}
}
