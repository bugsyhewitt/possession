package normalize

import (
	"net/url"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func TestDedup(t *testing.T) {
	reqs := []*model.CapturedRequest{
		{Method: "GET", URL: mustURL(t, "https://a.example.com/api/users/1")},
		{Method: "GET", URL: mustURL(t, "https://a.example.com/api/users/2")},
		{Method: "POST", URL: mustURL(t, "https://a.example.com/api/users")},
		{Method: "GET", URL: mustURL(t, "https://b.example.com/api/users/3")},
	}
	Apply(reqs)
	eps := Dedup(reqs)
	if len(eps) != 3 {
		t.Fatalf("got %d endpoints, want 3", len(eps))
	}
	// Endpoints are sorted by host then path then method.
	if eps[0].Host != "a.example.com" || eps[0].PathTemplate != "/api/users" || eps[0].Method != "POST" {
		t.Errorf("endpoints[0] = %+v", eps[0])
	}
	if eps[1].PathTemplate != "/api/users/{id}" || len(eps[1].Samples) != 2 {
		t.Errorf("endpoints[1] = %+v (samples=%d)", eps[1], len(eps[1].Samples))
	}
	if eps[2].Host != "b.example.com" {
		t.Errorf("endpoints[2] = %+v", eps[2])
	}
}
