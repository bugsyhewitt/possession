package replay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/bugsyhewitt/possession/internal/model"
)

// A captured/mutated "Host" header must be promoted onto req.Host (net/http
// ignores a "Host" entry in the header map otherwise) and removed from the
// header map, so a host-spoof (host-header mutator) actually reaches the wire.
func TestBuildHTTPRequest_PromotesHostHeader(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/admin")
	h := http.Header{}
	h.Set("Host", "internal")
	h.Set("Authorization", "Bearer alice")
	base := &model.CapturedRequest{Method: "GET", URL: u, Headers: h}

	req, err := buildHTTPRequest(context.Background(), base)
	if err != nil {
		t.Fatalf("buildHTTPRequest: %v", err)
	}
	if req.Host != "internal" {
		t.Errorf("req.Host = %q; want internal (Host header must be promoted to the wire host)", req.Host)
	}
	if got := req.Header.Get("Host"); got != "" {
		t.Errorf("Host header still present in map (%q); must be removed to avoid duplication", got)
	}
	// Other headers are untouched.
	if req.Header.Get("Authorization") != "Bearer alice" {
		t.Errorf("Authorization header altered: %q", req.Header.Get("Authorization"))
	}
}

// When no Host header is present, req.Host is left as net/http set it from the
// URL host (http.NewRequest populates it) — the common path is unchanged.
func TestBuildHTTPRequest_NoHostHeaderUnchanged(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/admin")
	base := &model.CapturedRequest{Method: "GET", URL: u, Headers: http.Header{}}

	req, err := buildHTTPRequest(context.Background(), base)
	if err != nil {
		t.Fatalf("buildHTTPRequest: %v", err)
	}
	if req.Host != "api.example.com" {
		t.Errorf("req.Host = %q; want api.example.com (the URL host, unchanged)", req.Host)
	}
}

// End-to-end: a spoofed "Host" header on the variant must arrive on the wire as
// the request Host the server observes (r.Host), proving the host-header mutator
// actually reaches the target rather than being silently dropped by net/http.
func TestEngine_SpoofedHostReachesWire(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/admin")
	h := http.Header{}
	h.Set("Host", "internal")
	v := model.Variant{
		ID:       "spoof",
		Identity: nil,
		Base:     &model.CapturedRequest{Method: "GET", URL: u, Headers: h},
		Mutation: model.Mutation{Type: "host-header"},
	}

	e, _ := newTestEngine(t, model.RunSettings{Timeout: 5 * time.Second})
	res := e.Run(context.Background(), Plan{Variants: []model.Variant{v}})
	if len(res) != 1 || res[0].Status != 200 {
		t.Fatalf("bad result: %+v", res)
	}
	if gotHost != "internal" {
		t.Errorf("server observed Host = %q; want internal (spoofed host must reach the wire)", gotHost)
	}
}
