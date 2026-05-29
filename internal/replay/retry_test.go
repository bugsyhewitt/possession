package replay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

func TestIsTransientFailure(t *testing.T) {
	cases := []struct {
		name string
		resp *model.Response
		want bool
	}{
		{"nil response", nil, true},
		{"transport error", &model.Response{Err: "dial tcp: connection refused"}, true},
		{"429 too many requests", &model.Response{Status: http.StatusTooManyRequests}, true},
		{"500 internal error", &model.Response{Status: 500}, true},
		{"503 unavailable", &model.Response{Status: 503}, true},
		{"200 ok", &model.Response{Status: 200}, false},
		{"403 denied", &model.Response{Status: 403}, false},
		{"404 not found", &model.Response{Status: 404}, false},
		{"302 redirect", &model.Response{Status: 302}, false},
		// Inconclusive (refresh/flow failure) is NOT retryable even if a status
		// or error is present — a single variant retry cannot fix per-identity
		// setup failures.
		{"inconclusive refresh failure", &model.Response{Inconclusive: true, Err: "refresh failed"}, false},
		{"inconclusive with 500", &model.Response{Inconclusive: true, Status: 500}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsTransientFailure(c.resp); got != c.want {
				t.Errorf("IsTransientFailure(%+v) = %v, want %v", c.resp, got, c.want)
			}
		})
	}
}

// TestRetryInconclusive_RecoversFlake fires a server that returns 500 on first
// contact and 200 thereafter. After the initial Run leaves a transient 500, a
// RetryInconclusive pass should recover it to a 200.
func TestRetryInconclusive_RecoversFlake(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	e, _ := newTestEngine(t, model.RunSettings{})
	plan := Plan{Variants: []model.Variant{mkVariant("v1", "GET", srv.URL+"/x", nil)}}

	responses := e.Run(context.Background(), plan)
	if responses[0].Status != 500 {
		t.Fatalf("setup: expected first attempt 500, got %d", responses[0].Status)
	}

	out, retried, improved := e.RetryInconclusive(context.Background(), plan, responses)
	if retried != 1 {
		t.Errorf("retried = %d, want 1", retried)
	}
	if improved != 1 {
		t.Errorf("improved = %d, want 1", improved)
	}
	if out[0].Status != 200 {
		t.Errorf("after retry: status = %d, want 200", out[0].Status)
	}
}

// TestRetryInconclusive_KeepsOriginalWhenRetryAlsoFails verifies a target that
// stays broken does not make the result worse: the original transient response
// is preserved and improved stays 0.
func TestRetryInconclusive_KeepsOriginalWhenRetryAlsoFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	e, _ := newTestEngine(t, model.RunSettings{})
	plan := Plan{Variants: []model.Variant{mkVariant("v1", "GET", srv.URL+"/x", nil)}}

	responses := e.Run(context.Background(), plan)
	out, retried, improved := e.RetryInconclusive(context.Background(), plan, responses)
	if retried != 1 {
		t.Errorf("retried = %d, want 1", retried)
	}
	if improved != 0 {
		t.Errorf("improved = %d, want 0 (still failing)", improved)
	}
	if out[0].Status != 500 {
		t.Errorf("status = %d, want original 500 preserved", out[0].Status)
	}
}

// TestRetryInconclusive_SkipsHealthyAndInconclusive verifies only transient
// failures are re-issued: 200s and refresh-failure inconclusives are left
// alone and never re-hit the server.
func TestRetryInconclusive_SkipsHealthyAndInconclusive(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	e, _ := newTestEngine(t, model.RunSettings{})
	plan := Plan{Variants: []model.Variant{
		mkVariant("ok", "GET", srv.URL+"/a", nil),
		mkVariant("inc", "GET", srv.URL+"/b", nil),
	}}
	responses := []model.Response{
		{VariantID: "ok", Status: 200},
		{VariantID: "inc", Inconclusive: true, Err: "refresh failed"},
	}

	out, retried, improved := e.RetryInconclusive(context.Background(), plan, responses)
	if retried != 0 {
		t.Errorf("retried = %d, want 0 (nothing transient)", retried)
	}
	if improved != 0 {
		t.Errorf("improved = %d, want 0", improved)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Errorf("server hit %d time(s); retry should have fired no requests", hits)
	}
	if out[0].Status != 200 || !out[1].Inconclusive {
		t.Errorf("responses mutated unexpectedly: %+v", out)
	}
}

// TestRetryInconclusive_OnResponseFiresOnlyForKeptRetries verifies the
// OnResponse hook (used by --resume/--record) is invoked once per recovered
// retry and never for a discarded one.
func TestRetryInconclusive_OnResponseFiresOnlyForKeptRetries(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /good recovers on retry; /bad stays 500.
		if r.URL.Path == "/good" && atomic.AddInt32(&hits, 1) >= 1 {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(500)
	}))
	defer srv.Close()

	e, _ := newTestEngine(t, model.RunSettings{})
	plan := Plan{Variants: []model.Variant{
		mkVariant("good", "GET", srv.URL+"/good", nil),
		mkVariant("bad", "GET", srv.URL+"/bad", nil),
	}}
	// Both started transient.
	responses := []model.Response{
		{VariantID: "good", Status: 500},
		{VariantID: "bad", Status: 500},
	}

	var mu sync.Mutex
	var hooked []string
	e.OnResponse = func(resp model.Response, baseline bool) {
		mu.Lock()
		hooked = append(hooked, resp.VariantID)
		mu.Unlock()
	}

	out, retried, improved := e.RetryInconclusive(context.Background(), plan, responses)
	if retried != 2 {
		t.Errorf("retried = %d, want 2", retried)
	}
	if improved != 1 {
		t.Errorf("improved = %d, want 1", improved)
	}
	if out[0].Status != 200 {
		t.Errorf("good variant status = %d, want 200", out[0].Status)
	}
	if out[1].Status != 500 {
		t.Errorf("bad variant status = %d, want 500 preserved", out[1].Status)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hooked) != 1 || hooked[0] != "good" {
		t.Errorf("OnResponse fired for %v, want exactly [good]", hooked)
	}
}
