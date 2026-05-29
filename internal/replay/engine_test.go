package replay

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bugsyhewitt/possession/internal/model"
)

// mkVariant constructs a minimal Variant pointed at u.
func mkVariant(id, method, u string, ident *model.Identity) model.Variant {
	p, _ := url.Parse(u)
	return model.Variant{
		ID:       id,
		Identity: ident,
		Base: &model.CapturedRequest{
			Method:  method,
			URL:     p,
			Headers: http.Header{},
		},
		Mutation: model.Mutation{Type: "test"},
	}
}

func newTestEngine(t *testing.T, s model.RunSettings) (*Engine, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	if s.Timeout == 0 {
		s.Timeout = 5 * time.Second
	}
	return New(s, "possession/test", buf), buf
}

func TestEngine_Basic200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"ok":true}`)
	}))
	defer srv.Close()

	e, _ := newTestEngine(t, model.RunSettings{})
	v := mkVariant("v1", "GET", srv.URL+"/x", nil)
	res := e.Run(context.Background(), Plan{Variants: []model.Variant{v}})
	if len(res) != 1 || res[0].Status != 200 {
		t.Fatalf("bad result: %+v", res)
	}
	if !bytes.Contains(res[0].Body, []byte("ok")) {
		t.Errorf("body missing: %q", res[0].Body)
	}
}

func TestEngine_RedirectNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/elsewhere")
		w.WriteHeader(302)
	}))
	defer srv.Close()
	e, _ := newTestEngine(t, model.RunSettings{FollowRedirects: false})
	v := mkVariant("r", "GET", srv.URL+"/", nil)
	res := e.Run(context.Background(), Plan{Variants: []model.Variant{v}})
	if res[0].Status != 302 {
		t.Errorf("expected 302 observed; got %d", res[0].Status)
	}
}

func TestEngine_BodyCap(t *testing.T) {
	big := make([]byte, 200)
	for i := range big {
		big[i] = 'a'
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(big)
	}))
	defer srv.Close()

	e, _ := newTestEngine(t, model.RunSettings{MaxBody: 64})
	v := mkVariant("c", "GET", srv.URL, nil)
	res := e.Run(context.Background(), Plan{Variants: []model.Variant{v}})[0]
	if !res.Truncated {
		t.Error("expected Truncated=true")
	}
	if len(res.Body) != 64 {
		t.Errorf("body len: want 64 got %d", len(res.Body))
	}
}

func TestEngine_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Write([]byte("late"))
	}))
	defer srv.Close()
	e, _ := newTestEngine(t, model.RunSettings{Timeout: 50 * time.Millisecond})
	v := mkVariant("t", "GET", srv.URL, nil)
	res := e.Run(context.Background(), Plan{Variants: []model.Variant{v}})[0]
	if res.Err == "" {
		t.Error("expected Err on timeout")
	}
}

func TestEngine_429RetryAfter(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("done"))
	}))
	defer srv.Close()

	e, _ := newTestEngine(t, model.RunSettings{})
	v := mkVariant("r1", "GET", srv.URL, nil)
	start := time.Now()
	res := e.Run(context.Background(), Plan{Variants: []model.Variant{v}})[0]
	elapsed := time.Since(start)
	if res.Status != 200 {
		t.Fatalf("expected 200 after retry, got %d (err=%s)", res.Status, res.Err)
	}
	if elapsed < 900*time.Millisecond {
		t.Errorf("expected backoff ~1s, got %v", elapsed)
	}
}

func TestEngine_503Exhaustion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(503)
	}))
	defer srv.Close()

	e, _ := newTestEngine(t, model.RunSettings{})
	v := mkVariant("ex", "GET", srv.URL, nil)
	res := e.Run(context.Background(), Plan{Variants: []model.Variant{v}})[0]
	if res.Err == "" {
		t.Error("expected Err after 4 503 attempts")
	}
}

func TestEngine_RateLimitSpacing(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(204)
	}))
	defer srv.Close()
	e, _ := newTestEngine(t, model.RunSettings{RatePerHost: 2, Concurrency: 4})
	plan := Plan{Variants: []model.Variant{
		mkVariant("1", "GET", srv.URL, nil),
		mkVariant("2", "GET", srv.URL, nil),
		mkVariant("3", "GET", srv.URL, nil),
		mkVariant("4", "GET", srv.URL, nil),
	}}
	start := time.Now()
	_ = e.Run(context.Background(), plan)
	elapsed := time.Since(start)
	// 4 requests at 2/sec: burst=2 immediate, then 1s+1s ≈ 2s. Allow slack.
	if elapsed < 800*time.Millisecond {
		t.Errorf("rate limit not enforced: elapsed=%v", elapsed)
	}
}

func TestEngine_RefreshFailure_Inconclusive(t *testing.T) {
	// Refresh endpoint always 500s. The protected endpoint is fine, but the
	// identity's variant must be marked Inconclusive.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/refresh") {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ident := model.Identity{
		Name: "alice", Rank: 10,
		Refresh: &model.RefreshHook{
			Request: model.RawRequest{Method: "GET", URL: srv.URL + "/refresh"},
			Extract: []model.Extraction{{Name: "csrf", From: "header", Expr: "X-CSRF",
				Inject: model.Injection{Into: "header", Key: "X-CSRF"}}},
		},
	}
	m := &model.RoleMatrix{Identities: []model.Identity{ident}}
	e, errBuf := newTestEngine(t, model.RunSettings{})

	ctx := context.Background()
	e.PrepareRefresh(ctx, m)
	if !strings.Contains(errBuf.String(), "REFRESH FAILED") {
		t.Errorf("expected loud warning in stderr; got %q", errBuf.String())
	}

	v := mkVariant("v", "GET", srv.URL+"/protected", &ident)
	res := e.Run(ctx, Plan{Variants: []model.Variant{v}})[0]
	if !res.Inconclusive {
		t.Error("expected Inconclusive=true after refresh failure")
	}
}

func TestEngine_RefreshSuccess_InjectsHeader(t *testing.T) {
	var injected string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/refresh":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"csrf":"tok-XYZ"}`)
		default:
			injected = r.Header.Get("X-CSRF")
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()

	ident := model.Identity{
		Name: "alice", Rank: 10,
		Refresh: &model.RefreshHook{
			Request: model.RawRequest{Method: "GET", URL: srv.URL + "/refresh"},
			Extract: []model.Extraction{{Name: "csrf", From: "body-json", Expr: "$.csrf",
				Inject: model.Injection{Into: "header", Key: "X-CSRF"}}},
		},
	}
	m := &model.RoleMatrix{Identities: []model.Identity{ident}}
	e, _ := newTestEngine(t, model.RunSettings{})
	ctx := context.Background()
	e.PrepareRefresh(ctx, m)
	v := mkVariant("v", "GET", srv.URL+"/protected", &ident)
	_ = e.Run(ctx, Plan{Variants: []model.Variant{v}})
	if injected != "tok-XYZ" {
		t.Errorf("expected injected X-CSRF=tok-XYZ, got %q", injected)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if d, ok := parseRetryAfter("3"); !ok || d != 3*time.Second {
		t.Errorf("delta-seconds parse: %v %v", d, ok)
	}
	if _, ok := parseRetryAfter("garbage"); ok {
		t.Error("garbage should fail")
	}
}

// TestEngine_OnResponseHook verifies the OnResponse hook fires once per
// completed response with the correct baseline flag, and that RunWithKind
// returns the same plan-ordered slice as Run regardless of the hook. This is
// the seam that resume-on-interrupt uses to checkpoint responses as they land.
func TestEngine_OnResponseHook(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"ok":true}`)
	}))
	defer srv.Close()

	e, _ := newTestEngine(t, model.RunSettings{})

	var mu sync.Mutex
	seen := map[string]bool{}   // VariantID → baseline flag observed
	var calls atomic.Int64
	e.OnResponse = func(resp model.Response, baseline bool) {
		calls.Add(1)
		mu.Lock()
		seen[resp.VariantID] = baseline
		mu.Unlock()
	}

	plan := Plan{Variants: []model.Variant{
		mkVariant("v1", "GET", srv.URL+"/a", nil),
		mkVariant("v2", "GET", srv.URL+"/b", nil),
	}}
	res := e.RunWithKind(context.Background(), plan, true)

	if len(res) != 2 || res[0].VariantID != "v1" || res[1].VariantID != "v2" {
		t.Fatalf("plan order not preserved: %+v", res)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("OnResponse should fire once per variant; got %d calls", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if !seen["v1"] || !seen["v2"] {
		t.Errorf("baseline flag not propagated to hook: %+v", seen)
	}
}

// TestEngine_NilOnResponse_NoPanic confirms a nil hook is a no-op (the default
// path for every non-resume scan).
func TestEngine_NilOnResponse_NoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{}`)
	}))
	defer srv.Close()
	e, _ := newTestEngine(t, model.RunSettings{})
	res := e.RunWithKind(context.Background(), Plan{Variants: []model.Variant{
		mkVariant("v1", "GET", srv.URL+"/x", nil),
	}}, false)
	if len(res) != 1 || res[0].Status != 200 {
		t.Fatalf("nil hook altered behaviour: %+v", res)
	}
}
