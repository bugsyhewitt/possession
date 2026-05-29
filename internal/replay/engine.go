// Package replay issues baseline and variant HTTP requests and collects
// responses. It owns all network I/O for possession; mutators are pure.
//
// Engine guarantees (D15, D11, D12, D10):
//   - Per-host token-bucket rate limit + bounded concurrency
//   - Adaptive backoff on 429/503 honoring Retry-After
//   - Body capped at MaxBody; Truncated flagged when cap hit
//   - Tier-1 refresh hooks fire once per identity, before that identity's
//     variants; refresh failure aborts that identity (variants
//     Inconclusive) but does not abort the run
package replay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bugsyhewitt/possession/internal/flow"
	"github.com/bugsyhewitt/possession/internal/model"
)

// DefaultMaxBody is the per-response body cap (5 MB, D12).
const DefaultMaxBody = 5 * 1024 * 1024

// Engine drives a single scan: refresh, replay, collect.
type Engine struct {
	HTTP        *http.Client
	Limiter     *hostLimiter
	Concurrency int
	MaxBody     int64
	UserAgent   string
	Stderr      io.Writer

	// OnResponse, when non-nil, is invoked exactly once for each completed
	// response as soon as it is collected (ROADMAP v1.1 "resume on
	// interrupt"). It runs on worker goroutines and may be called
	// concurrently, so an implementation must be safe for concurrent use.
	// Run still returns the full plan-ordered slice regardless; the hook is
	// purely additive so a nil hook preserves the previous behaviour exactly.
	OnResponse func(resp model.Response, baseline bool)

	// refresh caches per-identity refresh results so each identity's hook
	// fires at most once per scan (4.4).
	mu      sync.Mutex
	refresh map[string]*refreshResult // keyed by identity name
	// flows caches per-identity flow execution results (P7).
	flows    map[string]*flowExecResult // keyed by identity name
	// flowHTTP is a jar-free HTTP client used exclusively for flow execution.
	// Flows establish their own credentials via explicit extractions; the main
	// client's cookie jar must not bleed cross-identity session state into
	// flow-obtained credentials.
	flowHTTP *http.Client
}

// flowExecResult holds the outcome of executing a stateful flow for one identity.
type flowExecResult struct {
	vars         map[string]string // extracted variables from flow execution
	injections   map[string]model.Injection // name → injection target
	volatileHead int               // first volatile step index (-1 = none)
	flowDef      *model.FlowDef    // the flow definition for volatile re-runs
	err          error
}

// refreshResult captures the outcome of a single identity's refresh hook.
type refreshResult struct {
	// values holds extracted name → value pairs.
	values map[string]string
	// injections maps name → original Injection so we know where to put each value.
	injections map[string]model.Injection
	err        error
}

// New constructs an Engine from settings. Pass settings.MaxBody=0 to use
// DefaultMaxBody.
func New(s model.RunSettings, userAgent string, stderr io.Writer) *Engine {
	if userAgent == "" {
		userAgent = "possession/dev"
	}
	if stderr == nil {
		stderr = io.Discard
	}
	maxBody := s.MaxBody
	if maxBody <= 0 {
		maxBody = DefaultMaxBody
	}
	conc := s.Concurrency
	if conc <= 0 {
		conc = 5
	}
	rate := s.RatePerHost
	if rate <= 0 {
		rate = 10
	}

	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: s.Insecure}, // #nosec G402 - lab opt-in
		Proxy:           http.ProxyFromEnvironment,
	}
	client := &http.Client{
		Timeout:   s.Timeout,
		Transport: transport,
		Jar:       jar,
	}
	if !s.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// flowHTTP is a separate client with no cookie jar. Flows must not share
	// session state across identities via the jar (D43 / integration fix).
	flowClient := &http.Client{
		Timeout:   s.Timeout,
		Transport: transport,
	}
	if !s.FollowRedirects {
		flowClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return &Engine{
		HTTP:        client,
		Limiter:     newHostLimiter(rate, s.NoLimit),
		Concurrency: conc,
		MaxBody:     maxBody,
		UserAgent:   userAgent,
		Stderr:      stderr,
		refresh:     make(map[string]*refreshResult),
		flows:       make(map[string]*flowExecResult),
		flowHTTP:    flowClient,
	}
}

// PrepareFlows executes named flows for every identity that references one
// (P7). Results are cached; a flow failure marks that identity's variants
// inconclusive (D10 policy, consistent with Tier-1 refresh).
func (e *Engine) PrepareFlows(ctx context.Context, matrix *model.RoleMatrix) {
	if matrix == nil || len(matrix.Flows) == 0 {
		return
	}
	for i := range matrix.Identities {
		ident := matrix.Identities[i]
		if ident.FlowName == "" {
			continue
		}
		e.mu.Lock()
		_, done := e.flows[ident.Name]
		e.mu.Unlock()
		if done {
			continue
		}
		fd, ok := matrix.Flows[ident.FlowName]
		if !ok {
			res := &flowExecResult{err: fmt.Errorf("flow %q not found in matrix.flows", ident.FlowName)}
			fmt.Fprintf(e.Stderr,
				"!!! FLOW FAILED for identity %q: %v — variants will be inconclusive\n",
				ident.Name, res.err)
			e.mu.Lock()
			e.flows[ident.Name] = res
			e.mu.Unlock()
			continue
		}
		baseURL := ""
		if matrix.Target.BaseURL != "" {
			baseURL = matrix.Target.BaseURL
		}
		result := flow.Execute(ctx, e.flowHTTP, baseURL, fd, nil)
		res := &flowExecResult{
			vars:         result.Vars,
			volatileHead: result.VolatileHead,
			flowDef:      &fd,
		}
		if result.Err != nil {
			res.err = result.Err
			fmt.Fprintf(e.Stderr,
				"!!! FLOW FAILED for identity %q: %v — variants will be inconclusive\n",
				ident.Name, res.err)
		} else {
			// Build injection map from flow extractions.
			res.injections = make(map[string]model.Injection)
			for _, step := range fd.Steps {
				for _, ex := range step.Extract {
					if ex.Inject.Into != "" {
						res.injections[ex.Name] = ex.Inject
					}
				}
			}
		}
		e.mu.Lock()
		e.flows[ident.Name] = res
		e.mu.Unlock()
	}
}

// PrepareRefresh fires the refresh hook for every identity that has one
// (D3). Results are cached on the engine; subsequent calls are no-ops.
// Refresh failures are recorded on the cache entry so per-variant code can
// short-circuit to Inconclusive (D10) and log the loud warning once.
func (e *Engine) PrepareRefresh(ctx context.Context, matrix *model.RoleMatrix) {
	if matrix == nil {
		return
	}
	for i := range matrix.Identities {
		ident := matrix.Identities[i]
		if ident.Refresh == nil {
			continue
		}
		e.mu.Lock()
		_, done := e.refresh[ident.Name]
		e.mu.Unlock()
		if done {
			continue
		}
		res := e.runRefresh(ctx, &ident)
		if res.err != nil {
			fmt.Fprintf(e.Stderr,
				"!!! REFRESH FAILED for identity %q: %v — variants for this identity will be marked inconclusive\n",
				ident.Name, res.err)
		}
		e.mu.Lock()
		e.refresh[ident.Name] = res
		e.mu.Unlock()
	}
}

func (e *Engine) runRefresh(ctx context.Context, ident *model.Identity) *refreshResult {
	res := &refreshResult{
		values:     make(map[string]string),
		injections: make(map[string]model.Injection),
	}
	rh := ident.Refresh
	if rh == nil {
		return res
	}
	method := rh.Request.Method
	if method == "" {
		method = "GET"
	}
	body := io.Reader(nil)
	if rh.Request.Body != "" {
		body = strings.NewReader(rh.Request.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rh.Request.URL, body)
	if err != nil {
		res.err = fmt.Errorf("build request: %w", err)
		return res
	}
	for k, v := range rh.Request.Headers {
		req.Header.Set(k, v)
	}
	// Apply the identity's static creds so the refresh hook is authenticated.
	applyIdentityToRequest(req, ident)
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", e.UserAgent)
	}

	if u, _ := url.Parse(rh.Request.URL); u != nil {
		if err := e.Limiter.wait(ctx, u.Host); err != nil {
			res.err = fmt.Errorf("limiter wait: %w", err)
			return res
		}
	}

	resp, err := e.HTTP.Do(req)
	if err != nil {
		res.err = fmt.Errorf("do: %w", err)
		return res
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, e.MaxBody))
	if err != nil {
		res.err = fmt.Errorf("read body: %w", err)
		return res
	}

	if resp.StatusCode >= 400 {
		res.err = fmt.Errorf("refresh returned status %d", resp.StatusCode)
		return res
	}

	// Parse JSON eagerly only if we have any body-json extractions.
	var jsonDoc any
	for _, ex := range rh.Extract {
		if ex.From == "body-json" {
			if err := json.Unmarshal(rawBody, &jsonDoc); err != nil {
				res.err = fmt.Errorf("decode body-json: %w", err)
				return res
			}
			break
		}
	}

	for _, ex := range rh.Extract {
		val, err := extractOne(ex, jsonDoc, rawBody, resp)
		if err != nil {
			res.err = fmt.Errorf("extract %q: %w", ex.Name, err)
			return res
		}
		res.values[ex.Name] = val
		res.injections[ex.Name] = ex.Inject
	}
	return res
}

func extractOne(ex model.Extraction, jsonDoc any, body []byte, resp *http.Response) (string, error) {
	switch ex.From {
	case "body-json":
		v, err := DottedPath(ex.Expr, jsonDoc)
		if err != nil {
			return "", err
		}
		return fmt.Sprint(v), nil
	case "body-regex":
		re, err := regexp.Compile(ex.Expr)
		if err != nil {
			return "", fmt.Errorf("compile regex: %w", err)
		}
		m := re.FindSubmatch(body)
		if len(m) < 2 {
			return "", fmt.Errorf("regex matched no capture group")
		}
		return string(m[1]), nil
	case "header":
		v := resp.Header.Get(ex.Expr)
		if v == "" {
			return "", fmt.Errorf("response header %q missing", ex.Expr)
		}
		return v, nil
	case "cookie":
		for _, c := range resp.Cookies() {
			if c.Name == ex.Expr {
				return c.Value, nil
			}
		}
		return "", fmt.Errorf("response cookie %q missing", ex.Expr)
	default:
		return "", fmt.Errorf("unsupported extract.from %q", ex.From)
	}
}

// applyIdentityToRequest layers an identity's static credentials onto a live
// http.Request. Mirrors mutate.applyIdentity, but works against an outgoing
// http.Request rather than a CapturedRequest. Kept here to avoid an import
// cycle with internal/mutate.
func applyIdentityToRequest(req *http.Request, ident *model.Identity) {
	if ident == nil || ident.Creds == nil {
		return
	}
	c := ident.Creds
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	for name, val := range c.Cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: val})
	}
	if c.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.Bearer)
	}
	if c.Basic != nil {
		req.SetBasicAuth(c.Basic.Username, c.Basic.Password)
	}
}

// Run replays a Plan and returns one Response per Variant, paired by slice
// position. Bounded concurrency per Engine.Concurrency; results are
// re-sorted into plan order before return so the output is deterministic
// regardless of which worker finished first.
//
// Run treats the plan as a variant plan for the OnResponse hook. Use
// RunWithKind to fire a baseline plan so checkpointed responses are routed to
// the baseline set.
func (e *Engine) Run(ctx context.Context, plan Plan) []model.Response {
	return e.RunWithKind(ctx, plan, false)
}

// RunWithKind is Run with an explicit baseline flag for the OnResponse hook.
// baseline=true marks every completed response as an owner-baseline response so
// resume checkpointing can route it to the baseline set; the network behaviour
// is identical to Run.
func (e *Engine) RunWithKind(ctx context.Context, plan Plan, baseline bool) []model.Response {
	type job struct {
		idx int
		v   model.Variant
	}
	jobs := make(chan job)
	out := make([]model.Response, len(plan.Variants))

	var wg sync.WaitGroup
	for w := 0; w < e.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				r := e.fire(ctx, j.v)
				out[j.idx] = r
				if e.OnResponse != nil {
					e.OnResponse(r, baseline)
				}
			}
		}()
	}

	for i, v := range plan.Variants {
		select {
		case <-ctx.Done():
		case jobs <- job{idx: i, v: v}:
		}
	}
	close(jobs)
	wg.Wait()
	return out
}

// fire is the inner per-variant execution: refresh inconclusive check,
// build http.Request, limiter wait, retry on 429/503, body cap, response
// record.
func (e *Engine) fire(ctx context.Context, v model.Variant) model.Response {
	resp := model.Response{VariantID: v.ID}

	// Refresh-failure short circuit (D10).
	if v.Identity != nil {
		e.mu.Lock()
		rr, ok := e.refresh[v.Identity.Name]
		e.mu.Unlock()
		if ok && rr.err != nil {
			resp.Inconclusive = true
			resp.Err = "refresh failed: " + rr.err.Error()
			return resp
		}
		// Flow-failure short circuit (P7, same D10 policy).
		e.mu.Lock()
		fr, fok := e.flows[v.Identity.Name]
		e.mu.Unlock()
		if fok && fr.err != nil {
			resp.Inconclusive = true
			resp.Err = "flow failed: " + fr.err.Error()
			return resp
		}
	}

	req, err := buildHTTPRequest(ctx, v.Base)
	if err != nil {
		resp.Err = err.Error()
		return resp
	}
	req.Header.Set("User-Agent", e.UserAgent)

	// Apply refresh injections AFTER mutate has already shaped creds on the
	// base. Injections are per-identity dynamic values; mutate-baked creds
	// are static.
	if v.Identity != nil {
		e.applyInjections(req, v.Identity.Name)
		// Apply flow variable injections (P7).
		e.applyFlowInjections(req, v.Identity.Name, ctx)
	}

	start := time.Now()
	httpResp, fireErr := e.doWithRetry(ctx, req)
	resp.DurationMS = time.Since(start).Milliseconds()
	if fireErr != nil {
		resp.Err = fireErr.Error()
		return resp
	}
	defer httpResp.Body.Close()

	resp.Status = httpResp.StatusCode
	resp.Headers = httpResp.Header.Clone()

	limited := io.LimitReader(httpResp.Body, e.MaxBody+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		resp.Err = "read body: " + err.Error()
		return resp
	}
	if int64(len(body)) > e.MaxBody {
		resp.Truncated = true
		body = body[:e.MaxBody]
	}
	resp.Body = body
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		resp.BodySHA256 = hex.EncodeToString(sum[:])
	}
	if cl := httpResp.Header.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
			resp.BodySize = n
		}
	}
	if resp.BodySize == 0 {
		resp.BodySize = int64(len(body))
	}
	return resp
}

func buildHTTPRequest(ctx context.Context, base *model.CapturedRequest) (*http.Request, error) {
	if base == nil || base.URL == nil {
		return nil, errors.New("buildHTTPRequest: nil base or URL")
	}
	var body io.Reader
	if len(base.Body) > 0 {
		body = bytes.NewReader(base.Body)
	}
	req, err := http.NewRequestWithContext(ctx, base.Method, base.URL.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header = base.Headers.Clone()
	if req.Header == nil {
		req.Header = http.Header{}
	}
	// net/http sends the Host from req.Host, NOT a "Host" entry in the header
	// map (it ignores the latter). Promote a captured/mutated Host header onto
	// req.Host so a spoofed host (host-header mutator) and any genuinely
	// captured Host actually reach the wire; then drop it from the header map to
	// avoid a duplicate. When absent, req.Host stays empty and net/http derives
	// it from the URL host as before.
	if h := req.Header.Get("Host"); h != "" {
		req.Host = h
		req.Header.Del("Host")
	}
	for _, c := range base.Cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	return req, nil
}

func (e *Engine) applyInjections(req *http.Request, identName string) {
	e.mu.Lock()
	rr, ok := e.refresh[identName]
	e.mu.Unlock()
	if !ok || rr == nil {
		return
	}
	for name, val := range rr.values {
		inj := rr.injections[name]
		switch inj.Into {
		case "header":
			req.Header.Set(inj.Key, val)
		case "cookie":
			req.AddCookie(&http.Cookie{Name: inj.Key, Value: val})
		case "query":
			q := req.URL.Query()
			q.Set(inj.Key, val)
			req.URL.RawQuery = q.Encode()
		case "body-json":
			// Only attempt on JSON bodies. We round-trip the body through a
			// map; if it isn't a JSON object we silently skip.
			if req.Body == nil {
				continue
			}
			raw, err := io.ReadAll(req.Body)
			req.Body.Close()
			if err != nil {
				continue
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				// Not a JSON object — restore body and skip.
				req.Body = io.NopCloser(bytes.NewReader(raw))
				req.ContentLength = int64(len(raw))
				continue
			}
			doc[inj.Key] = val
			updated, _ := json.Marshal(doc)
			req.Body = io.NopCloser(bytes.NewReader(updated))
			req.ContentLength = int64(len(updated))
		}
	}
}

// applyFlowInjections applies flow-extracted variable values to req using each
// extraction's Inject directive. For volatile variables, re-runs the volatile
// tail first to ensure freshness.
func (e *Engine) applyFlowInjections(req *http.Request, identName string, ctx context.Context) {
	e.mu.Lock()
	fr, ok := e.flows[identName]
	e.mu.Unlock()
	if !ok || fr == nil || fr.err != nil || len(fr.injections) == 0 {
		return
	}

	// Copy vars and flow metadata under lock to prevent data races with
	// concurrent goroutines that may be updating fr.vars (volatile re-runs).
	e.mu.Lock()
	vars := make(map[string]string, len(fr.vars))
	for k, v := range fr.vars {
		vars[k] = v
	}
	volatileHead := fr.volatileHead
	flowDef := fr.flowDef
	e.mu.Unlock()

	// Re-run volatile tail for nonce/CSRF freshness (outside the lock — this
	// makes network I/O and must not hold the mutex).
	if volatileHead >= 0 && flowDef != nil {
		updated, err := flow.ExecuteFrom(ctx, e.flowHTTP, "", *flowDef, vars, volatileHead)
		if err == nil {
			vars = updated
			// Write updated values back key-by-key under lock so concurrent
			// readers always see a consistent map.
			e.mu.Lock()
			for k, v := range updated {
				fr.vars[k] = v
			}
			e.mu.Unlock()
		}
	}

	for name, inj := range fr.injections {
		val, ok := vars[name]
		if !ok {
			continue
		}
		switch inj.Into {
		case "header":
			req.Header.Set(inj.Key, val)
		case "cookie":
			req.AddCookie(&http.Cookie{Name: inj.Key, Value: val})
		case "query":
			q := req.URL.Query()
			q.Set(inj.Key, val)
			req.URL.RawQuery = q.Encode()
		}
	}
}

// doWithRetry honors 429/503 with Retry-After (D15). Up to 3 retries with
// exponential 1s/2s/4s cap. Retry-After overrides exponential when present.
func (e *Engine) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	const maxAttempts = 4 // initial + 3 retries
	backoffs := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}

	var lastBodyClose func() error
	host := ""
	if req.URL != nil {
		host = req.URL.Host
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := e.Limiter.wait(ctx, host); err != nil {
			return nil, err
		}
		// Need a fresh body each attempt — net/http consumed it.
		if attempt > 0 && req.GetBody != nil {
			b, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			req.Body = b
		}
		resp, err := e.HTTP.Do(req)
		if err != nil {
			lastBodyClose = nil
			if attempt == maxAttempts-1 {
				return nil, err
			}
			wait := backoffs[attempt]
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable {
			return resp, nil
		}
		// Final attempt: surface as error rather than handing back the
		// 429/503 (D15 "errored" semantics).
		if attempt == maxAttempts-1 {
			status := resp.StatusCode
			resp.Body.Close()
			return nil, fmt.Errorf("status %d after %d attempts", status, maxAttempts)
		}
		// Backoff per Retry-After else exponential.
		wait := backoffs[attempt]
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if d, ok := parseRetryAfter(ra); ok {
				wait = d
			}
		}
		resp.Body.Close()
		lastBodyClose = nil
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	_ = lastBodyClose
	return nil, errors.New("doWithRetry: exhausted")
}

func parseRetryAfter(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	// delta-seconds
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second, true
	}
	// HTTP-date
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}
