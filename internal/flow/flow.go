// Package flow implements Tier-2 stateful multi-step authentication flows
// (Packet 7). A FlowDef is an ordered list of HTTP steps where each step
// can extract values used by later steps via {name} interpolation. Identities
// reference a flow by name; the replay engine executes the flow once (caching
// the result) and re-executes volatile steps per replay batch.
package flow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// Result is the output of executing a flow: a map of extracted variable
// names to their values, plus the index of the first volatile step so the
// caller knows which steps to re-run for freshness.
type Result struct {
	Vars         map[string]string
	VolatileHead int  // index of first volatile step; -1 if none
	Err          error
}

// Execute runs all steps in fd using client against baseURL. baseURL is
// prepended to relative step URLs. initialVars seeds the interpolation
// context (e.g. static credentials). Returns the accumulated variable map.
func Execute(ctx context.Context, client *http.Client, baseURL string, fd model.FlowDef, initialVars map[string]string) Result {
	vars := make(map[string]string, len(initialVars)+8)
	for k, v := range initialVars {
		vars[k] = v
	}
	volatileHead := -1
	for i, step := range fd.Steps {
		if err := ctx.Err(); err != nil {
			return Result{Vars: vars, VolatileHead: volatileHead, Err: fmt.Errorf("flow %q step %q: context: %w", fd.Name, step.Name, err)}
		}
		if step.Request == nil && step.OAuth2 == nil {
			// Steps without requests or oauth2 are pure extraction placeholders; skip.
			continue
		}
		var resp *http.Response
		var err error
		if step.OAuth2 != nil {
			resp, err = issueOAuth2Step(ctx, client, step.OAuth2, vars)
		} else {
			resp, err = issueStep(ctx, client, baseURL, step.Request, vars)
		}
		if err != nil {
			return Result{Vars: vars, VolatileHead: volatileHead, Err: fmt.Errorf("flow %q step %q: %w", fd.Name, step.Name, err)}
		}
		defer resp.Body.Close()
		var bodyBuf bytes.Buffer
		_, _ = bodyBuf.ReadFrom(resp.Body)
		body := bodyBuf.Bytes()

		for _, ex := range step.Extract {
			val, err := extractValue(ex, resp, body)
			if err != nil {
				return Result{Vars: vars, VolatileHead: volatileHead, Err: fmt.Errorf("flow %q step %q extract %q: %w", fd.Name, step.Name, ex.Name, err)}
			}
			vars[ex.Name] = val
			if ex.Volatile && volatileHead < 0 {
				volatileHead = i
			}
		}
	}
	return Result{Vars: vars, VolatileHead: volatileHead}
}

// ExecuteFrom re-executes steps from fromIndex onward using the accumulated
// vars (for volatile/nonce re-run). Returns updated vars.
func ExecuteFrom(ctx context.Context, client *http.Client, baseURL string, fd model.FlowDef, vars map[string]string, fromIndex int) (map[string]string, error) {
	out := make(map[string]string, len(vars))
	for k, v := range vars {
		out[k] = v
	}
	for i := fromIndex; i < len(fd.Steps); i++ {
		step := fd.Steps[i]
		if step.Request == nil && step.OAuth2 == nil {
			continue
		}
		var resp *http.Response
		var err error
		if step.OAuth2 != nil {
			resp, err = issueOAuth2Step(ctx, client, step.OAuth2, out)
		} else {
			resp, err = issueStep(ctx, client, baseURL, step.Request, out)
		}
		if err != nil {
			return out, fmt.Errorf("flow %q step %q (volatile re-run): %w", fd.Name, step.Name, err)
		}
		defer resp.Body.Close()
		var bodyBuf bytes.Buffer
		_, _ = bodyBuf.ReadFrom(resp.Body)
		body := bodyBuf.Bytes()
		for _, ex := range step.Extract {
			val, err := extractValue(ex, resp, body)
			if err != nil {
				return out, fmt.Errorf("flow %q step %q extract %q: %w", fd.Name, step.Name, ex.Name, err)
			}
			out[ex.Name] = val
		}
	}
	return out, nil
}

// Validate checks a FlowDef for structural errors:
// - step names unique
// - no cyclic {name} dependencies (a step cannot reference a name it extracts)
// - every {name} reference resolves to a name extracted by an earlier step
func Validate(fd model.FlowDef) []string {
	var errs []string
	seen := make(map[string]struct{})
	extracted := make(map[string]int) // name → step index where it's first extracted

	for i, step := range fd.Steps {
		if step.Name == "" {
			errs = append(errs, fmt.Sprintf("flow %q: step[%d] has no name", fd.Name, i))
		}
		if _, dup := seen[step.Name]; dup {
			errs = append(errs, fmt.Sprintf("flow %q: duplicate step name %q", fd.Name, step.Name))
		}
		seen[step.Name] = struct{}{}

		// Check {name} references in the request are already extracted.
		if step.Request != nil {
			refs := interpolationRefs(step.Request.URL + step.Request.Body)
			for hv := range step.Request.Headers {
				refs = append(refs, interpolationRefs(hv)...)
			}
			for _, ref := range refs {
				if defAt, ok := extracted[ref]; !ok {
					errs = append(errs, fmt.Sprintf("flow %q step %q: references {%s} but it is not extracted by any earlier step", fd.Name, step.Name, ref))
				} else if defAt >= i {
					errs = append(errs, fmt.Sprintf("flow %q step %q: cyclic dependency on {%s} (extracted at step %d)", fd.Name, step.Name, ref, defAt))
				}
			}
		}

		// Register extractions from this step.
		for _, ex := range step.Extract {
			if ex.Name == "" {
				errs = append(errs, fmt.Sprintf("flow %q step %q: extraction has no name", fd.Name, step.Name))
				continue
			}
			if _, dup := extracted[ex.Name]; dup {
				errs = append(errs, fmt.Sprintf("flow %q step %q: duplicate extraction name %q", fd.Name, step.Name, ex.Name))
			}
			extracted[ex.Name] = i
		}
	}
	return errs
}

// ─── internal helpers ─────────────────────────────────────────────────

// interpolationPattern matches {name} where name is a valid identifier.
// We restrict to [A-Za-z][A-Za-z0-9_-]* to avoid false matches inside
// JSON bodies like {"key":"value"}.
var interpolationPattern = regexp.MustCompile(`\{([A-Za-z][A-Za-z0-9_\-]*)\}`)

// interpolationRefs returns all {name} references in s.
func interpolationRefs(s string) []string {
	var out []string
	for _, m := range interpolationPattern.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// interpolate replaces {name} occurrences in s with vars[name].
func interpolate(s string, vars map[string]string) string {
	return interpolationPattern.ReplaceAllStringFunc(s, func(m string) string {
		name := m[1 : len(m)-1]
		if v, ok := vars[name]; ok {
			return v
		}
		return m // leave unreplaced if not found
	})
}

// issueOAuth2Step acquires a token via client_credentials or refresh_token grant.
// The response body is not closed — caller must close it.
func issueOAuth2Step(ctx context.Context, client *http.Client, def *model.OAuth2StepDef, vars map[string]string) (*http.Response, error) {
	tokenURL := interpolate(def.TokenURL, vars)
	if tokenURL == "" {
		return nil, fmt.Errorf("oauth2: token_url is required")
	}
	params := url.Values{
		"grant_type":    {def.Grant},
		"client_id":     {interpolate(def.ClientID, vars)},
		"client_secret": {interpolate(def.ClientSecret, vars)},
	}
	if def.Scope != "" {
		params.Set("scope", interpolate(def.Scope, vars))
	}
	switch def.Grant {
	case "client_credentials":
		// no additional params needed
	case "refresh_token":
		rt := interpolate(def.RefreshToken, vars)
		if rt == "" {
			return nil, fmt.Errorf("oauth2: refresh_token is required for grant=refresh_token")
		}
		params.Set("refresh_token", rt)
	default:
		return nil, fmt.Errorf("oauth2: unsupported grant type %q (want: client_credentials|refresh_token)", def.Grant)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return client.Do(req)
}

func issueStep(ctx context.Context, client *http.Client, baseURL string, rr *model.RawRequest, vars map[string]string) (*http.Response, error) {
	rawURL := interpolate(rr.URL, vars)
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(rawURL, "/")
	}
	body := interpolate(rr.Body, vars)
	method := rr.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range rr.Headers {
		req.Header.Set(k, interpolate(v, vars))
	}
	return client.Do(req)
}

func extractValue(ex model.FlowExtraction, resp *http.Response, body []byte) (string, error) {
	switch ex.From {
	case "cookie":
		for _, c := range resp.Cookies() {
			if c.Name == ex.Expr {
				return c.Value, nil
			}
		}
		return "", fmt.Errorf("cookie %q not found", ex.Expr)
	case "header":
		v := resp.Header.Get(ex.Expr)
		if v == "" {
			return "", fmt.Errorf("header %q not found or empty", ex.Expr)
		}
		return v, nil
	case "body-json":
		return extractBodyJSON(body, ex.Expr)
	case "body-regex":
		re, err := regexp.Compile(ex.Expr)
		if err != nil {
			return "", fmt.Errorf("invalid regex %q: %w", ex.Expr, err)
		}
		m := re.FindSubmatch(body)
		if m == nil {
			return "", fmt.Errorf("body-regex %q: no match", ex.Expr)
		}
		if len(m) > 1 {
			return string(m[1]), nil
		}
		return string(m[0]), nil
	default:
		return "", fmt.Errorf("unknown from %q", ex.From)
	}
}

// extractBodyJSON extracts a value using a minimal dotted-path selector.
// Supports $.key and $.key.subkey; no wildcards, no arrays.
func extractBodyJSON(body []byte, expr string) (string, error) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return "", fmt.Errorf("body-json: json parse: %w", err)
	}
	path := strings.TrimPrefix(expr, "$.")
	parts := strings.SplitN(path, ".", 2)
	val, ok := m[parts[0]]
	if !ok {
		return "", fmt.Errorf("body-json: key %q not found", parts[0])
	}
	if len(parts) == 2 {
		sub, ok := val.(map[string]any)
		if !ok {
			return "", fmt.Errorf("body-json: %q is not an object", parts[0])
		}
		val, ok = sub[parts[1]]
		if !ok {
			return "", fmt.Errorf("body-json: key %q not found in %q", parts[1], parts[0])
		}
	}
	switch v := val.(type) {
	case string:
		return v, nil
	case float64:
		return fmt.Sprintf("%g", v), nil
	case bool:
		if v {
			return "true", nil
		}
		return "false", nil
	default:
		b, _ := json.Marshal(val)
		return string(b), nil
	}
}
