package mutate

import (
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// CSRFHeader is the anti-CSRF-token bypass mutator. Where StripToken *removes*
// the CSRF header to probe whether the server depends on it (auth-dependency),
// this mutator forges or reshapes the CSRF token to probe whether the server's
// CSRF validation can be satisfied with a value the caller controls — the
// classic broken double-submit-cookie / presence-only-check family.
//
// Every variant keeps the caller's own credentials (Identity == nil): this is
// not an identity swap and not a token-strip. The bug being tested is "the same
// caller forges a CSRF token the server should reject, and the request still
// succeeds." A server that issues per-session CSRF tokens and validates them
// server-side rejects all of these; a server that merely checks
//   - header == cookie (without binding either to the session), or
//   - "a CSRF header is present and non-empty", or
//   - that the header reflects the cookie value
//
// accepts a forged token and is vulnerable to cross-site request forgery.
//
// Three techniques, each emitted as a separate variant for attribution:
//
//   - forged-double-submit: when both a CSRF header and a CSRF cookie are
//     present, overwrite BOTH with one identical attacker-chosen value. A naive
//     double-submit check (header == cookie) passes; a server-side-bound token
//     fails. Only emitted when both sides exist.
//   - reflect-cookie-to-header: copy the CSRF *cookie* value into the CSRF
//     *header* verbatim. The textbook double-submit reflection — an attacker who
//     can plant the cookie (subdomain, login-CSRF, cookie tossing) then controls
//     the header. Emitted when a CSRF cookie exists; the header is set/overwritten
//     to the cookie's value.
//   - inject-missing-header: when NO CSRF header is present, inject a plausible
//     one with an attacker-chosen value. Tests presence-only enforcement (the
//     server accepts any non-empty token). Only emitted when no CSRF header
//     already exists.
//
// Detection rides the existing comparative ladder unchanged: the caller's own
// baseline is the legitimate request with its real CSRF token; a variant that
// returns an owner-shaped 2xx with a forged/reflected token is the bypass.
// Findings are class "authz-bypass" (CSRF is a request-forgery access-control
// failure; ASVS V8.3.x / V13).
//
// Generate is pure and deterministic: techniques are emitted in a fixed
// sorted-by-name order, and the forged token is a constant, so identical inputs
// yield an identical variant slice (--dry-run and the offline corpus cover it).
//
// CSRFHeader is OFF by default (Enabled == false). Forging an anti-CSRF token is
// an active access-control probe, mirroring the off-by-default gating of XXE,
// MassAssign, ForbiddenBypass, WSHijack, and JWTAuth.
type CSRFHeader struct {
	Enabled bool
}

func (CSRFHeader) Name() string { return "csrf-header" }

// csrfForgedToken is the constant attacker-chosen value used by the
// forged-double-submit and inject-missing-header techniques. A fixed value
// keeps generation deterministic; the value is recognisably attacker-supplied.
const csrfForgedToken = "possession-forged-csrf"

// csrfInjectHeader is the canonical header name used when injecting a CSRF
// header where none was present. X-CSRF-Token is the most widely-recognised
// anti-CSRF header name across frameworks.
const csrfInjectHeader = "X-CSRF-Token"

func (m CSRFHeader) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !m.Enabled || base == nil {
		return nil
	}

	hdrNames := findCSRFHeaders(base)             // canonical CSRF-ish header names present
	cookieName, cookieVal := findCSRFCookie(base) // first CSRF-ish cookie, "" if none

	var out []model.Variant

	// ── forged-double-submit ─────────────────────────────────────────────
	// Requires BOTH a CSRF header and a CSRF cookie. Overwrite both with one
	// identical forged value — a naive header==cookie check still passes.
	if len(hdrNames) > 0 && cookieName != "" {
		req := CloneRequest(base)
		for _, h := range hdrNames {
			req.Headers.Set(h, csrfForgedToken)
		}
		setCookieValue(req, cookieName, csrfForgedToken)
		out = append(out, model.Variant{
			Base:     req,
			Identity: nil, // caller credentials unchanged
			Mutation: model.Mutation{
				Type:        "csrf-header",
				Description: "forge identical CSRF token in header and cookie (double-submit bypass)",
				Detail: map[string]string{
					"technique": "forged-double-submit",
					"header":    strings.Join(hdrNames, ","),
					"cookie":    cookieName,
					"value":     csrfForgedToken,
				},
				Class: "authz-bypass",
			},
		})
	}

	// ── reflect-cookie-to-header ─────────────────────────────────────────
	// Requires a CSRF cookie. Set the CSRF header to the cookie's own value —
	// the double-submit reflection an attacker who can plant the cookie abuses.
	if cookieName != "" && cookieVal != "" {
		req := CloneRequest(base)
		// Target the existing CSRF header if present, else the canonical name.
		target := csrfInjectHeader
		if len(hdrNames) > 0 {
			target = hdrNames[0]
		}
		req.Headers.Set(target, cookieVal)
		out = append(out, model.Variant{
			Base:     req,
			Identity: nil,
			Mutation: model.Mutation{
				Type:        "csrf-header",
				Description: "reflect CSRF cookie value into CSRF header (double-submit reflection)",
				Detail: map[string]string{
					"technique": "reflect-cookie-to-header",
					"header":    target,
					"cookie":    cookieName,
				},
				Class: "authz-bypass",
			},
		})
	}

	// ── inject-missing-header ────────────────────────────────────────────
	// Requires NO CSRF header. Inject a plausible header with a forged value to
	// test presence-only enforcement.
	if len(hdrNames) == 0 {
		req := CloneRequest(base)
		req.Headers.Set(csrfInjectHeader, csrfForgedToken)
		out = append(out, model.Variant{
			Base:     req,
			Identity: nil,
			Mutation: model.Mutation{
				Type:        "csrf-header",
				Description: "inject a forged CSRF header where none was present (presence-only-check bypass)",
				Detail: map[string]string{
					"technique": "inject-missing-header",
					"header":    csrfInjectHeader,
					"value":     csrfForgedToken,
				},
				Class: "authz-bypass",
			},
		})
	}

	// Deterministic order: sort by technique name. The conditions above are
	// mutually shaped so the same input always yields the same set; sorting
	// makes the *order* canonical regardless of emission order above.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Mutation.Detail["technique"] < out[j].Mutation.Detail["technique"]
	})

	return out
}

// findCSRFCookie returns the name and value of the first CSRF-ish cookie on the
// request (lexicographically smallest name for determinism), or ("", "") if
// none. A cookie is CSRF-ish if its name contains "csrf" or "xsrf"
// (case-insensitive) — matching findCSRFHeaders' header heuristic.
func findCSRFCookie(req *model.CapturedRequest) (string, string) {
	if req == nil {
		return "", ""
	}
	type kv struct{ name, val string }
	var found []kv
	for _, c := range req.Cookies {
		if c == nil {
			continue
		}
		ln := strings.ToLower(c.Name)
		if strings.Contains(ln, "csrf") || strings.Contains(ln, "xsrf") {
			found = append(found, kv{c.Name, c.Value})
		}
	}
	if len(found) == 0 {
		return "", ""
	}
	sort.Slice(found, func(i, j int) bool { return found[i].name < found[j].name })
	return found[0].name, found[0].val
}

// setCookieValue sets the value of the named cookie on req (matched exactly).
// No-op if the cookie is absent.
func setCookieValue(req *model.CapturedRequest, name, value string) {
	for i, c := range req.Cookies {
		if c == nil {
			continue
		}
		if c.Name == name {
			cc := *c
			cc.Value = value
			req.Cookies[i] = &cc
			return
		}
	}
}
