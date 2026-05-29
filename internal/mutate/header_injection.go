package mutate

import (
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// HeaderInjection is the trusted-header access-control bypass mutator. It targets
// the case where a backend trusts request headers it assumes a fronting proxy
// (load balancer, API gateway, WAF, auth proxy) populated, and makes a routing or
// authorization decision from them — but the header is in fact reachable from the
// untrusted client edge. A caller who sets the header directly is treated as
// though the trusted proxy vouched for them.
//
// Where ForbiddenBypass attacks *how the path is matched*, MethodOverride attacks
// *which verb is evaluated*, HostHeader attacks *which host the access-control
// layer believes the request targets*, and CookieTamper attacks *which
// authorization state the app trusts inside a cookie*, HeaderInjection attacks
// *which trusted-proxy assertion the backend believes about the caller* — the
// canonical "trusted header" / "internal-header spoofing" family every
// 403/401-bypass cheat-sheet lists.
//
// Two technique families, each emitted as a separate variant for attribution and
// kept deliberately disjoint from the header sets ForbiddenBypass and HostHeader
// already inject (X-Forwarded-For, X-Original-URL, X-Rewrite-URL, Forwarded,
// X-Forwarded-Host, X-Forwarded-Server, X-HTTP-Host-Override, X-Host):
//
//   - client-ip-spoof: a trusted-client-IP header (X-Real-IP, X-Client-IP,
//     X-Originating-IP, X-Remote-IP, X-Remote-Addr) set to the loopback address.
//     Apps that grant internal/admin access by trusting a proxy-supplied client IP
//     (an "allow 127.0.0.1" / "internal network" rule) are fooled into treating
//     the caller as originating from inside the trust boundary. This complements
//     ForbiddenBypass's single X-Forwarded-For:127.0.0.1 by covering the other
//     trusted-client-IP headers proxies and frameworks read, none of which it sets.
//
//   - trusted-identity: a proxy-set identity-assertion header (X-Authenticated-User,
//     X-Remote-User, X-Forwarded-User, X-User, X-WEBAUTH-USER) naming a privileged
//     principal. Auth proxies (mod_auth, oauth2-proxy, SSO gateways) authenticate
//     the caller and forward the established identity to the backend in such a
//     header; a backend that trusts it without re-verifying lets a client who sets
//     the header directly assert an arbitrary identity.
//
// Every variant keeps the caller's OWN credentials (Identity == nil): this is NOT
// an identity swap. The caller stays themselves on the wire; they merely add a
// header a misconfigured backend trusts. The bug being tested is "the same caller
// gains access by asserting a trusted-proxy header the edge should have stripped."
//
// Detection rides the existing comparative ladder unchanged. The caller's own
// baseline against the request without the injected header is the reference; a
// variant that returns an owner-shaped 2xx (or otherwise differs from a
// denied/empty baseline) under the injected header is the bypass. Findings are
// class "authz-bypass" (ASVS V8.3.x, severity high) — the same class
// ForbiddenBypass, MethodOverride, HostHeader, and CookieTamper use.
//
// Note on scope: this is emphatically NOT CRLF / HTTP response-splitting. The
// injected values are well-formed header tokens (an IP, a username); net/http (and
// the replay engine that builds on it) rejects raw CR/LF in header values, so a
// response-splitting payload would never reach the wire and is intentionally out
// of scope. The technique here is trusting a *legitimately-shaped* header the edge
// failed to strip.
//
// Generate is pure and deterministic: header names are constants emitted in a
// fixed (sorted-by-name) order, so identical inputs yield an identical variant
// slice (--dry-run and the offline corpus cover it).
//
// HeaderInjection is OFF by default (Enabled == false). The spoofed-trust variants
// actively assert internal-origin / privileged identity against the access-control
// layer, so it only fires when the operator explicitly opts in via
// --header-injection. This mirrors the off-by-default gating of XXE, MassAssign,
// EnumerateID, ForbiddenBypass, WSHijack, CSRFHeader, MethodOverride, HostHeader,
// and CookieTamper.
type HeaderInjection struct {
	Enabled bool
}

func (HeaderInjection) Name() string { return "header-injection" }

// loopbackIP is the trusted-internal client address asserted by every
// client-ip-spoof variant: the loopback the "internal network" / "allow
// localhost" rules backends most often special-case.
const loopbackIP = "127.0.0.1"

// privilegedUser is the principal asserted by every trusted-identity variant. A
// conventional administrative account name an auth-proxy-trusting backend would
// grant elevated access to.
const privilegedUser = "admin"

// clientIPHeaders is the built-in trusted-client-IP header set. Each names a
// header a reverse proxy or framework may read as the authoritative client
// address for an IP-based access rule. Deliberately disjoint from
// ForbiddenBypass.rewriteHeaders (which sets X-Forwarded-For:127.0.0.1 only).
// Sorted by name for deterministic generation order; the order test covers this.
var clientIPHeaders = []string{
	"X-Client-IP",
	"X-Originating-IP",
	"X-Real-IP",
	"X-Remote-Addr",
	"X-Remote-IP",
}

// identityHeaders is the built-in trusted-identity header set. Each names a header
// an authenticating proxy may forward to the backend carrying the established
// principal. Sorted by name for deterministic generation order; the order test
// covers this.
var identityHeaders = []string{
	"X-Authenticated-User",
	"X-Forwarded-User",
	"X-Remote-User",
	"X-User",
	"X-WEBAUTH-USER",
}

func (hi HeaderInjection) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !hi.Enabled || base == nil || base.URL == nil {
		return nil
	}

	// Deterministic copies sorted by name.
	ipHeaders := append([]string(nil), clientIPHeaders...)
	sort.Strings(ipHeaders)
	idHeaders := append([]string(nil), identityHeaders...)
	sort.Strings(idHeaders)

	var out []model.Variant

	// ── client-ip-spoof variants ─────────────────────────────────────────
	// Inject a trusted-client-IP header set to the loopback so an IP-gated
	// internal/admin rule treats the caller as originating inside the trust
	// boundary. One variant per header for attribution.
	for _, h := range ipHeaders {
		req := CloneRequest(base)
		if req.Headers == nil {
			continue
		}
		req.Headers.Set(h, loopbackIP)
		out = append(out, model.Variant{
			Base:     req,
			Identity: nil, // credentials unchanged — same caller, spoofed trusted IP
			Mutation: model.Mutation{
				Type:        "header-injection",
				Description: "inject " + h + ": " + loopbackIP + " to spoof an internal-origin client",
				Detail: map[string]string{
					"header-injection": "client-ip-spoof:" + h,
					"technique":        "client-ip-spoof:" + h,
					"family":           "client-ip-spoof",
					"header":           h,
					"value":            loopbackIP,
				},
				Class: "authz-bypass",
			},
		})
	}

	// ── trusted-identity variants ────────────────────────────────────────
	// Inject a proxy-set identity-assertion header naming a privileged principal
	// so a backend that trusts the forwarded identity grants elevated access.
	// One variant per header for attribution.
	for _, h := range idHeaders {
		req := CloneRequest(base)
		if req.Headers == nil {
			continue
		}
		req.Headers.Set(h, privilegedUser)
		out = append(out, model.Variant{
			Base:     req,
			Identity: nil, // credentials unchanged — same caller, asserted trusted identity
			Mutation: model.Mutation{
				Type:        "header-injection",
				Description: "inject " + h + ": " + privilegedUser + " to assert a trusted-proxy identity",
				Detail: map[string]string{
					"header-injection": "trusted-identity:" + h,
					"technique":        "trusted-identity:" + h,
					"family":           "trusted-identity",
					"header":           h,
					"value":            privilegedUser,
				},
				Class: "authz-bypass",
			},
		})
	}

	return out
}

// headerInjectionTechnique is a small helper used in tests to assert a mutation's
// technique without depending on the Detail map layout from outside the package.
func headerInjectionTechnique(m model.Mutation) string {
	if m.Detail == nil {
		return ""
	}
	return strings.TrimSpace(m.Detail["technique"])
}
