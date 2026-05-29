package mutate

import (
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// HostHeader is the Host-header / host-override access-control bypass mutator.
// Where ForbiddenBypass attacks *how the path is matched*, MethodOverride
// attacks *which verb is evaluated*, and CSRFHeader attacks *the anti-CSRF
// token*, HostHeader attacks *which host the access-control layer believes the
// request targets* — the canonical "host-header injection" family every
// 403/401-bypass and SSRF/cache-poisoning cheat-sheet lists.
//
// Many deployments make routing and authorization decisions from the Host (or a
// forwarded-host header a fronting proxy trusts): virtual-host routing maps a
// host to an internal app, an API gateway gates "admin.internal" behind a
// network ACL while serving the public host, a reverse proxy forwards the
// client-supplied Host straight to the backend, or an app builds absolute URLs
// (password-reset links, cache keys, redirects) from the Host. Spoofing the
// host can route a request to an otherwise-unreachable internal virtual host,
// reach an admin vhost from the public edge, or poison host-derived behaviour —
// all while keeping the caller's own credentials.
//
// Every variant keeps the caller's own credentials (Identity == nil): this is
// emphatically NOT an identity swap. The bug being tested is "the same caller
// reaches a host-gated resource by lying about the host."
//
// Two technique families, each emitted as a separate variant for attribution:
//
//   - host-override: replace the request's own Host with an attacker-named host
//     (an internal vhost, the loopback, or the localhost name). net/http sends
//     the Host from the request's Host field, NOT a "Host" entry in the header
//     map — so the variant carries the spoofed value as a "Host" header and the
//     replay engine promotes it onto the wire Host (see buildHTTPRequest). A
//     request that succeeds against a spoofed internal host where the public
//     host did not is a host-routing authorization bypass.
//
//   - forwarded-host: keep the real Host on the request line but inject a
//     forwarded-host override header (X-Forwarded-Host, X-Host,
//     X-Forwarded-Server, X-HTTP-Host-Override, Forwarded). A reverse proxy /
//     framework that trusts the forwarded host for routing, link generation, or
//     cache keys is fooled into treating the request as targeting the spoofed
//     host. These complement ForbiddenBypass's rewrite headers (X-Original-URL,
//     X-Rewrite-URL, X-Forwarded-For), which spoof the *URL* and *client IP* but
//     never the *host*.
//
// Detection rides the existing comparative ladder unchanged. The caller's own
// baseline against the unmutated host is the reference; a variant that returns
// an owner-shaped 2xx (or otherwise differs from a denied/empty baseline) under
// a spoofed host is the bypass. Findings are class "authz-bypass" (ASVS V8.3.x,
// severity high) — the same class ForbiddenBypass and MethodOverride use.
//
// Generate is pure and deterministic: technique values are constants and emitted
// in a fixed (sorted-by-name) order, so identical inputs yield an identical
// variant slice (--dry-run and the offline corpus cover it).
//
// HostHeader is OFF by default (Enabled == false). The spoofed-host variants
// actively probe the routing/access-control layer and can reach internal-only
// virtual hosts on a misconfigured proxy, so it only fires when the operator
// explicitly opts in via --host-header. This mirrors the off-by-default gating
// of XXE, MassAssign, EnumerateID, ForbiddenBypass, WSHijack, CSRFHeader, and
// MethodOverride.
type HostHeader struct {
	Enabled bool
}

func (HostHeader) Name() string { return "host-header" }

// spoofHost is one attacker-controlled host value to substitute for the
// request's own host. Kept small and high-signal: the values most consistently
// effective at reaching an internal/loopback virtual host behind a fronting
// proxy. Sorted by name so generation order is deterministic; the order test
// covers this.
type spoofHost struct {
	// name is the technique identifier (sorted on).
	name string
	// value is the host string written onto the spoofed Host / forwarded-host.
	value string
}

var spoofHosts = []spoofHost{
	// 127.0.0.1 — the loopback address; a proxy that routes by host may map it
	// to an internal admin/management vhost bound to localhost.
	{name: "loopback-ip", value: "127.0.0.1"},
	// localhost — the loopback name; same intent as loopback-ip but matches
	// name-based (rather than IP-based) internal vhost rules.
	{name: "localhost", value: "localhost"},
	// internal — a conventional internal-only virtual host an edge gateway is
	// expected to refuse from the public side but the backend still serves.
	{name: "internal-vhost", value: "internal"},
}

// forwardedHostHeaders is the built-in forwarded-host override header set. Each
// names a header a reverse proxy or application framework may trust as the
// effective host while the request line still carries the real host. Sorted by
// name for deterministic generation order; the order test covers this.
//
// Deliberately disjoint from ForbiddenBypass.rewriteHeaders (X-Forwarded-For,
// X-Original-URL, X-Rewrite-URL): those spoof the client IP and the URL, never
// the host. "Forwarded" carries an RFC 7239 host= directive.
var forwardedHostHeaders = []string{
	"Forwarded",
	"X-Forwarded-Host",
	"X-Forwarded-Server",
	"X-HTTP-Host-Override",
	"X-Host",
}

func (hh HostHeader) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !hh.Enabled || base == nil || base.URL == nil {
		return nil
	}

	origHost := base.URL.Host
	if origHost == "" {
		return nil
	}

	// Deterministic copies sorted by name.
	hosts := append([]spoofHost(nil), spoofHosts...)
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].name < hosts[j].name })
	fwdHeaders := append([]string(nil), forwardedHostHeaders...)
	sort.Strings(fwdHeaders)

	var out []model.Variant

	// ── host-override variants ───────────────────────────────────────────
	// Replace the request's own Host with a spoofed value. The value is set as
	// a "Host" header; the replay engine promotes a "Host" header onto the wire
	// Host field (net/http otherwise ignores a Host header). A no-op (spoof ==
	// original host) is skipped.
	for _, sh := range hosts {
		if sh.value == origHost {
			continue
		}
		req := CloneRequest(base)
		if req.Headers == nil {
			continue
		}
		req.Headers.Set("Host", sh.value)
		out = append(out, model.Variant{
			Base:     req,
			Identity: nil, // credentials unchanged — same caller, spoofed host
			Mutation: model.Mutation{
				Type:        "host-header",
				Description: "override Host: " + sh.value + " to reach a host-gated resource",
				Detail: map[string]string{
					"host-header": "host-override:" + sh.name,
					"technique":   "host-override:" + sh.name,
					"host_from":   origHost,
					"host_to":     sh.value,
				},
				Class: "authz-bypass",
			},
		})
	}

	// ── forwarded-host variants ──────────────────────────────────────────
	// Keep the real Host on the request line; inject a forwarded-host override
	// header naming a spoofed host. One variant per (header, spoof-host) pair
	// so a confirmed bypass is attributable to the precise header+host that
	// worked. The "Forwarded" header uses the RFC 7239 host= form.
	for _, hName := range fwdHeaders {
		for _, sh := range hosts {
			req := CloneRequest(base)
			if req.Headers == nil {
				continue
			}
			val := sh.value
			if hName == "Forwarded" {
				val = "host=" + sh.value
			}
			req.Headers.Set(hName, val)
			out = append(out, model.Variant{
				Base:     req,
				Identity: nil, // credentials unchanged — same caller, spoofed forwarded host
				Mutation: model.Mutation{
					Type:        "host-header",
					Description: "inject " + hName + ": " + val + " to spoof the trusted host",
					Detail: map[string]string{
						"host-header": "forwarded-host:" + hName + ":" + sh.name,
						"technique":   "forwarded-host:" + hName,
						"header":      hName,
						"value":       val,
						"host_from":   origHost,
						"host_to":     sh.value,
					},
					Class: "authz-bypass",
				},
			})
		}
	}

	return out
}

// hasHostHeaderTechnique is a small helper used in tests to assert a mutation's
// technique without depending on the Detail map layout from outside the package.
// Kept here so the technique-key contract lives next to its producer.
func hostHeaderTechnique(m model.Mutation) string {
	if m.Detail == nil {
		return ""
	}
	return strings.TrimSpace(m.Detail["technique"])
}
