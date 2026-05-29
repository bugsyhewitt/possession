package mutate

import (
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// OriginSpoof is the Origin/Referer-header access-control bypass mutator. It
// targets the very common state-change defense where a backend (or a fronting
// gateway) decides whether to honour a request by validating the Origin or
// Referer header against an allowlist of trusted sites — the standard
// "verify the Origin header" CSRF / SameSite-defense pattern OWASP and every
// CSRF cheat-sheet recommend, and which is just as commonly implemented wrong.
//
// Where CSRFHeader attacks *the anti-CSRF token*, HostHeader attacks *which
// host the access-control layer believes the request targets*, and
// HeaderInjection attacks *which trusted-proxy assertion the backend believes
// about the caller*, OriginSpoof attacks *which originating site the
// access-control layer believes the request came from* — the canonical
// "Origin/Referer validation bypass" family. The two are deliberately
// disjoint: CSRFHeader never touches Origin/Referer, and OriginSpoof never
// touches the anti-CSRF token.
//
// Every variant keeps the caller's OWN credentials (Identity == nil): this is
// NOT an identity swap. The caller stays themselves on the wire; they merely
// claim the request originated from a site the server should refuse. The bug
// being tested is "the same caller's state-change is honoured when it claims to
// come from an untrusted (or cleverly-shaped) origin a correct check would
// reject."
//
// Three technique families, each emitted as a separate variant for attribution:
//
//   - null-origin: set Origin: null (and Referer dropped). A sandboxed iframe,
//     a data:/javascript: document, a redirect-laundered request, or a
//     meta-referrer policy all produce the literal origin "null". Allowlists
//     that special-case or fail-open on "null" (a very common mistake) accept
//     it; a correct check refuses an unrecognised origin. One variant.
//
//   - cross-origin: set Origin and Referer to a wholly-foreign attacker site
//     (https://attacker.example). Tests the baseline failure — an app that does
//     not validate Origin/Referer at all (or only checks presence) honours a
//     blatantly cross-site request. One variant.
//
//   - suffix-confusion: set Origin and Referer to attacker-controlled hosts
//     crafted to defeat naive allowlist matching of the request's own host:
//     a domain that *contains* it as a substring (https://<host>.attacker.example),
//     a domain that *ends with* it after an attacker-controlled label
//     (https://attacker-<host-with-dots-collapsed>… via a leading-label trick),
//     and a userinfo-confusion form (https://<host>@attacker.example) that a
//     parser splitting on the wrong delimiter mis-reads as the trusted host.
//     These are the three matcher mistakes — naive Contains, naive HasSuffix /
//     HasPrefix, and authority-userinfo confusion — every Origin-validation
//     write-up demonstrates. One variant per crafted host.
//
// Detection rides the existing comparative ladder unchanged. The caller's own
// baseline against the request with its real Origin/Referer is the reference; a
// variant that returns an owner-shaped 2xx (or otherwise differs from a
// denied/empty baseline) under a spoofed origin is the bypass. Findings are
// class "authz-bypass" (ASVS V8.3.x, severity high) — the same class
// CSRFHeader, HostHeader, MethodOverride, and HeaderInjection use.
//
// Note on scope: the injected values are well-formed origin/URL tokens. This is
// NOT CRLF / response-splitting (net/http rejects raw CR/LF in header values),
// and it does not forge the anti-CSRF token (that is CSRFHeader's job). The
// technique here is lying about *where the request came from*.
//
// Generate is pure and deterministic: technique names and crafted hosts are
// derived from fixed templates and emitted in a fixed (sorted-by-technique)
// order, so identical inputs yield an identical variant slice (--dry-run and the
// offline corpus cover it).
//
// OriginSpoof is OFF by default (Enabled == false). The spoofed-origin variants
// actively assert an untrusted/forged origin against the access-control layer
// and re-issue the (often state-changing) request, so it only fires when the
// operator explicitly opts in via --origin-spoof. This mirrors the
// off-by-default gating of XXE, MassAssign, EnumerateID, ForbiddenBypass,
// WSHijack, CSRFHeader, MethodOverride, HostHeader, CookieTamper,
// HeaderInjection, and ParamPollution.
type OriginSpoof struct {
	Enabled bool
}

func (OriginSpoof) Name() string { return "origin-spoof" }

// attackerOrigin is the wholly-foreign attacker site used by the cross-origin
// technique and as the attacker-controlled domain in the suffix-confusion
// crafted hosts. .example is an IANA-reserved TLD, so the value can never
// resolve to a real target — it is recognisably attacker-supplied.
const attackerOrigin = "https://attacker.example"

// attackerDomain is the bare attacker domain (no scheme) used to build the
// suffix-confusion crafted hosts.
const attackerDomain = "attacker.example"

// nullOrigin is the literal origin a sandboxed/laundered request carries; the
// value allowlists most commonly mishandle.
const nullOrigin = "null"

func (os OriginSpoof) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !os.Enabled || base == nil || base.URL == nil {
		return nil
	}

	origHost := base.URL.Host
	if origHost == "" {
		return nil
	}

	var out []model.Variant

	// ── null-origin ──────────────────────────────────────────────────────
	// Claim the request came from a null origin (sandboxed iframe / redirect
	// laundering). Drop Referer so the two signals agree on "no real origin".
	{
		req := CloneRequest(base)
		if req.Headers != nil {
			req.Headers.Set("Origin", nullOrigin)
			req.Headers.Del("Referer")
			out = append(out, model.Variant{
				Base:     req,
				Identity: nil, // credentials unchanged — same caller, spoofed origin
				Mutation: model.Mutation{
					Type:        "origin-spoof",
					Description: "set Origin: null to bypass an allowlist that fails-open on the null origin",
					Detail: map[string]string{
						"origin-spoof":  "null-origin",
						"technique":     "null-origin",
						"origin_header": nullOrigin,
						"origin_from":   origHost,
					},
					Class: "authz-bypass",
				},
			})
		}
	}

	// ── cross-origin ─────────────────────────────────────────────────────
	// A blatantly foreign origin. Tests the baseline failure: no Origin check
	// (or presence-only). Set both Origin and Referer so an app validating
	// either is exercised.
	{
		req := CloneRequest(base)
		if req.Headers != nil {
			req.Headers.Set("Origin", attackerOrigin)
			req.Headers.Set("Referer", attackerOrigin+"/")
			out = append(out, model.Variant{
				Base:     req,
				Identity: nil,
				Mutation: model.Mutation{
					Type:        "origin-spoof",
					Description: "set Origin/Referer to a foreign attacker site to test for a missing origin check",
					Detail: map[string]string{
						"origin-spoof":   "cross-origin",
						"technique":      "cross-origin",
						"origin_header":  attackerOrigin,
						"referer_header": attackerOrigin + "/",
						"origin_from":    origHost,
					},
					Class: "authz-bypass",
				},
			})
		}
	}

	// ── suffix-confusion ─────────────────────────────────────────────────
	// Attacker-controlled hosts crafted to slip past a naive allowlist that
	// matches the request's own host with Contains / HasPrefix / HasSuffix /
	// authority-userinfo confusion. One variant per crafted host, each named so
	// a confirmed bypass attributes the precise matcher mistake.
	for _, sc := range suffixConfusionHosts(origHost) {
		req := CloneRequest(base)
		if req.Headers == nil {
			continue
		}
		origin := "https://" + sc.host
		req.Headers.Set("Origin", origin)
		req.Headers.Set("Referer", origin+"/")
		out = append(out, model.Variant{
			Base:     req,
			Identity: nil,
			Mutation: model.Mutation{
				Type:        "origin-spoof",
				Description: "set Origin/Referer to " + origin + " to defeat a naive " + sc.name + " allowlist match",
				Detail: map[string]string{
					"origin-spoof":   "suffix-confusion:" + sc.name,
					"technique":      "suffix-confusion:" + sc.name,
					"origin_header":  origin,
					"referer_header": origin + "/",
					"origin_from":    origHost,
					"matcher":        sc.name,
				},
				Class: "authz-bypass",
			},
		})
	}

	return out
}

// confusionHost is one crafted attacker host paired with the matcher mistake it
// targets (used as the technique suffix).
type confusionHost struct {
	// name is the matcher mistake this host defeats (sorted on).
	name string
	// host is the attacker-controlled host placed in Origin/Referer.
	host string
}

// suffixConfusionHosts returns the crafted attacker hosts for the request's own
// host, in deterministic (sorted-by-name) order. Each defeats a specific naive
// allowlist matcher:
//
//   - prefix-match: "<host>.attacker.example" — defeats a check that the origin
//     host HasPrefix the trusted host (and a naive Contains).
//   - suffix-match: "attacker<host>" with dots collapsed to a label-safe form,
//     i.e. "attacker-example-com.attacker.example" for host "example.com" —
//     defeats a check that the origin host HasSuffix the trusted host by
//     embedding the trusted labels; kept DNS-label-safe so the value is a
//     well-formed host.
//   - userinfo-confusion: "<host>@attacker.example" — a userinfo authority that
//     a parser splitting on the wrong delimiter mis-reads as the trusted host
//     while the real authority is attacker.example.
func suffixConfusionHosts(origHost string) []confusionHost {
	// Strip any port from the host for the crafted labels; the host portion is
	// what an allowlist matches on.
	h := origHost
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	// A DNS-label-safe rendering of the trusted host for the suffix-match form
	// (dots are not legal inside a single label).
	labelSafe := strings.ReplaceAll(h, ".", "-")

	hosts := []confusionHost{
		{name: "prefix-match", host: h + "." + attackerDomain},
		{name: "suffix-match", host: "attacker-" + labelSafe + "." + attackerDomain},
		{name: "userinfo-confusion", host: h + "@" + attackerDomain},
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].name < hosts[j].name })
	return hosts
}

// originSpoofTechnique is a small helper used in tests to assert a mutation's
// technique without depending on the Detail map layout from outside the package.
// Kept here so the technique-key contract lives next to its producer.
func originSpoofTechnique(m model.Mutation) string {
	if m.Detail == nil {
		return ""
	}
	return strings.TrimSpace(m.Detail["technique"])
}
