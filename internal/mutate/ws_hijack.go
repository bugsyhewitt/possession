package mutate

import "github.com/bugsyhewitt/possession/internal/model"

// WSHijack is the WebSocket upgrade authorization probe mutator (POST_V01
// follow-on: WebSocket upgrade hijack). It targets endpoints whose captured
// request is an HTTP→WebSocket Upgrade handshake and tests whether the server
// completes that handshake (HTTP 101 Switching Protocols) when the caller's
// credentials have been removed or replaced by another identity's.
//
// The threat it surfaces is real and routinely missed: many applications
// enforce authorization on their REST routes but mount the WebSocket endpoint
// behind a handshake that skips the authz check (the upgrade is treated as a
// transport concern, not a resource access). A server that returns 101 to an
// unauthenticated or cross-identity upgrade has a broken-authz WebSocket — any
// caller can open a live channel they should not be able to.
//
// Where SwapIdentity attacks *who* the caller is on a normal request,
// SwapObject attacks *which object* is referenced, and StripAuth attacks
// whether auth is required at all, WSHijack applies those same identity moves
// to the *upgrade handshake itself* — the one request whose access check
// applications most often forget — and judges them on the decisive 101 signal
// rather than on a body differential (a WebSocket handshake has no meaningful
// response body to compare).
//
// It emits, in deterministic order:
//   - one "strip-auth" variant with all credentials removed (anonymous
//     upgrade), and
//   - one "swap-identity" variant per matrix identity (in canonical rank,name
//     order) carrying that identity's credentials.
//
// Every variant preserves the WebSocket upgrade headers (Upgrade,
// Connection, Sec-WebSocket-Key, Sec-WebSocket-Version) so the server still
// sees a valid handshake; only the credentials change.
//
// Detection (handled in internal/detect): each variant carries
// Mutation.Detail["ws-hijack"] == the technique name. The evaluator gates a
// decisive "handshake completed" verdict on the response status being 101
// Switching Protocols, mirroring the in-band XXE canary / GraphQL
// introspection branches — a WebSocket handshake has no owner/actor baseline
// body to compare against, and a 101 to a stripped/foreign identity is
// false-positive-free proof the upgrade bypassed authorization. Because 101
// would otherwise be classified as a transport error (status < 200), this
// branch runs ahead of the status-error short-circuit in the ladder.
//
// WebSocket detection is by request shape only: the captured request must
// carry an "Upgrade: websocket" header (case-insensitive) together with a
// Connection header that mentions "upgrade", OR carry a Sec-WebSocket-Key
// header. Non-WebSocket requests produce no variants.
//
// Like every mutator, Generate is pure and deterministic: techniques are
// emitted in a fixed order (strip-auth first, then identities in canonical
// (rank, name) order), so identical inputs yield an identical variant slice.
//
// WSHijack is OFF by default (Enabled == false). Opening (or attempting to
// open) a privileged live channel under a foreign or stripped identity is an
// active access-control probe, so it only fires when the operator explicitly
// opts in via --ws-hijack. This mirrors the off-by-default gating of
// MassAssign, EnumerateID, JWTAuth, XXE, and GraphQL.
type WSHijack struct {
	Enabled bool
}

func (WSHijack) Name() string { return "ws-hijack" }

func (w WSHijack) Generate(base *model.CapturedRequest, m *model.RoleMatrix) []model.Variant {
	if !w.Enabled || base == nil {
		return nil
	}
	if !isWebSocketUpgrade(base) {
		return nil
	}

	// Resolve the captured request's owner tenant so cross-tenant upgrades are
	// flagged with the higher-severity cross-tenant class, exactly as
	// SwapIdentity does for normal requests.
	ownerTenant := capturedOwnerTenant(base, m)

	var out []model.Variant

	// Technique 1: anonymous upgrade — strip all credentials but keep the
	// upgrade headers. A 101 here means the WebSocket accepts unauthenticated
	// clients.
	{
		req := CloneRequest(base)
		applyIdentity(req, nil) // strip all auth, keep upgrade headers
		out = append(out, model.Variant{
			Base:     req,
			Identity: nil,
			Mutation: model.Mutation{
				Type:        "ws-hijack",
				Description: "attempt WebSocket upgrade with all credentials stripped (anonymous handshake)",
				Detail: map[string]string{
					"ws-hijack": "strip-auth",
					"technique": "strip-auth",
				},
				Class: "authn-bypass",
			},
		})
	}

	// Technique 2..N: cross-identity upgrade — replace the caller's
	// credentials with each matrix identity's. A 101 to an identity that
	// should not reach this channel is a WebSocket authz bypass.
	if m != nil {
		ids := sortIdentities(m.Identities)
		for i := range ids {
			ident := ids[i]
			req := CloneRequest(base)
			applyIdentity(req, &ident)

			class := "idor"
			detail := map[string]string{
				"ws-hijack":  "swap-identity",
				"technique":  "swap-identity",
				"swapped_to": ident.Name,
			}
			if ownerTenant != "" && ident.Tenant != "" && ident.Tenant != ownerTenant {
				class = "idor-cross-tenant"
				detail["actor_tenant"] = ident.Tenant
				detail["owner_tenant"] = ownerTenant
			}

			out = append(out, model.Variant{
				Base:     req,
				Identity: &ids[i],
				Mutation: model.Mutation{
					Type:        "ws-hijack",
					Description: "attempt WebSocket upgrade as identity " + ident.Name,
					Detail:      detail,
					Class:       class,
				},
			})
		}
	}

	return out
}

// isWebSocketUpgrade reports whether req is an HTTP→WebSocket upgrade
// handshake. Recognition is by the standard handshake headers (RFC 6455 §4.1):
// an "Upgrade: websocket" header paired with a Connection header that mentions
// "upgrade", or the presence of a Sec-WebSocket-Key header (which a client only
// sends on a genuine handshake). Matching is case-insensitive; header *values*
// are matched with a substring check so multi-token Connection values
// ("keep-alive, Upgrade") are recognized. A nil Headers map is not a WebSocket
// request.
func isWebSocketUpgrade(req *model.CapturedRequest) bool {
	if req == nil || req.Headers == nil {
		return false
	}
	if hasHeaderToken(req, "Upgrade", "websocket") &&
		hasHeaderToken(req, "Connection", "upgrade") {
		return true
	}
	// Sec-WebSocket-Key alone is a strong, client-only handshake signal.
	if req.Headers.Get("Sec-WebSocket-Key") != "" {
		return true
	}
	return false
}

// hasHeaderToken reports whether req's named header contains substr
// (case-insensitive). http.Header.Get is already canonical-case aware.
func hasHeaderToken(req *model.CapturedRequest, name, substr string) bool {
	v := req.Headers.Get(name)
	if v == "" {
		return false
	}
	return containsFold(v, substr)
}

// containsFold reports whether s contains substr, case-insensitively, without
// allocating a lowered copy of the whole string for the common short-header
// case. substr is assumed already lowercase by callers.
func containsFold(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			c := s[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
