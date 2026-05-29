package mutate

import (
	"encoding/base64"
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// CookieTamper is the cookie-value privilege-tampering mutator. Where DropCookie
// *removes* an auth cookie to map which cookie enforces access, and StripToken
// strips the bearer/CSRF side of the credential pair, CookieTamper keeps every
// cookie present and instead *edits the value* of an auth cookie to flip a
// client-controllable authorization claim from its unprivileged form to a
// privileged one.
//
// The bug being tested is the classic broken-access-control / privilege-escalation
// pattern where the server trusts authorization state it stored in a cookie value
// without re-deriving or signing it: a `role=user` cookie the app reads back to
// decide privilege, an `admin=0` flag, an `is_admin=false` claim, or a base64-wrapped
// (unsigned) blob carrying the same. If a request succeeds with elevated privilege
// after a one-claim flip, the cookie value is an unguarded authorization input.
//
// Every variant keeps the caller's own credentials (Identity == nil): this is NOT
// an identity swap. The caller stays themselves; only one privilege claim inside
// one of their own cookies is flipped. (JWT-shaped cookie values are handled by the
// JWT mutator family and are skipped here — a value with two '.' separators that
// base64-decodes to JSON is left untouched so the two mutators do not collide.)
//
// Two technique families, each emitted as a separate variant for attribution:
//
//   - value-claim-flip: the cookie value is a delimited `key=value`-ish payload
//     (`role=user;tier=free`, `admin=0`, `is_admin=false`). The matching claim is
//     rewritten in place to its privileged form, every other byte preserved.
//
//   - base64-claim-flip: the cookie value base64-decodes (std or URL alphabet) to a
//     printable string that itself carries such a claim. The decoded form is flipped
//     and re-encoded with the same alphabet/padding it arrived in, so a server that
//     base64-decodes the cookie and trusts the inner claim is fooled.
//
// Detection rides the existing comparative ladder unchanged. The caller's own
// baseline against the unmutated cookie is the reference; a variant that returns an
// elevated/owner-shaped response where the baseline did not is the bypass. Findings
// are class "authz-bypass" (ASVS V8.3.x, severity high) — the same class
// ForbiddenBypass, MethodOverride, and HostHeader use.
//
// Generate is pure and deterministic: cookies are processed in name-sorted order,
// claims in a fixed (sorted-by-key) order, so identical inputs yield an identical
// variant slice (--dry-run and the offline corpus cover it).
//
// CookieTamper is OFF by default (Enabled == false). The flipped-claim variants
// actively assert elevated privilege against the access-control layer, so it only
// fires when the operator explicitly opts in via --cookie-tampering. This mirrors
// the off-by-default gating of XXE, MassAssign, EnumerateID, ForbiddenBypass,
// WSHijack, CSRFHeader, MethodOverride, and HostHeader.
type CookieTamper struct {
	Enabled bool
}

func (CookieTamper) Name() string { return "cookie-tamper" }

// privClaim is one client-controllable authorization claim CookieTamper flips from
// its unprivileged form to a privileged one. Matching is case-insensitive on the
// key; the value match is also case-insensitive. Kept small and high-signal — the
// canonical privilege flags carried in plaintext/base64 cookies across web apps — to
// bound the variant count and keep the false-positive surface low.
//
// Sorted by key so generation order is deterministic; the order test covers it.
type privClaim struct {
	// key is the claim name as it appears before the value separator (role, admin…).
	key string
	// from is the unprivileged value to look for (case-insensitive).
	from string
	// to is the privileged value to write in its place.
	to string
}

var privClaims = []privClaim{
	{key: "admin", from: "0", to: "1"},
	{key: "admin", from: "false", to: "true"},
	{key: "is_admin", from: "false", to: "true"},
	{key: "isadmin", from: "false", to: "true"},
	{key: "role", from: "user", to: "admin"},
	{key: "role", from: "guest", to: "admin"},
	{key: "verified", from: "false", to: "true"},
}

func (ct CookieTamper) Generate(base *model.CapturedRequest, _ *model.RoleMatrix) []model.Variant {
	if !ct.Enabled || base == nil || len(base.Cookies) == 0 {
		return nil
	}

	// Auth cookies in name-sorted order so generation is deterministic regardless of
	// upstream parsing order. Index of each so we can locate it in a clone.
	type authCookie struct {
		idx  int
		name string
	}
	var cookies []authCookie
	for i, c := range base.Cookies {
		if c != nil && IsAuthCookie(c.Name) {
			cookies = append(cookies, authCookie{idx: i, name: c.Name})
		}
	}
	if len(cookies) == 0 {
		return nil
	}
	sort.Slice(cookies, func(i, j int) bool { return cookies[i].name < cookies[j].name })

	claims := append([]privClaim(nil), privClaims...)
	sort.Slice(claims, func(i, j int) bool {
		if claims[i].key != claims[j].key {
			return claims[i].key < claims[j].key
		}
		return claims[i].from < claims[j].from
	})

	var out []model.Variant

	for _, ac := range cookies {
		origVal := base.Cookies[ac.idx].Value
		if origVal == "" {
			continue
		}

		// ── value-claim-flip ─────────────────────────────────────────────
		// The plaintext value carries a delimited privilege claim. Flip it in place.
		for _, pc := range claims {
			flipped, ok := flipPlainClaim(origVal, pc)
			if !ok {
				continue
			}
			out = append(out, ct.variant(base, ac.idx, ac.name, flipped,
				"value-claim-flip", pc, origVal, flipped))
		}

		// ── base64-claim-flip ────────────────────────────────────────────
		// The value base64-decodes to a printable string carrying a privilege claim.
		// JWT-shaped values (two dots, JSON segments) are skipped — that's the JWT
		// mutator's territory.
		if looksJWT(origVal) {
			continue
		}
		decoded, enc, ok := decodeB64(origVal)
		if !ok || !isPrintable(decoded) {
			continue
		}
		for _, pc := range claims {
			flippedInner, ok := flipPlainClaim(decoded, pc)
			if !ok {
				continue
			}
			reencoded := enc.EncodeToString([]byte(flippedInner))
			out = append(out, ct.variant(base, ac.idx, ac.name, reencoded,
				"base64-claim-flip", pc, origVal, reencoded))
		}
	}

	return out
}

// variant builds one CookieTamper variant: a clone of base with the cookie at idx
// rewritten to newVal, credentials otherwise untouched (Identity == nil).
func (ct CookieTamper) variant(base *model.CapturedRequest, idx int, name, newVal, family string, pc privClaim, fromVal, toVal string) model.Variant {
	req := CloneRequest(base)
	if idx < len(req.Cookies) && req.Cookies[idx] != nil {
		req.Cookies[idx].Value = newVal
	}
	technique := family + ":" + name + ":" + pc.key
	return model.Variant{
		Base:     req,
		Identity: nil, // credentials unchanged — same caller, tampered cookie value
		Mutation: model.Mutation{
			Type:        "cookie-tamper",
			Description: "flip " + pc.key + " " + pc.from + "→" + pc.to + " in cookie " + name + " (" + family + ")",
			Detail: map[string]string{
				"cookie-tamper": technique,
				"technique":     technique,
				"family":        family,
				"cookie":        name,
				"claim":         pc.key,
				"claim_from":    pc.from,
				"claim_to":      pc.to,
				"value_from":    fromVal,
				"value_to":      toVal,
			},
			Class: "authz-bypass",
		},
	}
}

// flipPlainClaim looks for `pc.key` followed by a separator (= or :) and the
// `pc.from` value as a delimited token inside s, and returns s with that single
// occurrence rewritten to `pc.to`. The match is case-insensitive on both key and
// value; the surrounding bytes (other claims, separators) are preserved verbatim.
// Returns false if the claim is not present in its unprivileged form (so a no-op
// never emits a variant).
//
// A "delimited token" means the value is bounded by a claim separator (; & , space)
// or the string ends — so `role=user` matches but `role=username` does not.
func flipPlainClaim(s string, pc privClaim) (string, bool) {
	low := strings.ToLower(s)
	keyLow := strings.ToLower(pc.key)
	fromLow := strings.ToLower(pc.from)

	search := 0
	for {
		ki := indexFrom(low, keyLow, search)
		if ki < 0 {
			return "", false
		}
		// The key must start a token: preceded by start-of-string or a delimiter.
		if ki > 0 && !isClaimDelim(low[ki-1]) {
			search = ki + 1
			continue
		}
		after := ki + len(keyLow)
		if after >= len(low) || (low[after] != '=' && low[after] != ':') {
			search = ki + 1
			continue
		}
		valStart := after + 1
		valEnd := valStart
		for valEnd < len(low) && !isClaimDelim(low[valEnd]) {
			valEnd++
		}
		// Case-insensitive value match; rewrite preserves the original key casing,
		// separator, and every surrounding byte from the source string.
		if low[valStart:valEnd] == fromLow {
			return s[:valStart] + pc.to + s[valEnd:], true
		}
		search = valEnd
	}
}

// indexFrom is strings.Index starting at offset.
func indexFrom(s, sub string, from int) int {
	if from >= len(s) {
		return -1
	}
	i := strings.Index(s[from:], sub)
	if i < 0 {
		return -1
	}
	return from + i
}

// isClaimDelim reports whether b separates claims in a cookie value.
func isClaimDelim(b byte) bool {
	switch b {
	case ';', '&', ',', ' ', '\t':
		return true
	}
	return false
}

// decodeB64 attempts to base64-decode s under the std then URL alphabet, with and
// without padding, returning the decoded string, the encoding that round-trips it,
// and whether any attempt succeeded. The returned encoding re-produces s verbatim
// when re-encoded, so a flipped payload stays in the same wire shape.
func decodeB64(s string) (string, *base64.Encoding, bool) {
	encs := []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	}
	for _, e := range encs {
		raw, err := e.DecodeString(s)
		if err != nil {
			continue
		}
		// Require the encoding to round-trip exactly, so re-encoding a flipped value
		// produces a wire-shape consistent with the original (no alphabet/padding drift).
		if e.EncodeToString(raw) != s {
			continue
		}
		// Reject trivially-short decodes that are just incidental base64 of the
		// cookie's own characters — a privilege claim is at least a few bytes.
		if len(raw) < 3 {
			continue
		}
		return string(raw), e, true
	}
	return "", nil, false
}

// isPrintable reports whether s is entirely printable ASCII (a guard against
// treating an arbitrary binary/encrypted cookie value as a tamperable claim string).
func isPrintable(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// looksJWT reports whether v has the three-segment shape of a JWT (header.payload.sig),
// which the JWT mutator family owns; CookieTamper skips these to avoid collision.
func looksJWT(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	// The first segment of a JWT base64url-decodes to JSON beginning with '{'.
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		// Padded variant.
		hdr, err = base64.URLEncoding.DecodeString(parts[0])
		if err != nil {
			return false
		}
	}
	return len(hdr) > 0 && strings.TrimSpace(string(hdr))[0] == '{'
}

// cookieTamperTechnique is a small helper used in tests to assert a mutation's
// technique without depending on the Detail map layout from outside the package.
func cookieTamperTechnique(m model.Mutation) string {
	if m.Detail == nil {
		return ""
	}
	return strings.TrimSpace(m.Detail["technique"])
}
