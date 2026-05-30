# Changelog

All notable changes to possession will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Open-redirect mutator** (`--open-redirect`,
  `internal/mutate/open_redirect.go`): a new mutator targeting the
  CWE-601 / ASVS V5.1.5 unvalidated-redirect family at the
  request-parameter layer. Where `--ssrf-probe` attacks *what
  server-side network resource the application fetches on the caller's
  behalf* (the URL value is consumed by an outbound HTTP client
  reaching internal IPs / cloud metadata), `--open-redirect` attacks
  *what destination the application bounces the caller's browser to*
  (the URL value is reflected into a `Location:` header reaching an
  attacker-controlled external site). Eligible parameters are matched
  by name (substring, case-insensitive, against a sorted token list —
  `back`, `callback`, `continue`, `dest`, `destination`, `goto`,
  `next`, `redir`, `redirect`, `return`, `returnto`, `success`,
  `target`, `url` — covers `redirect_uri`, `redirect_url`, `returnTo`,
  `next_page`, etc.) OR by value shape (an existing absolute `http(s)`
  URL). Four surfaces (query, urlencoded body, top-level JSON string,
  and the `Referer` header when present) are each cross-producted with
  seven disjoint payload techniques: `backslash-host`
  (`https://attacker.example\@target.example/` — RFC-vs-browser
  authority-parsing disagreement), `cross-origin`
  (`https://attacker.example/` — textbook external URL),
  `data-uri` (`data:text/html,<script>alert(1)</script>` — XSS via
  redirect), `javascript-uri` (`javascript:alert(1)` — XSS via
  redirect on legacy clients / WebViews), `protocol-relative`
  (`//attacker.example/` — defeats same-origin-by-leading-slash
  defenses), `userinfo-confusion`
  (`https://target.example@attacker.example/` — naive substring/prefix
  validators read the username as the host), and `whitespace-prefix`
  (validators trim before matching, then pass the un-trimmed value to
  the browser which also trims). The `Referer` surface emits only the
  header-safe technique subset (excludes `backslash-host` and
  `whitespace-prefix`, which `net/http` would reject or silently trim
  from a header value). Every variant keeps the caller's own
  credentials (`Identity == nil`) — this is a same-caller
  destination-rewrite probe, not an identity swap. Requests with no
  redirect-destination parameter and no `Referer` emit zero variants.
  Findings are class `open-redirect` (ASVS V5.1.5, severity MEDIUM:
  impact is phishing / OAuth-token leakage, not direct privilege
  bypass). Off by default — the payloads point callers' browsers at
  attacker-controlled URLs and embed XSS-via-redirect shapes (`data:` /
  `javascript:`). README and scan-help text updated. Disjoint from
  `--ssrf-probe` (server-side fetch, not client-side redirect),
  `--origin-spoof` (spoofs `Origin`/`Referer` to bypass origin-validation
  CSRF, not to coerce a redirect destination), and `--csrf-header`
  (forges anti-CSRF tokens, not redirect destinations).

- **SSRF probe mutator** (`--ssrf-probe`,
  `internal/mutate/ssrf_probe.go`): a new mutator targeting OWASP
  A10:2021 Server-Side Request Forgery at the request-parameter layer.
  Where `--path-traversal` reshapes the request path so the caller
  breaks out of the resource collection, `--mass-assign` injects
  privileged JSON properties, and `--swap-object` substitutes a
  resource-reference ID, `--ssrf-probe` rewrites URL-bearing query,
  urlencoded body, and top-level JSON string parameters to attacker-
  chosen SSRF payloads — weaponising the server's outbound HTTP
  client to reach loopback, RFC1918 private space, cloud-provider
  instance-metadata endpoints (AWS IMDSv1 169.254.169.254, GCP
  metadata.google.internal, Azure IMDS), and protocol-smuggling
  schemes (`file://`, `gopher://`). On a vulnerable EC2 instance the
  AWS IMDSv1 payload leaks instance IAM credentials in one hop — the
  2019 Capital One breach shape. Eligible parameters are matched by
  name (substring, case-insensitive, against a sorted token list
  including `url`, `uri`, `redirect`, `callback`, `webhook`,
  `target`, `dest`, `endpoint`, `next`, `return`, `src`, `host`,
  `image`, `fetch`) OR by value shape (an existing absolute http(s)
  URL). Cross-product is (3 surfaces × 7 techniques × eligible-
  parameter count); requests with no URL-bearing parameter emit
  zero variants. Every variant keeps the caller's own credentials
  (`Identity == nil`) — this is a same-caller fetch-target-rewrite
  probe, not an identity swap. Findings are class `ssrf`
  (ASVS V12.6). Off by default — the payloads reach the server's
  internal network including cloud metadata endpoints whose response
  on a vulnerable target contains the instance's IAM credentials.
  README and scan-help text updated.

- **Prototype-pollution mutator** (`--prototype-pollution`,
  `internal/mutate/prototype_pollution.go`): a new mutator in the
  privilege-escalation family targeting the canonical Node.js / browser
  prototype-pollution authz-bypass class (CVE-2018-3721 lodash,
  CVE-2019-10744 lodash, CVE-2019-11358 jQuery, and the 2024 Express
  qs/parseUrl chains; OWASP "Prototype Pollution Prevention" cheat sheet).
  Where `--mass-assign` attacks *which top-level properties the model
  binds* (server-side BOPLA at the object layer — set `is_admin` on the
  model instance), `--prototype-pollution` attacks *which properties
  every object in the JavaScript runtime inherits* (set `is_admin` on
  Object.prototype so every object answers `true` for it) — a distinct
  authz-bypass class with a distinct fix. A backend that deep-merges
  attacker-controlled JSON (lodash `_.merge`, `_.defaultsDeep`,
  `$.extend(true, …)`, mongoose, hand-rolled recursive Object.assign)
  walks past the `__proto__` / `constructor` / `prototype` keys it
  should be guarding and writes onto Object.prototype; every subsequent
  object the process creates inherits the polluted property and a
  downstream authz check that reads `req.user.is_admin` finds `true`
  even though the request never legitimately granted it. For each
  privileged property in the canonical set
  (`PrivilegedProperties` — `admin`, `is_admin`, `isAdmin`, `role`,
  `roles`, `verified`, shared with `--mass-assign` so the same
  authz-bypass surface is exercised against the prototype layer) and
  each of the three pollution vectors, a separate variant is emitted in
  deterministic sorted-by-field then sorted-by-vector order:
  `__proto__` (`{"__proto__": {key: value}}` — the direct CVE-2018-3721
  vector); `constructor.prototype`
  (`{"constructor": {"prototype": {key: value}}}` — every object's
  `constructor` is a function whose `.prototype` IS Object.prototype, so
  this bypasses guards that block only the literal `__proto__` key); and
  `prototype` (`{"prototype": {key: value}}` — the bare alias used by
  mongoose / handlebars / some hand-rolled merges that walk a key
  literally named `prototype` as data, a third pathway documented across
  the npm-ecosystem CVE chain). Every variant keeps the caller's own
  credentials (`Identity == nil` — credentials unchanged) and preserves
  the caller's own top-level body fields verbatim; the pollution
  payload is *added* alongside them, never replaces. Arrays, scalars,
  and non-JSON bodies emit no variants — there is nothing for a JSON
  deep-merge helper to recurse into. If the caller's own body already
  contains a top-level `__proto__` / `constructor` / `prototype` key
  (vanishingly rare in real traffic), that specific vector is skipped
  for that input. Pure and deterministic — the property and vector
  sweeps both sort at call time — so `--dry-run` and the offline corpus
  cover it for free. Findings are class `privesc`. Off by default: the
  polluted JSON reaches deep-merge code paths whose effect is
  *process-wide* (the entire Node.js process answers the polluted
  property thereafter — including for every concurrent user — until the
  runtime restarts), so it only fires when the operator opts in,
  mirroring the gating of `--mass-assign` (its top-level counterpart)
  and the rest of the off-by-default mutator family. Wired through
  `buildRegistry`; the mutator is always registered (inert when
  disabled) so the canonical `DefaultRegistry` order and the order test
  stay unchanged. Covered by 13 new tests across
  `internal/mutate/prototype_pollution_test.go` and
  `internal/cli/buildregistry_forbidden_test.go` — disabled-by-default
  contract, full cross-product cell coverage (every property × every
  vector emitted exactly once), per-vector body-shape invariants
  (`__proto__.key`, `constructor.prototype.key`, `prototype.key`
  reachable at the correct path; the polluted field NOT leaked to the
  top level, keeping the mutator disjoint from `--mass-assign`),
  caller-field preservation, non-JSON / array / empty body skip,
  already-present vector-key skip, determinism (field-outer/vector-inner
  monotonic sweep), credentials-unchanged contract, body
  non-aliasing, `Name()` stability for the allowlist, the
  not-in-`DefaultRegistry` contract, and the gating end-to-end through
  `buildRegistry` (both wordlist-on and wordlist-off paths).

- **Web Cache Deception mutator** (`--cache-deception`,
  `internal/mutate/cache_deception.go`): a new mutator in the
  access-control bypass family targeting the canonical Web Cache Deception
  class (Omer Gil, BlackHat 2017; refreshed in the 2024–2026 BlackHat
  Cache-Confusion / CDN-Confusion research). Where
  `--content-type-confusion` attacks *which body parser each layer
  chooses*, `--forbidden-bypass` attacks *how the path is matched against
  a deny rule*, and `--host-header` attacks *which host the gate evaluates*,
  `--cache-deception` attacks *which storage tier sees the response* — the
  URL is decorated with cacheable file-extension shapes (`.css`, `.js`,
  `.png`, `.jpg`, `.ico`, `.gif`, `.svg`) that a fronting CDN / edge cache
  stores by default, while the application router strips, ignores, or
  normalises away the decoration and still returns the caller's personal
  response. The cache stores that personal response under a public-looking
  key, exposing it to every later caller. Four disjoint technique shapes,
  each cross-producted with the cacheable extension set in deterministic
  sorted-by-name order: `path-suffix` (`/api/me/possession.css`, the
  Omer-Gil original), `path-extension` (`/api/me.css`, framework-extension
  stripping), `semicolon-suffix` (`/api/me;.css`, Tomcat / Spring
  matrix-parameter), and `encoded-suffix` (`/api/me%2fpossession.css`,
  gateway/router URL-normalisation desync). Every variant keeps the
  caller's own credentials (`Identity == nil`) — this is NOT an identity
  swap, the same caller's same fetch is decorated with a cacheable URL
  shape so the comparative ladder can flag the candidate cache-deception
  finding when the response remains owner-shaped. Endpoints already at a
  cacheable extension are skipped (no-op probe); on a trailing-slash path
  `path-extension` and `semicolon-suffix` are skipped (no terminal
  segment), and the encoded-suffix decoded form is normalised to avoid
  double-slashes. The mutation Detail carries `shape`, `extension`,
  `path_from`, and `path_to` so the reporter (and any future repro-snippet
  generator) can quote both URLs for the operator's cold-cache confirm
  step. Findings are class `authz-bypass` (ASVS V8.3.x, severity HIGH).
  Off by default: the decorated variants reach the caller's own personal
  endpoints by design and observably warm the upstream cache at the
  decorated URL on the caller's behalf — opt in via `--cache-deception`.
  Wired through `buildRegistry`; the mutator is always registered (inert
  when disabled) so the canonical `DefaultRegistry` order and the order
  test stay unchanged. Covered by 17 new tests across
  `internal/mutate/cache_deception_test.go` and
  `internal/cli/buildregistry_forbidden_test.go` — disabled-by-default
  contract, nil/empty/degenerate input safety, every-credentials-preserved
  contract, full cross-product cell coverage, per-shape Path/RawPath
  invariants (including the `%2f` un-double-encoded wire form), the
  already-cacheable-extension skip, trailing-slash handling,
  determinism, sorted-emission order, the `Name()` stability contract,
  the not-in-DefaultRegistry contract, and the gating end-to-end through
  `buildRegistry` (both wordlist-on and wordlist-off paths).

- **Content-Type confusion mutator** (`--content-type-confusion`,
  `internal/mutate/content_type_confusion.go`): a new mutator in the
  access-control bypass family. Where `--parameter-pollution` attacks *which
  copy of a duplicated parameter each layer reads*, `--host-header` attacks
  *which host the access-control layer believes the request targets*, and
  `--xxe` attacks *how the XML parser resolves entities*,
  `--content-type-confusion` attacks *which body parser each layer of the
  stack chooses* — the canonical Content-Type confusion / parser-sniffing
  family. The body bytes are kept byte-identical; only the `Content-Type`
  header is mutated. The bug being tested: a fronting WAF / API gateway
  short-circuits its body-inspection rules ("this is text/plain, no JSON to
  validate") while the application handler still parses the body as JSON, or
  the handler is wired to multiple parsers (JSON ↔ XML ↔ form) with different
  authz middleware and is coerced onto the alternate path. Every variant
  keeps the caller's own credentials (no identity swap — they merely
  relabel the body the handler will parse). Three technique sets, one per
  body shape, emitted in deterministic sorted order: JSON-shaped bodies
  (declared `*json*` or sniffed `{`/`[`) fan out to `as-form`
  (`application/x-www-form-urlencoded`), `as-text` (`text/plain`),
  `as-xml` (`application/xml`), and `strip-type` (drop the `Content-Type`
  header entirely so the receiver must sniff); XML-shaped bodies (declared
  `*xml*` or sniffed `<?xml` / a leading tag) emit `as-json` and `as-text`;
  urlencoded form bodies emit only `as-json` (the highest-signal mismatch;
  urlencoded bodies are hard to sniff so the technique set is deliberately
  narrow). The media-type comparison is parameter-insensitive
  (`application/json; charset=utf-8` and `application/json` compare equal)
  so a no-op relabel (declared type already matches target) is skipped —
  the comparative ladder must see a real probe, never a byte-identical
  baseline. Binary, multipart, and empty bodies produce no variants.
  Detection rides the existing comparative ladder unchanged: a variant that
  returns an owner-shaped 2xx where the caller's honest-Content-Type
  baseline did not is the bypass (class `authz-bypass`, ASVS V8.3.x). Pure
  and deterministic — body-shape classification is a fixed heuristic and
  techniques emit in sorted order — so `--dry-run` and the offline corpus
  cover it for free. **Off by default**: the relabelled variants reach
  alternate-parser code paths with weaker validation, so it only fires when
  the operator opts in, mirroring the gating of `--origin-spoof`,
  `--parameter-pollution`, `--header-injection`, `--cookie-tampering`,
  `--host-header`, `--forbidden-bypass`, `--method-override`,
  `--csrf-header`, `--ws-hijack`, `--xxe`, and `--mass-assign`. Registered
  (inert when disabled) so the canonical `DefaultRegistry` order is
  unchanged.
- **Origin/Referer spoofing mutator** (`--origin-spoof`,
  `internal/mutate/origin_spoof.go`): a new mutator in the access-control
  bypass family. Where `--csrf-header` attacks *the anti-CSRF token*,
  `--host-header` attacks *which host the access-control layer believes the
  request targets*, and `--header-injection` attacks *which trusted-proxy
  assertion the backend believes about the caller*, `--origin-spoof` attacks
  *which originating site the access-control layer believes the request came
  from* — the canonical "Origin/Referer-validation bypass" family every modern
  CSRF cheat-sheet describes. Many backends and gateways enforce state-change
  protection by validating the `Origin` (or `Referer`) header against an
  allowlist (the standard OWASP-recommended CSRF defense), and just as commonly
  implement the matcher wrong. Every variant keeps the caller's own credentials
  (no identity swap — they merely claim the request originated from a site the
  server should refuse). Three technique families, each a separate variant for
  attribution and emitted in deterministic sorted order: null-origin (set
  `Origin: null`, drop `Referer` — sandboxed iframes, `data:` / `javascript:`
  documents, redirect laundering, and meta-referrer policies all produce the
  literal origin `null`, which allowlists most commonly mishandle), cross-origin
  (set `Origin` and `Referer` to a wholly-foreign attacker site
  `https://attacker.example` — tests the baseline failure where the app does
  not validate Origin at all), and suffix-confusion (three crafted attacker
  hosts that defeat naive allowlist matching of the request's own host:
  prefix-match `<host>.attacker.example`, suffix-match
  `attacker-<host-with-dots-collapsed>.attacker.example`, and userinfo-confusion
  `<host>@attacker.example`). Deliberately disjoint from `--csrf-header` (which
  forges the anti-CSRF token, not the origin) and `--host-header` (which spoofs
  the wire `Host`, not the `Origin`). Detection rides the existing comparative
  ladder unchanged: a state-change that succeeds under a spoofed origin where a
  correct check would refuse it is the bypass (class `authz-bypass`, ASVS
  V8.3.x). Pure and deterministic — technique names and crafted hosts derive
  from fixed templates and emit in sorted order — so `--dry-run` and the
  offline corpus cover it for free. **Off by default**: the spoofed-origin
  variants re-issue the (often state-changing) request asserting an
  untrusted/forged origin against the access-control layer, so it only fires
  when the operator opts in, mirroring the gating of `--parameter-pollution`,
  `--header-injection`, `--cookie-tampering`, `--host-header`,
  `--forbidden-bypass`, `--method-override`, `--csrf-header`, `--ws-hijack`,
  `--xxe`, and `--mass-assign`.
- **HTTP Parameter Pollution mutator** (`--parameter-pollution`,
  `internal/mutate/param_pollution.go`): a new mutator in the access-control
  bypass family. Where `--swap-object` *replaces* a reference value and
  `--method-override` attacks *which verb the gate evaluates*,
  `--parameter-pollution` attacks *which copy of a duplicated parameter each
  layer of the stack reads* — the canonical HPP family. A request that carries
  the same parameter name twice can be parsed differently by a fronting WAF /
  API gateway (typically first-occurrence or concatenated) and the application
  framework (PHP / ASP.NET take the last, some Java stacks the first); by
  supplying the original gate-passing value once and an attacker-chosen value in
  a second occurrence, an unsanitised / privilege-altering value slips past the
  gate. Every variant keeps the caller's own credentials (no identity swap —
  they merely duplicate a parameter the stack mis-parses). Two surfaces, each
  emitted in two orderings for deterministic attribution: query-pollute
  (duplicate each query parameter, the tamper value once appended after the
  original and once prepended before it) and body-pollute (the same duplication
  applied to `application/x-www-form-urlencoded` bodies). The original
  occurrence is always preserved so a gate reading the expected value still
  passes; the injected tamper value defaults to `admin` and is configurable.
  Deliberately disjoint from `--swap-object` (which substitutes, not
  duplicates); JSON and multipart bodies are left untouched. Detection rides
  the existing comparative ladder unchanged: a variant that gains owner-shaped
  access where the caller's un-polluted baseline did not is the bypass (class
  `authz-bypass`, ASVS V8.3.x). Pure and deterministic — parameters processed
  in sorted name order, orderings in a fixed sequence — so `--dry-run` and the
  offline corpus cover it for free. **Off by default**: the polluted variants
  re-issue requests with altered parameter values that can reach mutating
  handlers, so it only fires when the operator opts in, mirroring the gating of
  `--header-injection`, `--cookie-tampering`, `--host-header`,
  `--forbidden-bypass`, `--method-override`, `--csrf-header`, `--ws-hijack`,
  `--xxe`, and `--mass-assign`.
- **Trusted-header injection mutator** (`--header-injection`,
  `internal/mutate/header_injection.go`): a new mutator in the access-control
  bypass family. Where `--host-header` attacks *which host the access-control
  layer trusts* and `--cookie-tampering` attacks *which authorization state the
  app trusts inside a cookie*, `--header-injection` attacks *which trusted-proxy
  assertion the backend believes about the caller* — the canonical "trusted
  header" / "internal-header spoofing" family. A backend that trusts headers it
  assumes a fronting proxy populated, but which are reachable from the untrusted
  client edge, is fooled into vouching for a caller who sets them directly. Every
  variant keeps the caller's own credentials (no identity swap — they merely add a
  header a misconfigured backend trusts). Two technique families, each a separate
  variant for attribution and emitted in deterministic sorted order:
  client-ip-spoof (a trusted-client-IP header — `X-Real-IP`, `X-Client-IP`,
  `X-Originating-IP`, `X-Remote-IP`, `X-Remote-Addr` — set to the loopback
  `127.0.0.1` so an IP-gated internal/admin rule treats the caller as inside the
  trust boundary) and trusted-identity (a proxy-set identity-assertion header —
  `X-Authenticated-User`, `X-Remote-User`, `X-Forwarded-User`, `X-User`,
  `X-WEBAUTH-USER` — naming a privileged principal so a backend that trusts a
  forwarded identity grants elevated access). The header set is deliberately
  disjoint from the headers `--forbidden-bypass` (`X-Forwarded-For`,
  `X-Original-URL`, `X-Rewrite-URL`) and `--host-header` (`Forwarded`,
  `X-Forwarded-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `X-Host`)
  already inject — no double-coverage, clean per-mutator attribution. This is
  **not** CRLF / response-splitting: injected values are well-formed tokens and
  `net/http` rejects raw CR/LF in header values, so splitting payloads are out of
  scope. Detection rides the existing comparative ladder unchanged: a variant that
  gains owner-shaped access where the caller's no-header baseline did not is the
  bypass (class `authz-bypass`, ASVS V8.3.x). Pure and deterministic, so
  `--dry-run` and the offline corpus cover it for free. **Off by default**: the
  spoofed-trust variants actively assert internal-origin/privileged identity
  against the access-control layer, mirroring the gating of `--cookie-tampering`,
  `--host-header`, `--forbidden-bypass`, `--method-override`, `--csrf-header`,
  `--ws-hijack`, `--xxe`, and `--mass-assign`. Registered (inert when disabled) so
  the canonical `DefaultRegistry` order is unchanged.

- **Cookie-value privilege-tampering mutator** (`--cookie-tampering`,
  `internal/mutate/cookie_tamper.go`): a new mutator in the access-control bypass
  family. Where `--drop-cookie` *removes* an auth cookie and `--strip-token`
  strips the bearer/CSRF side of the credential pair, `--cookie-tampering` keeps
  every cookie present and instead **flips one privilege claim inside an auth
  cookie's value** from its unprivileged to its privileged form — the classic
  broken-access-control pattern where the server trusts unsigned authorization
  state it stored in a cookie (`role=user`, `admin=0`, `is_admin=false`). Every
  variant keeps the caller's own credentials (no identity swap). Two technique
  families, each a separate variant for attribution and emitted in deterministic
  sorted order: value-claim-flip (rewrite a delimited plaintext claim in place —
  `role=user`→`role=admin`, `admin=0`→`admin=1` — token-bounded so `role=username`
  is left alone, and case-insensitive while preserving the original key casing)
  and base64-claim-flip (decode a base64-wrapped value under std/URL, padded or
  raw, flip the inner claim, and re-encode in the same alphabet/padding;
  JWT-shaped values are left to the JWT mutators). The built-in claim set
  (`role`, `admin`, `is_admin`, `isadmin`, `verified`) parallels `--mass-assign`'s
  privileged-property set; non-printable/encrypted blobs and values with no
  matching claim emit nothing. Detection rides the existing comparative ladder
  unchanged: a variant that gains elevated/owner-shaped access where the caller's
  untampered-cookie baseline did not is the bypass (class `authz-bypass`, ASVS
  V8.3.x). Pure and deterministic, so `--dry-run` and the offline corpus cover it
  for free. **Off by default**: the flipped-claim variants actively assert
  elevated privilege against the access-control layer, mirroring the gating of
  `--host-header`, `--forbidden-bypass`, `--method-override`, `--csrf-header`,
  `--ws-hijack`, `--xxe`, and `--mass-assign`. Registered (inert when disabled) so
  the canonical `DefaultRegistry` order is unchanged.

- **Host-header bypass mutator** (`--host-header`,
  `internal/mutate/host_header.go`): a new mutator in the access-control bypass
  family. Where `--forbidden-bypass` attacks *how the request path is matched*
  and `--method-override` attacks *which verb is evaluated*, `--host-header`
  attacks *which host the access-control layer believes the request targets* —
  the canonical "host-header injection" technique. Many deployments route or
  authorize from the `Host` (or a forwarded-host header a fronting proxy trusts);
  spoofing the host can reach an internal/loopback virtual host, hit an admin
  vhost from the public edge, or poison host-derived behaviour, all while keeping
  the caller's own credentials (no identity swap). Two technique families, each a
  separate variant for attribution and emitted in deterministic sorted order:
  host-override (replace the wire `Host` with `127.0.0.1` / `localhost` /
  `internal`; a no-op where the spoof equals the request's own host is skipped)
  and forwarded-host (keep the real `Host` on the request line and inject a
  forwarded-host override header — `X-Forwarded-Host`, `X-Host`,
  `X-Forwarded-Server`, `X-HTTP-Host-Override`, or RFC 7239 `Forwarded:
  host=…` — one variant per header×host). These complement `--forbidden-bypass`'s
  rewrite headers (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For`), which
  spoof the URL and client IP but never the host. Detection rides the existing
  comparative ladder unchanged: a variant returning an owner-shaped 2xx where the
  caller's public-host baseline did not, under a spoofed host, is the bypass
  (class `authz-bypass`, ASVS V8.3.x). Pure and deterministic (host values are
  constants), so `--dry-run` and the offline corpus cover it for free. **Off by
  default**: the spoofed-host variants actively probe the routing layer and can
  reach internal-only vhosts on a misconfigured proxy, mirroring the gating of
  `--forbidden-bypass`, `--method-override`, `--csrf-header`, `--ws-hijack`,
  `--xxe`, and `--mass-assign`. Registered (inert when disabled) so the canonical
  `DefaultRegistry` order is unchanged.

### Fixed

- **Captured/mutated `Host` header now reaches the wire**
  (`internal/replay/engine.go`, `buildHTTPRequest`): Go's `net/http` sends the
  request host from `http.Request.Host`, not a `Host` entry in the header map
  (which it silently ignores). `buildHTTPRequest` now promotes a `Host` header
  onto `req.Host` and removes it from the header map, so a spoofed host (the new
  `--host-header` mutator) and any genuinely captured `Host` actually reach the
  target. Requests without a `Host` header are unchanged (host derived from the
  URL as before).

- **HTTP verb / method-override bypass mutator** (`--method-override`,
  `internal/mutate/method_override.go`): a new mutator in the access-control
  bypass family. Where `--forbidden-bypass` attacks *how the request path is
  matched* and `--csrf-header` attacks *the anti-CSRF token*,
  `--method-override` attacks *which HTTP verb the access-control layer
  evaluates* — the canonical "method bypass" technique. Every variant keeps the
  caller's own credentials (no identity swap): the bug being tested is "the same
  rejected caller slips past the gate by changing the verb." Three technique
  families, each a separate variant for attribution and emitted in deterministic
  sorted order: override-header (`X-HTTP-Method`, `X-HTTP-Method-Override`,
  `X-Method-Override` — keep the request-line verb but inject a header naming a
  verb that crosses the safe/unsafe boundary: a safe GET/HEAD/OPTIONS request is
  overridden to POST, any write request to GET; frameworks that honour the
  override header dispatch the overridden verb to the protected handler the
  gateway gated by request-line method), verb-swap (change the actual
  request-line method to a sibling verb the gateway may not gate while the
  handler still serves it — GET ↔ HEAD/OPTIONS/POST, writes ↔ GET/PUT/PATCH; the
  original verb is never re-emitted), and case-toggle (flip the verb case, GET →
  get, to defeat a case-sensitive gateway matcher fronting a case-insensitive
  router). Detection rides the existing comparative ladder unchanged: the
  caller's own baseline against the protected endpoint is the denial; a variant
  returning an owner-shaped 2xx where the baseline was denied is the bypass
  (class `authz-bypass`, ASVS V8.3.x). Pure and deterministic (verbs are
  constants), so `--dry-run` and the offline corpus cover it for free. **Off by
  default**: verb-swap variants re-issue requests under state-changing methods
  and the override headers can reach mutating handlers, mirroring the gating of
  `--forbidden-bypass`, `--csrf-header`, `--ws-hijack`, `--xxe`, and
  `--mass-assign`. Registered (inert when disabled) so the canonical
  `DefaultRegistry` order is unchanged.

- **Anti-CSRF token bypass mutator** (`--csrf-header`,
  `internal/mutate/csrf_header.go`): a new mutator that is the inverse of
  `strip-token`. Where `strip-token` *removes* the CSRF header to probe whether
  the server depends on it, `--csrf-header` **forges or reflects** the anti-CSRF
  token using the caller's own credentials to probe whether the server's CSRF
  validation can be satisfied with a value the caller controls — the classic
  broken double-submit-cookie / presence-only-check family. Every variant keeps
  the caller's own credentials (no identity swap, no token strip): the bug being
  tested is "the same caller submits a CSRF token the server should reject, and
  the request still succeeds." Three techniques, each a separate variant for
  attribution and emitted in deterministic sorted order: `forged-double-submit`
  (when both a CSRF header and a CSRF cookie are present, overwrite *both* with
  one identical attacker-chosen value — a naive `header == cookie` check still
  passes), `reflect-cookie-to-header` (copy the CSRF cookie value verbatim into
  the CSRF header — the textbook double-submit reflection an attacker who can
  plant the cookie abuses), and `inject-missing-header` (when no CSRF header is
  present, inject `X-CSRF-Token` with a forged value to test presence-only
  enforcement). A header/cookie name is CSRF-ish when it contains `csrf` or
  `xsrf` (case-insensitive), matching `strip-token`'s heuristic. Detection rides
  the existing comparative ladder unchanged: the caller's own baseline is the
  legitimate request with its real token; a variant that returns an owner-shaped
  2xx with a forged/reflected token is the bypass (class `authz-bypass`, ASVS
  V8.3.x). Pure and deterministic (the forged token is a constant), so
  `--dry-run` and the offline corpus cover it for free. **Off by default**:
  forging an anti-CSRF token is an active access-control probe, mirroring the
  gating of `--xxe`, `--mass-assign`, `--forbidden-bypass`, `--ws-hijack`, and
  `--jwt-attack`. Registered (inert when disabled) so the canonical
  `DefaultRegistry` order is unchanged. A request with no CSRF header and no CSRF
  cookie yields a single `inject-missing-header` variant; a request with a CSRF
  header but no CSRF cookie yields no variants.

- **WebSocket upgrade hijack mutator** (`--ws-hijack`,
  `internal/mutate/ws_hijack.go`): a new mutator that attacks the one request
  applications most often forget to authorize — the HTTP → WebSocket upgrade
  handshake. WebSocket endpoints are frequently mounted behind a handshake that
  skips the per-route authorization the REST layer enforces, so any caller who
  can reach the endpoint can open a live channel. For every captured request
  recognized as a WebSocket handshake (by its RFC 6455 headers — `Upgrade:
  websocket` + a `Connection` value containing `upgrade`, or a
  `Sec-WebSocket-Key` header), it replays the handshake — **preserving the
  upgrade headers** — under modified identities: a `strip-auth` variant with all
  credentials removed (anonymous upgrade, class `authn-bypass`) and one
  `swap-identity` variant per matrix identity carrying that identity's
  credentials (class `idor`, or `idor-cross-tenant` when the swapped identity's
  tenant differs from the captured owner's). Detection sits outside the
  comparative ladder: a handshake has no comparable response body, so the
  decisive, false-positive-free signal is a `101 Switching Protocols` response —
  a 101 to a stripped/swapped identity means the server completed the upgrade
  without enforcing authorization (a new evaluator branch, near-certain
  confidence). Any non-101 response (401/403, transport error, or a normal 200)
  is enforced. The branch runs ahead of the transport-error short-circuit so a
  `101` (which is below the 2xx band) is never swallowed as an error. Pure and
  deterministic like every mutator (strip-auth first, then identities in
  canonical rank,name order). **Off by default**: opening a live channel under a
  foreign/stripped identity is an active access-control probe, so it only fires
  via `--ws-hijack`. Non-handshake requests produce no variants.

- **Burp Suite XML input parser** (`--format burp`, `internal/parse/burp.go`):
  a sixth capture format alongside HAR/curl/OpenAPI/Postman/mitmproxy. possession
  positions itself as the standalone alternative to Burp Autorize, but most
  hunters already capture their traffic *in* Burp — this parser lets them feed a
  Burp "Save items" / proxy-history XML export (`<items><item>…`) straight into
  `scan`/`parse` with no re-capture. For each `<item>` it parses the raw HTTP
  request (the `<request>` element — `base64="true"` decoded, otherwise verbatim)
  as authoritative for method, headers, cookies, and body, and assembles the
  absolute URL from the `<url>` field or the structured
  `<protocol>`/`<host>`/`<port>`/`<path>` (default ports elided, non-default
  preserved). An item with no usable raw request falls back to the structured
  fields. The same hygiene as the HAR parser applies — static assets, font/image/
  css/js content types, and well-known analytics hosts are dropped — so a Burp
  export and the equivalent HAR dedup to the same endpoints; one malformed item
  is skipped without failing the parse. Auto-detected by the `.xml` extension or
  a leading `<`. Synthesized endpoints feed every mutator exactly like HAR/curl
  captures.

- **XML External Entity / XXE mutator** (`--xxe`, `internal/mutate/xxe.go`): a
  new mutator that attacks *how the request body itself is parsed*. For APIs that
  accept **XML** request bodies, it tests whether the server's XML parser
  resolves external/internal entities — the root cause of file disclosure, SSRF,
  and parser DoS. For every captured request carrying an XML body (by
  `Content-Type` or body shape), it keeps the caller's own credentials and emits
  one variant per technique, rewriting the body to carry a malicious `DOCTYPE`:
  an `internal-entity` variant whose entity value is a unique per-endpoint canary
  string, and an `external-system` variant defining a `SYSTEM` entity pointing at
  `file:///etc/passwd`. Detection for the internal-entity technique is decisive
  and false-positive-free: a new evaluator branch (gated on
  `Mutation.Detail["xxe-canary"]`) raises a `xxe-injection`/HIGH bypass at
  near-certain confidence when the response reflects the canary verbatim — proof
  the parser expanded the entity. The branch sits ahead of the comparative
  similarity work (XXE has no owner/actor baseline) but behind the
  error/denied-status filters, so a `4xx`/`5xx` is still enforced even if it
  echoes the canary. The external-system technique carries no canary and falls
  through to the normal comparative ladder. Any pre-existing `DOCTYPE` is stripped
  first (no double-DOCTYPE), and an XML `Content-Type` is forced when absent.
  Pure and deterministic like every mutator (techniques emitted in sorted order,
  canary derived from the request's deterministic ID), so `--dry-run` and the
  offline corpus cover it for free. Off by default because the payloads are
  write-shaped against the parser and the SYSTEM-entity variant probes for
  local-file / SSRF resolution; non-XML bodies (JSON, form-encoded, empty) and
  self-closing-only roots produce no variants. Registered (inert when disabled)
  in `buildRegistry`, kept out of `DefaultRegistry` like the other gated
  mutators. New ASVS (`v5.0.0-13.4.1`) and severity mappings added for the
  `xxe-injection` class. (POST_V01 R18 candidate: XXE mutator for XML APIs.)
- **Mass-assignment / BOPLA mutator** (`--mass-assign`,
  `internal/mutate/mass_assign.go`): a new mutator that completes the third axis
  of an authorization test. Where `swap-identity` attacks *who* the caller is and
  `swap-object` attacks *which object* is referenced, `mass-assign` attacks
  *which properties* the caller may set — Broken Object Property Level
  Authorization (OWASP API #3, "mass assignment" / over-posting). For every
  captured request carrying a JSON **object** body, it keeps the caller's own
  credentials and emits one variant per privileged property (`admin`, `is_admin`,
  `isAdmin`, `role:admin`, `roles:[admin]`, `verified`), *adding* a field the
  client should not be permitted to set. A property the request already sets is
  skipped (case-insensitive). Pure and deterministic like every mutator
  (properties applied in sorted order, object keys re-marshalled sorted), so
  `--dry-run` and the offline corpus cover it for free. Findings are class
  `privesc`, severity HIGH — a 2xx whose body reflects the smuggled property
  means the server bound an attacker-controlled field onto its model. Off by
  default because the variants are write-shaped and mutate server state; requests
  without a JSON object body (GET, form-encoded, JSON arrays, empty bodies)
  produce no variants. Registered (inert when disabled) in `buildRegistry`, kept
  out of `DefaultRegistry` like the other gated mutators. (POST_V01 candidate:
  mass-assignment parameter pollution.)
- **Statistical retry** (`--retry-inconclusive`, `internal/replay/retry.go`): a
  scan can now re-issue each transiently-failed variant exactly once before
  detection runs, so a flaky target's one-off failures stop masquerading as
  inconclusive verdicts (and thus as findings you never see). A variant is
  re-issued when its response is a transport error, a `429`, or any `5xx`; the
  retry goes through the standard fire path (same rate limiter, concurrency,
  refresh injections, body caps). A recovered retry replaces the failure; a
  retry that fails again preserves the original response, so a flaky target can
  never make a result worse than the first attempt. Refresh/flow setup failures
  (`Inconclusive`) are deliberately not retried — a single variant re-issue
  cannot repair a per-identity setup failure, so it would only burn a request.
  Implemented as a pure `replay.IsTransientFailure` predicate plus an
  `Engine.RetryInconclusive` method that fires a sub-plan of just the failures
  and fires the `OnResponse` hook only for retries it keeps, so `--resume` and
  `--record` capture the improved response. Off by default and rate-sensitive
  (it costs extra requests against an already-struggling target); mutually
  exclusive with `--replay` (which fires nothing to retry). (ROADMAP v1.1:
  "statistical retry — re-issue inconclusive variants once before reporting".)

- **Resume on interrupt** (`--resume <dir>`, `internal/record/checkpoint.go`):
  a scan can now survive interruption — Ctrl-C, a dropped connection, a quota
  wall, a host reboot — without discarding the requests it already fired. Every
  completed baseline and variant response is checkpointed to an append-only
  `<dir>/checkpoint.jsonl` as it lands (one JSON object per line, flushed
  immediately). Re-running with the same `--resume <dir>` loads the checkpoint,
  skips every variant whose deterministic ID is already recorded, and fires only
  the remainder. Append-only JSON Lines is crash-safe by construction: a crash
  mid-write can at worst leave a torn final line, which is skipped on reload
  (that one variant is simply re-fired), so a checkpoint never poisons a resume.
  Because responses are keyed by variant ID and merged back into plan order, a
  resumed-then-completed scan feeds detection byte-for-byte identical inputs to
  an uninterrupted run. Implemented as an opt-in `Engine.OnResponse` hook fired
  per completed response (nil hook ⇒ previous behaviour exactly), plus a
  `RunWithKind` variant of `Engine.Run` that tags responses baseline-vs-variant.
  Mutually exclusive with `--replay` (replay fires nothing, so there is nothing
  to resume); composes with `--record`. (ROADMAP v1.1: "resume on interrupt".)

- **mitmproxy JSON input parser** (`internal/parse/mitmproxy.go`): `scan` and
  `parse` now accept a [mitmproxy](https://mitmproxy.org) JSON flow dump as a
  fifth input format (`--format mitmproxy`) alongside HAR, curl, OpenAPI 3.x,
  and Postman v2. Two stable text serializations are read — a **JSON array** of
  flow objects and **JSON Lines** (one flow per line, `.jsonl`/`.ndjson`) — the
  shapes the `jsondump`/`mitmdump` json addons emit. Each HTTP flow becomes one
  `CapturedRequest`: the URL is rebuilt from `scheme`+`host`+`port`+`path`
  (default `80`/`443` elided, non-default ports preserved, absolute-form paths
  parsed directly); headers are read from either serialization
  (`["Name","Value"]` pairs or `{"name","value"}` objects) and the `Cookie`
  header is split into individual cookies; the body comes from the request's
  `content`/`text` field. The HAR parser's hygiene is reused (static assets,
  `text/css`/`application/javascript`, analytics hosts dropped) so a mitmproxy
  dump and the equivalent HAR dedup identically. Non-HTTP flows (tcp/websocket/
  dns) and one malformed flow or JSON-Lines line are skipped without failing the
  parse. Auto-detection routes a top-level JSON array, a `.jsonl`/`.ndjson`
  extension, or a JSON flow object (`request` + `scheme`/`server_conn`, no
  `log`) to this parser. Native binary `.flow`/`.mitm` files are intentionally
  out of scope — export as JSON or HAR. (v1.1 backlog: "mitmproxy flow files".)

- **HTML reporter** (`--report html`, `internal/report/html.go`): a fifth
  output format that renders a single **self-contained, offline-interactive**
  HTML document — no external CSS/JS, no CDN links, no network fetches, so the
  styling and interactivity travel with the file (archive it, attach it to a
  ticket, open it on an air-gapped box). Findings are grouped by severity with
  colour-coded badges; each carries a metadata table, signal trace, the
  owner-baseline → variant differential, and a collapsible **Reproduction**
  block (raw HTTP + `curl`) built on native `<details>`/`<summary>` so the
  report is fully readable with JavaScript disabled. A small inline script adds
  severity filtering as progressive enhancement. Reproductions reuse the shared
  `BuildRepro` path: credentials are **redacted by default** to
  identity-tagged placeholders (`<bearer:bob>`), honour `--repro-creds` for
  live tokens, and all finding-derived data is HTML-escaped so untrusted
  response content cannot inject markup. Output is byte-stable across runs.
  (v1.1 backlog: "HTML reporter — offline interactive view with collapsible
  signal traces".)

- **Postman Collection v2 input parser** (`internal/parse/postman.go`): `scan`
  and `parse` now accept a Postman Collection v2.0/v2.1 export (the format the
  Postman app produces) as a fourth input format alongside HAR, curl, and
  OpenAPI 3.x. Folders are walked recursively; each request item becomes one
  `CapturedRequest`. The URL is read from the structured `url` object
  (`protocol`/`host`/`path`/`query`) or a bare string URL, dropping disabled
  query params; headers come from `request.header[]` (disabled entries
  skipped); bodies are read for `raw` (JSON content type inferred from
  `options.raw.language`), `urlencoded`, and text `formdata` modes.
  `{{variables}}` resolve from collection-, folder-, and request-level
  `variable[]` arrays with the innermost scope winning, and unbound
  `{{name}}` placeholders are left literal so missing variables stay visible.
  Auto-detection distinguishes Postman from HAR (both JSON objects) via the
  `collection/v2` schema marker, `_postman_id`, or the `info`+`item` pairing;
  override with `--format postman`. Postman v1 collections are rejected with a
  hint to re-export as v2.1. Synthesized endpoints feed every mutator exactly
  like HAR/curl/OpenAPI captures. (POST_V01: next self-contained input-coverage
  item; Items 1–7 already shipped.)

- **BOLA confidence band** (POST_V01 Item 5): every finding now carries a
  categorical `confidence_band` (`high`/`medium`/`low`) alongside the numeric
  `confidence`, derived from both the numeric confidence and the variant
  response body's similarity to the resource owner's baseline. This separates
  true BOLAs (body near-identical to the owner's resource ⇒ `high`) from the
  most common authz false positive — an API returning `200 OK` with an error
  body (`{"error":"forbidden"}`) instead of a `403`, whose body diverges from
  the owner baseline and is therefore capped at `low` regardless of numeric
  confidence. A decisive owner-marker reflection clears the similarity gate
  and qualifies for `high` even when the surrounding body differs. The band
  is surfaced as a new `BAND` column in the human reporter, the
  `confidence_band` field in JSON, and a `confidence_band` property in SARIF.
  Tuning constants (`BandHighSimFloor`, `BandMediumSimFloor`, `BandHighConfFloor`,
  `BandMediumConfFloor`) live in `internal/detect/tuning.go` alongside the rest
  of the calibration; the classifier is `detect.ClassifyConfidenceBand`.

- **Token-level JWT auth-bypass mutator** (`internal/mutate/jwt_auth.go`),
  gated behind `--jwt-attack` (off by default — noisier than identity swap).
  Where the existing mutators swap *identities*, this attacks the *token
  itself*, forging two auth-bypass variants per captured Bearer JWT:
  (1) **alg:none** — header rewritten to `{"alg":"none","typ":"JWT"}`,
  signature dropped (`<header>.<payload>.`), finding `POSSESSION-JWT-NONE`;
  (2) **blank-secret** — claims re-signed with HS256 using an empty-string
  HMAC key, finding `POSSESSION-JWT-BLANK-SECRET`. Both class `authn-bypass`,
  severity HIGH (pinned via `detect.SeverityOverrideByMutator`). No external
  JWT library — tokens are built by base64url decode/re-encode + HMAC. Works
  on any request whose `Authorization: Bearer`, auth header, auth cookie, or
  JSON body token field decodes as a 3-part JWT. Tests include a mock HTTP
  server that validates alg + signature in secure and misconfigured modes.

- **OpenAPI 3.x input parser** (`internal/parse/openapi.go`): accept an
  OpenAPI/Swagger 3.x spec (JSON or YAML) as `scan`/`parse` input, synthesizing
  one `CapturedRequest` per operation so an entire documented API surface can be
  tested without a HAR. Path/query/header params are filled from
  `example`/`examples`/`schema`/`default`/`enum` values (id-shaped path params
  fall back to `1`); minimal JSON bodies are synthesized from the `requestBody`
  schema with local `$ref` and shallow `allOf` resolution. Wired into
  `detectFormat` (`--format openapi`, plus `.yaml`/`.yml` extension and
  `openapi`/`swagger` content-key auto-detection that disambiguates OpenAPI JSON
  from HAR JSON). Synthesized endpoints feed every existing mutator unchanged.

### Fixed

- **Data race in `TestScanRecordThenReplay_RoundTrip`** (`internal/cli/
  scan_record_test.go`): the end-to-end record/replay test counted server hits
  with a plain `int` mutated from the `httptest.Server`'s per-connection
  goroutines while the test goroutine read it — and possession's replay engine
  fans variants out across `concurrency` goroutines, so the handler ran
  concurrently. `go test ./... -race` (the CI gate and `make test`) reported a
  `DATA RACE` and failed the whole `internal/cli` package. The counter is now a
  `sync/atomic.Int64`, making the increments and the three reads race-free; the
  full suite passes cleanly under `-race`. Test-only change — no production code,
  behaviour, or public surface affected.

## [1.1.0] — 2026-05-18

Four packets shipped in the v1.1 autonomous run. Plus one integration
hotfix found during merge: `replay.Engine.flowHTTP` (separate cookie-jar-free
client for flow execution, preventing cross-identity session bleed).

### Added

#### Packet 5 — Deep JWT Attacks
- Four new JWT mutators registered after the v1.0 set (D33–D36):
  - `jwt-alg-confusion`: RS256/ES256→HS256 by re-signing with the server's
    public key as the HMAC secret. Requires `target.jwt.public_key_pem`.
  - `jwt-kid-injection`: path-traversal (`../../../dev/null`) and SQLi-style
    payloads in the `kid` JWT header.
  - `jwt-jwks-spoof`: embed attacker-controlled key via inline `jwk` header or
    `jku` redirect; signs with matching ephemeral RSA-2048 private key.
  - `jwt-hmac-crack`: wordlist-based HS256 secret recovery; re-signs tampered
    token (role=admin) on a hit. Extends to `--jwt-wordlist <file>`.
- `target.jwt.public_key_pem` / `target.jwt.jwks_url` in the role-matrix
  schema (additive; absent → key-dependent attacks skip with a note).
- New helpers in `internal/jwt`: `AlgConfusionFromPEM`, `GenerateAttackerKeyPair`,
  `EncodeWithRS256`, `PublicKeyToJWK`, `B64URL`, `EncodePKIX`.

#### Packet 6 — AuthMatrix-style Assertion Evaluator
- `AssertionEvaluator` implements the `Evaluator` interface (D16). Predeclared
  `assertions:` block in the matrix YAML maps endpoint globs × roles → `allow`
  or `deny`. Explicit expectations yield high-confidence bypass findings (0.97).
- `BothEvaluator`: runs assertion evaluator where assertions exist, comparative
  everywhere else. Assertion verdict takes precedence.
- `--evaluator comparative|assertion|both` flag (default `comparative`; backward
  compatible). `assertion` with no assertions block → clear error.
- Glob precedence: most-specific pattern wins (longest string length; ties by
  declaration order). Defined and tested.
- `broken-deny` finding class (surfaces as `suspected`) for access-denied-but-
  allow-expected cases (overly-strict controls, not security bugs).
- Config validator: roles in `expect` must exist in `identities`; globs must compile.

#### Packet 7 — Stateful Flows (Tier 2)
- New `internal/flow` package:
  - `Validate`: cycle detection, forward-only reference resolution.
  - `Execute`: multi-step flow execution with `{name}` interpolation (identifier
    regex: `[A-Za-z][A-Za-z0-9_-]*` to avoid false matches in JSON bodies).
  - `ExecuteFrom`: re-run from a given step index for volatile/nonce re-use.
- `model.FlowDef`, `model.FlowStep`, `model.FlowExtraction` (with optional
  `Inject` and `Volatile` fields). `Identity.FlowName` references a named flow.
- `replay.Engine.PrepareFlows`: executes each identity's flow before its
  variants; caches result; D10 failure policy (inconclusive on flow failure).
- Volatile step re-run in `applyFlowInjections` per-variant for CSRF/nonce
  freshness; uses `Engine.flowHTTP` (jar-free, prevents cross-identity bleed).
- YAML: `flows:` list + `flow:` field on identities.

#### Packet 8 — Tenant Awareness + OAuth2/OIDC
- `Identity.Tenant` field + `RoleMatrix.Tenants` list. Activates the D31
  dormant `idor-cross-tenant` code path: `swap-identity` across a tenant
  boundary → class `idor-cross-tenant`, severity `critical`,
  ASVS `v5.0.0-8.4.1 + v5.0.0-8.2.2`.
- `OAuth2StepDef` in `model.FlowStep.OAuth2`: `client_credentials` and
  `refresh_token` grants. Token acquired via `issueOAuth2Step` in
  `internal/flow`; result flows through the variable bag for injection.
- YAML: `tenants:`, `tenant:` on identities, `oauth2:` in flow steps.

### Fixed

- **Integration hotfix (replay):** `Engine.flowHTTP` — a separate
  `http.Client` without a cookie jar for all flow execution. The main
  client's jar was accumulating `Set-Cookie` responses from multiple
  identity login flows, causing cross-identity session bleed and
  intermittent false negatives in the P7 corpus under `-race`.
  Concurrently fixed a data race in `applyFlowInjections` (copy `fr.vars`
  under mutex before calling `ExecuteFrom`; update keys individually on
  write-back rather than replacing the map pointer).

### Changed

- Mutator registry expanded from 9 to 13 entries (P5 additions).
- `docs/DECISIONS.md`: D33–D46 added.
- `docs/ROADMAP.md`: v1.2 backlog section added (SAML, deep OAuth/OIDC,
  GraphQL authz, ASVS V9 mapping, TUI, Postman/OpenAPI input).

---

## [1.0.0] — 2026-05-16

First stable release. Four packets shipped:

### Added

#### Packet 1 — Foundation
- HAR and curl parsers (`possession parse`).
- Path templating heuristics (numeric IDs, UUIDs, hex blobs → `{id}`).
- Endpoint dedup by `(method, host, path_template)`.
- Role-matrix YAML loader with aggregated validation errors.
- Glob-based scope filtering (custom tiny doublestar; see `docs/ARCHITECTURE.md`).
- Cobra CLI scaffold: `parse`, `scan` (stub), `version`.

#### Packet 2 — Replay engine
- Five mutators: `strip-auth`, `swap-identity`, `downgrade-role`,
  `drop-cookie`, `strip-token` (D8). Deterministic generation order
  with `--max-variants` cap (D11).
- HTTP client with per-host token-bucket rate limiter
  (`golang.org/x/time/rate`), bounded concurrency, adaptive
  429/503 backoff honoring `Retry-After` (D15).
- Tier-1 dynamic credential refresh hooks (`body-json`, `body-regex`,
  `header`, `cookie` extractors).
- End-to-end `possession scan` with structured JSON output.
- 5 MB body cap with `Response.Truncated` flag (D12); `BodySHA256`.

#### Packet 3 — Detection
- Capture-owner attribution (D17): match captured credentials against
  matrix identities (bearer / cookie / header / basic-username).
- Calibrated N-sample baseline (D18): per-endpoint similarity
  threshold derived from owner self-replay; noisy endpoints capped at
  `suspected`; baseline-not-2xx ⇒ inconclusive.
- JSON+HTML body normalization stripping volatile keys, timestamps,
  CSRF tokens, UUIDs (§4.2 of the P3 brief).
- Six signals: status-class, similarity (token-shingle Jaccard,
  shingle=4), size ratio, errorSignature, reflectedOwner,
  reflectedActor.
- Ten-branch verdict ladder (§4.4). Verdicts: `bypass`, `suspected`,
  `enforced`, `inconclusive` (D19).
- Per-identity `markers` field on `Identity` (D20) — optional unique
  data strings that enable the strongest IDOR detection signal.
- ASVS v5.0.0 chapter V8 control mapping per Finding.Class (D22).
- `Evaluator` interface + `ComparativeEvaluator` (D16) so a future
  declarative-assertion evaluator can drop in.
- Integration corpus (`internal/detect/corpus_test.go`): vulnapp +
  secureapp httptest servers. **Gate E**: secureapp must produce ZERO
  bypass findings — enforced by `TestCorpus_SecureApp_ZeroBypass`.

#### Packet 4 — JWT mutators + reporting + release
- Four JWT mutators (D24): `jwt-alg-none` (3 casings per location),
  `jwt-sig-strip`, `jwt-claim-tamper` (privesc/authn-bypass class per
  claim), `jwt-resign-weak-key` (8 conventional secrets).
- `internal/jwt` helper package: lenient `Detect`/`Decode`,
  malformed-token assembly in `encode.go`.
- `model.RunResult` aggregate (additive — does not break the legacy
  scan JSON shape).
- Three reporters via the `report.Reporter` interface (D26): `human`
  (default), `json`, `sarif`. SARIF 2.1.0 via `owenrumney/go-sarif/v3`
  (D27), round-trips through the library, with ASVS in rule helpUri.
- `--report sarif|json|human` and `--exit-zero` flags. Exit code 3
  when findings present (suppressable via `--exit-zero`).
- Typed `detect.EndpointNote` enum (D29) replaces P3's prefix-tagged
  free strings.
- `Mutation.Class` is now set at variant generation in each mutator
  (D30), no re-derivation in detect / cli.
- D28: cross-rank `swap-identity` runs the ladder and is capped at
  `suspected` with a `cross-rank-swap` note.
- Corpus extension: vulnapp `/jwt` accepts `alg=none`; secureapp
  `/jwt` enforces HS256 with a strong secret. Gate E confirmed for
  JWT path: 13 JWT-mutator bypasses on vulnapp, 0 on secureapp.
- Cross-compile Makefile target (`make release`): linux/{amd64,arm64},
  darwin/{amd64,arm64}, windows/amd64 with SHA256 checksums.
- Examples directory (`examples/ecommerce/`): runnable HAR + matrix +
  expected outputs.
- Full README rewrite, ROADMAP v1.1 backlog, DECISIONS D24–D32.

### Gate Status
- **Gate E** (secureapp zero bypass): PASS. Both classic (3 endpoints)
  and JWT (1 endpoint) sub-corpora produce zero bypass findings.
- **Gate F** (do not invent ASVS V9 IDs): observed. SARIF rule
  property bag emits V8 controls only; V9 (Self-Contained Tokens) IDs
  are deliberately omitted — they could not be confirmed from
  available references, and per the brief "hallucinated control IDs
  in a security tool's output are worse than just having V8".

### Known limitations (v1.1 candidates)
See `docs/ROADMAP.md` for the full backlog.
