# Roadmap

possession shipped v1.0.0 in four packets. v1.1 backlog follows.

## Packet 1 — Foundation (shipped)

- HAR + curl parsers.
- Path templating + endpoint dedup.
- Role matrix loader + validator.
- CLI scaffold (cobra): `parse`, `scan` (stub), `version`.
- Test data, unit tests, CI.

## Packet 2 — Replay engine (shipped)

- HTTP client with per-host rate limiting, bounded concurrency,
  configurable timeout, optional redirect following.
- Variant production: strip-auth, swap-identity, downgrade-role,
  drop-cookie, strip-token.
- Per-identity Tier-1 refresh hooks: issue refresh request, extract via
  body-json / body-regex / header / cookie, inject into subsequent replays.
- Response type with status, headers, body (size-capped), timing.
- End-to-end `scan` with structured JSON output.

## Packet 3 — Detection evaluator (shipped)

- `detect.Evaluator` interface + `ComparativeEvaluator` implementation.
- Owner attribution, calibrated baseline, six signals, ten-branch
  verdict ladder.
- Findings with confidence + severity + ASVS V8 control refs.
- Integration corpus (vulnapp + secureapp) with Gate E enforcement.

## Packet 4 — JWT + reporting + v1.0 (shipped)

- Four JWT mutators: jwt-alg-none, jwt-sig-strip, jwt-claim-tamper,
  jwt-resign-weak-key.
- `internal/jwt` helper package (lenient detect/decode, malformed-token
  encode).
- Three reporters: human (default), json, sarif (SARIF 2.1.0).
- Carried-over cleanups: D28 (cross-rank cap), D29 (typed
  EndpointNote), D30 (single-source Mutation.Class).
- Release prep: README, CHANGELOG, examples, cross-compile Makefile.

## v1.1 backlog

Items deliberately left out of v1.0 to keep the scope bounded:

### Detection / evaluator
- AuthMatrix-style declarative evaluator (the `Evaluator` interface
  seam in `internal/detect/evaluator.go` is ready for it).
- ~~Activate `idor-cross-tenant` (D31): add a per-identity `tenant`
  field to the role-matrix schema so the dormant code path can fire.~~
  **Shipped** (P8): `Identity.Tenant` field in role-matrix schema; cross-tenant
  swaps automatically emit `idor-cross-tenant` class (critical severity).
- Distinguish "denied" from "different resource" at the low-similarity
  end of the ladder (current v1.0 limitation, see branch 10 of
  `internal/detect/evaluate.go`).
- ~~Statistical retry: re-issue inconclusive variants once before
  reporting.~~ **Shipped** (`--retry-inconclusive`): re-issues each
  transiently-failed variant (transport error / 429 / 5xx) exactly once
  before detection; a recovered retry replaces the failure, a still-failing
  one preserves the original. Refresh/flow setup failures are not retried.
  Off by default, rate-sensitive; mutually exclusive with `--replay`.

### JWT (deeper attacks)
- ~~RS256→HS256 alg-confusion (sign attacker key with server's public
  key as HMAC secret).~~ **Shipped** (`--jwt-alg-confusion`).
- ~~`kid` injection (path traversal, SQL injection, command injection
  via the `kid` header).~~ **Shipped** (`jwt-kid-injection`, always-on
  when a JWT is detected; 6 payloads across path-traversal and sqli classes).
- ~~JKU / x5u / JWK spoofing (point the verifier at attacker-controlled
  JWKS).~~ **Shipped** (`jwt-jwks-spoof`): inline `jwk` header embed and
  `jku` redirect-to-attacker-URL variants per token location.
- ~~HMAC secret cracking against captured tokens (offline dictionary +
  rule-based mutation).~~ **Shipped** (`jwt-hmac-crack`): 16-entry default
  wordlist, cracked secret re-signs with role=admin escalation, capped at
  500 attempts per token location.

### Input formats
- ~~Postman collection v2 parser.~~ **Shipped.**
- ~~OpenAPI 3.x parser (synthesize requests from schema + examples).~~ **Shipped.**
- ~~mitmproxy flow files.~~ **Shipped** (`--format mitmproxy`): mitmproxy JSON
  flow dumps — a JSON array of flows or JSON Lines (`.jsonl`/`.ndjson`), the
  shapes the `jsondump`/`mitmdump` json addons emit. Native binary `.flow`
  files are intentionally out of scope (export as JSON or HAR).

### Auth flows
- Multi-step / stateful login flows (CSRF chains, OTP, redirect-heavy
  OAuth code-grant captures).
- SAML assertion mutators.
- OAuth2 PKCE / state mutators.

### Reporting
- ~~HTML reporter (offline interactive view with collapsible signal
  traces).~~ **Shipped** (`--report html`): single self-contained
  document, severity-grouped findings, collapsible repro blocks,
  progressive-enhancement severity filter.
- ~~Markdown reporter for PR comments.~~ **Shipped** (`--report markdown`):
  GitHub-flavored Markdown, impact-first, per-finding collapsible repro
  blocks (raw HTTP + curl), severity-grouped, credentials redacted by
  default (`--repro-creds` to show live tokens).
- ~~Suppression / baseline file (`possession.allowlist`) so re-runs only
  surface new findings.~~ **Shipped in v1.2.**

### Operational
- ~~Resume on interrupt (persist plan + completed variants to disk).~~
  **Shipped** (`--resume <dir>`): every completed response is checkpointed to an
  append-only `checkpoint.jsonl` as it lands; a re-run with the same dir skips
  already-completed variants and fires only the remainder. Crash-safe (torn tail
  lines are skipped) and detection-identical to an uninterrupted run.
- Replay-from-recording mode for offline re-evaluation without
  re-hitting the target.
- ASVS V9 (Self-Contained Tokens) control mapping once IDs are
  verified against the published v5.0.0 spec (Gate F — currently
  omitted intentionally).
- Branch protection / signed releases (post-v1.0 ops).

## v1.2 backlog (deferred from v1.1)

### Auth

- **SAML assertion mutators**: SAML is XML-DSIG — a genuinely separate
  effort from JWT. Signature stripping, assertion tamper, replay attacks.
  Requires a SAML-specific parser and signer.
- **Deep OAuth2/OIDC flows**: PKCE, device_code, implicit (deprecated but
  still common), state-parameter CSRF attacks, token leakage via redirect.
  The v1.1 OAuth2 step only covers client_credentials and refresh_token.
- **WebRTC signaling authz**: WebRTC offer/answer flows carry identity; the
  authz surface is different from REST APIs. Out of scope for v1.1.

### Detection

- **GraphQL authorization**: GraphQL introspection + field-level authz
  bypasses are a distinct problem (operation fragments, batching). Needs
  dedicated mutators and an endpoint-level dedup strategy.
- **ASVS V9 Self-Contained Token mapping**: Full V9 control IDs once the
  published v5.0.0 spec is verified stable (Gate F).
- **privesc to different resource class**: v1.1's comparative evaluator
  marks "different but still unauthorized resource" as enforced (D44
  limitation). A future evaluator mode using content-type or schema
  matching could detect this.

### Infrastructure

- **TUI dashboard**: Live per-endpoint finding counts during a scan.
- **Postman / OpenAPI input**: Additional input parsers beyond HAR + curl.
