# Changelog

All notable changes to possession will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
