# Changelog

All notable changes to possession will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
