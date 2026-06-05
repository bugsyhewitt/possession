# possession — Post-v0.1 Improvement Roadmap

**Generated:** 2026-05-26 by Worker (Rotation 2, research lap)
**Baseline:** possession v1.2 ships a standalone authz fuzzer that replays a known-good HTTP request under every identity in a role matrix (13 mutators: 5 classic + 8 JWT), a calibrated 10-branch comparative verdict ladder, an AuthMatrix-style assertion evaluator, Tier-1/Tier-2 refresh + OAuth2 flows, cross-tenant IDOR detection, human/json/sarif reporters, and an allowlist suppression system — with HAR + curl as its only input formats.

## Methodology

I read every Go source file under `internal/` and `cmd/`, the README, ROADMAP, CHANGELOG, go.mod, and the test suite (~27.5K LOC, build clean). I mapped possession's actual capability surface against the 2025/2026 authorization-testing landscape: Burp Autorize (identity-replay), AuthMatrix (role×request matrix + chain functionality), OWASP API BOLA testing guidance, and the dominant bug-bounty IDOR/BOLA workflow. Items are ranked by **bug-bounty-hunter value × inverse implementation complexity** — the highest slots go to capabilities hunters explicitly center their workflow on that possession structurally lacks today, weighted down by the engineering cost of adding them to the existing pure-mutator / comparative-evaluator architecture.

The single largest finding: possession swaps **identities** (replay alice's request with bob's token) but never swaps the **resource reference** (replay alice's token against bob's object ID). Identity-swap-only is the Autorize pattern; resource-ID swapping/enumeration is the canonical BOLA technique every hunter and the OWASP API testing guide describe as the heart of IDOR. possession is missing the most-requested half of its own niche.

---

## Item 0 — Mass-assignment / BOPLA mutator (`mass-assign`) — ✅ IMPLEMENTED (r17)

Shipped behind `--mass-assign`. Completes the third axis of an authz test: where
`swap-identity` attacks *who* the caller is and `swap-object` attacks *which
object* is referenced, `mass-assign` attacks *which properties* the caller may
set — Broken Object Property Level Authorization (OWASP API #3 / mass
assignment). For every captured request with a JSON **object** body, it keeps
the caller's own credentials and emits one variant per privileged property
(`admin`, `is_admin`, `isAdmin`, `role:admin`, `roles:[admin]`, `verified`),
*adding* a field the client should not be permitted to set. Properties the
request already sets are skipped (case-insensitive). Pure/deterministic like
every mutator (properties applied in sorted order); off by default because the
variants are write-shaped and mutate server state. Findings are class `privesc`,
severity HIGH. Requests without a JSON object body (GET, form-encoded, JSON
arrays, empty bodies) produce no variants. See `internal/mutate/mass_assign.go`
and `buildRegistry` in `internal/cli/scan.go`.

---

## Item 1 — Resource-reference swap mutator (`swap-object`) (Priority: CRITICAL) — ✅ IMPLEMENTED

### What
A new mutator that, instead of (or in addition to) swapping the *identity*, swaps the *object reference* in the request — path identifier segments (`/api/users/{id}`), query params (`?account_id=`), and JSON body fields — substituting another identity's known resource IDs while keeping the original caller's credentials. This is the textbook horizontal-IDOR / BOLA test: "can alice, using alice's own valid token, read bob's object?" possession currently cannot express this at all.

### How
- Add an optional `resources` block to each identity in the role matrix: `resources: { user_id: "1001", order_id: "5523" }` — the object IDs that identity legitimately owns.
- New `SwapObject` mutator in `internal/mutate/swap_object.go`. For each endpoint whose templated path contains a `{id}` placeholder (the `normalize.TemplatePath` machinery already locates these segments — reuse it), or whose captured query/body carries a key matching a known resource name, emit variants that substitute *another* identity's resource value while leaving the caller's credentials untouched.
- Finding class `idor` (already wired through `detect/tuning.go` ASVS V8.2.2, severity high). The existing comparative ladder works unchanged: owner-baseline is the legitimate caller fetching their own object; a 2xx with high body similarity to the *target's* baseline (or containing the target's marker) is the bypass.
- Register in `DefaultRegistry()` after the classic mutators. Pure/deterministic like every existing mutator, so `--dry-run` and the offline test corpus cover it for free.

### Effort estimate
Medium (180–250K). One mutator file, a matrix-schema field, and a baseline-cross-reference tweak in `scan.go` so a target identity's self-baseline is available for similarity comparison. Heaviest part is body/query field substitution; path substitution reuses existing template logic.

### Rationale
This is the #1 gap. Every IDOR write-up surveyed describes the same loop — log in as A, grab an object ID, replay with B's session — and possession automates only the credential half. Closing this turns possession from "an Autorize clone" into a tool that does what Autorize *and* AuthMatrix's single-user cross-resource mode do, in one CLI pass. Highest hunter value, and the architecture (pure mutators + comparative ladder + existing path templating) is already shaped to receive it.

---

## Item 2 — Sequential ID enumeration mutator (`enumerate-id`) (Priority: HIGH) — ✅ IMPLEMENTED

### What
For endpoints with a numeric or short-sequential identifier segment, fire the *same authenticated request* across a bounded range of neighboring IDs (e.g. captured `/orders/56789` → probe `56780..56799`) and report any that return owner-shaped 2xx responses the caller should not be able to see. This is the "try 50 random IDs, count the 200s" technique from the bug-bounty workflows — distinct from Item 1's known-owner swap because it finds objects you have no a-priori reference for.

### How
- New `EnumerateID` mutator gated behind a CLI flag (`--enumerate N`, default off) so it never fires accidentally — enumeration is rate-sensitive and noisy.
- Detect the numeric/short-id segment via the existing `normalize.IsIdentifierSegment` heuristics; generate ±N neighbors around the captured value (and a few random samples within a wider window).
- The per-host token-bucket limiter already in `internal/replay/limiter.go` governs request rate — reuse it; enumeration respects `--rate` with no new throttle code.
- Findings clustered: rather than N separate findings, emit one `idor` finding per endpoint with an evidence list of the hits, so a 200-ID sweep doesn't produce 200 allowlist entries.

### Effort estimate
Medium (150–200K). Mutator + one flag + a finding-aggregation step. The rate limiter and replay engine need no changes.

### Rationale
Hunters explicitly describe this as the move that surfaced "dozens of real users' records in minutes." It is the most mechanical, highest-signal IDOR test in the field and possession's rate-limited replay engine is ideally suited to run it safely. Gated-off-by-default keeps it from harming the secureapp Gate-E corpus guarantee. Slightly below Item 1 because it produces more noise and needs the clustering work to stay usable.

---

## Item 3 — OpenAPI 3.x input parser (Priority: HIGH) — ✅ IMPLEMENTED

### What
Accept an OpenAPI/Swagger 3.x spec as scan input, synthesizing one CapturedRequest per operation (method + path + example/required params) so possession can test an entire API surface without first capturing every call in a HAR.

### How
- New `internal/parse/openapi.go` returning `[]*model.CapturedRequest`, wired into `detectFormat`/`scan.go` alongside HAR and curl.
- Walk `paths` → operations; build the path with example values (or matrix-supplied resource IDs from Item 1) for `{param}` segments; pull required query/header params from the spec; synthesize a minimal JSON body from `requestBody` schema examples.
- Path templating is already a solved problem (`normalize.TemplatePath`) — OpenAPI path params map directly onto the `{id}` placeholder model, so dedup and owner attribution work unchanged.

### Effort estimate
Medium-High (250–300K). Schema-driven request synthesis is fiddly (refs, examples, allOf), but a pragmatic subset (paths + required params + example bodies) covers most real specs. No core-engine changes.

### Rationale
The 2026 BOLA workflow is API-first, and the bottleneck is *coverage* — you can only test endpoints you captured. An OpenAPI front door lets a hunter point possession at a published spec and test every documented operation, which is exactly where object-level authz gaps hide. Pairs directly with Items 1–2: synthesized endpoints feed the object-swap and enumeration mutators. Ranked below the mutators because it expands *reach* rather than adding a *detection capability* hunters can't otherwise get.

---

## Item 4 — Per-finding HTTP/curl reproduction in reporters (Priority: HIGH) — ✅ IMPLEMENTED (r36)

### What
For every finding, emit a ready-to-paste reproduction: the exact request that triggered the bypass (method, URL, headers with credentials redacted or templated) as both a raw HTTP block and a `curl` one-liner, plus the differential (owner baseline vs. variant response: status, size, marker hit).

### How
- The data already exists — `model.ResultEntry` carries the variant request and response, and `Finding` links to its variant. Add a `repro` block to the JSON reporter and a fenced curl/HTTP snippet to the human reporter.
- Redact credential values to `<bearer:alice>` placeholders by default; add `--repro-creds` to emit real tokens for local triage.
- Add a fourth reporter, **Markdown** (`--report markdown`), purpose-built for PR comments and bug-bounty submissions — the human reporter's content, GitHub-flavored, with collapsible repro blocks. The `report.New` switch and `Reporter` interface already make this a drop-in.

### Effort estimate
Low-Medium (120–180K). No new analysis; it's a presentation-layer feature over data already in `RunResult`. The Markdown reporter is a near-clone of the human reporter with different formatting.

### Rationale
A finding a hunter can't reproduce is a finding they can't submit. The most-repeated reporting lesson in the surveyed workflows is "impact-first, copy-paste PoC." Burp gives you the request inline; possession currently makes you reconstruct it from JSON. This is high value at low cost — pure leverage on existing data — and the Markdown reporter directly serves the PR-comment / report-writing use case the README already flags as backlog. Just below the detection items because it amplifies findings rather than producing new ones.

Shipped in two parts: `--report markdown` (PR-ready GFM, shipped r33) and `--report html`
(self-contained interactive report, shipped r34). Per r36 this item is fully complete: the
JSON reporter now embeds a `repro` object on every finding (`model.Finding.Repro`, populated
from `report.BuildRepro` while the in-memory `Variant` is live). The three repro fields —
`http` (raw HTTP/1.1 request block), `curl` (single-line shell command), and `differential`
(`baseline N → variant N · similarity S · ΔsizeD`) — appear in the `--report json` output
so downstream consumers and triage tooling can copy-paste reproductions without requiring a
markdown or HTML render pass. Credential values are redacted to `<bearer:identity>`
placeholders by default; `--repro-creds` emits live tokens.

---

## Item 5 — Automated marker harvesting from owner baselines (Priority: MEDIUM) — ✅ IMPLEMENTED (r9)

Shipped behind `--learn-markers`. The baseline self-replay bodies are grouped
per owning identity; `detect.HarvestMarkers` extracts candidate tokens (emails,
UUIDs, long digit runs, account-id-shaped alphanumerics) and promotes only those
that are **stable across all of an identity's samples** AND **unique to one
identity across the run**. Learned markers are merged (augment-only — operator
markers are never dropped) onto the matrix identities, every endpoint
`OwnerIdentity`, and every variant identity, then feed the existing
owner-reflection verdict branch unchanged. See `internal/detect/harvest.go` and
`learnMarkers` in `internal/cli/scan.go`.

### What
Today, IDOR detection's strongest signal — `markers` (an identity's unique data strings like email/account-id) — must be hand-entered per identity in the matrix. Add an opt-in pass that *learns* each identity's markers automatically by diffing their owner-baseline response bodies, so the highest-confidence IDOR branch fires without manual curation.

### How
- During the existing baseline self-replay phase (`buildBaselinePlan` already fetches N owner samples per endpoint), collect candidate unique tokens (emails, UUIDs, long digit runs, account-id-shaped strings) that appear stably across an identity's responses but differ between identities.
- Promote tokens that are unique-to-one-identity into that identity's effective `Markers` set for the run; feed them into the existing `ReflectedOwner`/`ReflectedActor` signals in `detect/evaluate.go` unchanged.
- Gate behind `--learn-markers`; never overwrite operator-supplied markers, only augment.

### Effort estimate
Medium (180–230K). The candidate-extraction heuristics and cross-identity uniqueness diffing are the work; the detection side already consumes markers, so no ladder changes.

### Rationale
Marker-based detection is possession's most decisive IDOR branch (near-certain bypass), but it's also the most operator-effort-intensive to set up — and setup friction is the #1 complaint about AuthMatrix in the survey. Automating it lowers the barrier to high-confidence findings and improves results on real targets where operators don't know every identity's unique strings up front. Medium rather than high because it's a confidence/usability multiplier on an existing capability, not a new attack class, and the heuristics carry false-positive risk that needs careful tuning against the corpus.

---

## Item 6 — GraphQL operation-level authz testing (Priority: MEDIUM) — ✅ IMPLEMENTED

### What
First-class GraphQL support: parse a `/graphql` POST capture (or introspection schema), generate per-operation and per-field variants, and run the identity-swap + object-swap ladder against individual queries/mutations rather than treating the whole POST as one opaque endpoint.

### How
- New `internal/parse/graphql.go` that recognizes a GraphQL POST body, splits it into named operations, and (optionally) consumes an introspection JSON to enumerate queries/mutations.
- A GraphQL-aware endpoint key (operation name, not just `POST /graphql`) so dedup and owner attribution work per-operation — the README's own v1.2 backlog flags "endpoint-level dedup strategy" as the hard part; this item delivers exactly that.
- Object-reference swap (Item 1) extends naturally to GraphQL variables (`{ getProfile(id: 101) }`), and alias-batching detection can flag amplified-exfil risk.

### Effort estimate
High (300K, likely a two-lap effort). GraphQL's resolver-level authz model and operation/field dedup are a genuinely separate problem from REST; depends on Item 1 (object-swap) being in place first.

### Rationale
GraphQL is the fastest-growing IDOR surface in 2026 — every surveyed guide stresses that route-level scanners miss field-resolver BOLA, and that batching turns one IDOR into mass exfiltration. High strategic value and a clear niche-defense move (no standalone CLI tool does GraphQL authz fuzzing well). Ranked sixth purely on complexity: it's the most expensive item, sequenced after the REST object-swap foundation it builds on. Worth committing to, but as a deliberate multi-lap effort rather than a quick win.

---

## Item 7 — Replay-from-recording mode (`--record` / `--replay`) (Priority: MEDIUM) — ✅ IMPLEMENTED (r10)

Shipped behind `--record <dir>` and `--replay <dir>`. A live scan with
`--record` writes every baseline and variant response, keyed by the
deterministic variant ID, to `<dir>/recording.json` (atomic temp-file + rename,
versioned schema). `--replay <dir>` skips the entire network phase — engine,
refresh, flows, rate limiter — and feeds the saved responses straight into the
detection loop in plan order, so calibration, owner attribution, and finding
generation run unchanged. Variant IDs are deterministic given the same
input + matrix, so replay matches index-for-index by ID; any variant absent
from the recording becomes an inconclusive placeholder (never a false bypass)
and is surfaced on stderr. `--record`/`--replay` are mutually exclusive, and
`--replay` rejects `--dry-run`. A base-url mismatch between recording and matrix
warns loudly. See `internal/record/` and the record/replay branch in
`internal/cli/scan.go`. Enables offline detection-threshold tuning, evaluator
A/B testing, and re-scanning a target you only had permission to hit once.

### What
Persist every variant request+response from a scan to disk, and add a mode that re-runs detection over a saved recording *without re-hitting the target*. Decouples the (rate-limited, permission-sensitive, slow) network phase from the (fast, iterable) detection phase.

### How
- `--record <dir>` writes the raw `RunResult.Results` (already a complete request/response log) to a deterministic on-disk format.
- `--replay <dir>` skips the replay engine entirely and feeds saved responses straight into the evaluator loop in `scan.go` — the detection code is already cleanly separated from replay, so this is mostly plumbing.
- Enables: tuning detection thresholds offline, A/B-testing evaluator changes, and re-scanning a target you only have permission to hit once.

### Effort estimate
Medium (150–200K). The request/response data is already aggregated in `RunResult`; the work is serialization + a replay-bypass branch in the scan pipeline.

### Rationale
Bug-bounty programs frequently rate-limit aggressively or grant narrow scan windows; the ability to capture once and iterate detection offline is a meaningful operational advantage and de-risks tuning the new mutators from Items 1–2 without burning target requests. It also makes the test corpus richer (record real responses as fixtures). Medium because it's an operational/workflow enabler rather than a finding-producing capability — valuable, but secondary to the detection and coverage items above it.

---

## Item 8 — SAML assertion tamper mutator (`--saml-tamper`) — ✅ IMPLEMENTED (r37)

Shipped behind `--saml-tamper`. Targets SAML SSO assertion-layer authentication
bypasses at the HTTP POST binding layer (OWASP SAML Security Cheat Sheet /
ASVS V3.5.3). For each captured request carrying a `SAMLResponse` form
parameter, emits two disjoint bypass variants while keeping the caller's own
session credentials untouched:

- **signature-strip** (`saml-tamper-sig-strip`): removes the `<ds:Signature>`
  block entirely. A service provider that grants access to an unsigned assertion
  has disabled signature verification — finding ID `POSSESSION-SAML-SIG-STRIP`,
  class `authn-bypass`, severity critical.

- **nameid-swap** (`saml-tamper-nameid-swap`): replaces the `<saml:NameID>`
  with a privileged target (`admin` / `administrator` / `root` / `superuser`)
  while preserving the original signature intact. A service provider that honours
  a NameID-swapped assertion reads identity outside the signed boundary — finding
  ID `POSSESSION-SAML-NAMEID-SWAP`, class `authn-bypass`, severity critical.

16 tests in `internal/mutate/saml_tamper_test.go`. Detection class wired via
`internal/detect/tuning.go` (`MutatorClass`). Off by default; enable with
`--saml-tamper`. See `CHANGELOG.md` and `internal/mutate/saml_tamper.go`.
