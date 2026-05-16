# Decisions

Architectural decisions for possession. Lock these in until explicitly
revisited.

| ID | Decision                                                      | Rationale |
|----|---------------------------------------------------------------|-----------|
| D1 | Single static binary, Go 1.26                                  | Easy distribution; one runtime; native concurrency for the future replay engine. |
| D2 | Subprocess-invokable: stable `--json` contract on `parse` (and later `scan`) | Pho3nix and other harnesses shell out rather than embed; keeps possession's license isolation clean. |
| D3 | HAR + curl as input formats                                   | HAR comes free from every browser devtools; curl is the lingua franca of API capture. Postman / OpenAPI deferred. |
| D4 | Path templating uses simple table-driven heuristics, not LLMs  | Deterministic, fast, debuggable, no external dependency. |
| D5 | Role matrix is YAML, validated up front, errors aggregated     | Users edit it directly; one run surfaces every problem. |
| D6 | Glob dialect is a tiny custom doublestar (see ARCHITECTURE.md) | Avoids `gobwas/glob` dep; covers `*`, `**`, `?` which is all we need for path scoping. |
| D7 | **License: AGPL-3.0-only** (override of the original packet)   | The original brief proposed MIT. The human explicitly overrode this and chose AGPL-3.0 for maximum copyleft protection. The AGPL network clause matters because possession may be reused inside SaaS products (e.g. Pho3nix). Per D2, downstream tools invoke possession as a subprocess, so they do NOT pick up AGPL obligations on their own source — only modifications to possession itself must be shared. This deliberately keeps Pho3nix's own code unaffected while protecting the tool. |
| D8  | v1.0 mutators: strip-auth, swap-identity, downgrade-role, drop-cookie, strip-token | Cover authn-bypass, IDOR / cross-user, privilege escalation, auth-dependency mapping, and token-vs-cookie enforcement. JWT mutators deferred to P4. |
| D9  | Replay-as-self is the baseline anchor                                   | The matrix is N identities (self included), not N−1 pairs. Replaying an identity as itself gives the comparison anchor for P3's detection evaluator. |
| D10 | Refresh-hook failure aborts that identity only                          | Variants for the failed identity are marked Inconclusive; loud warning logged; the run continues with other identities. A single credential outage must not invalidate the whole scan. |
| D11 | Variant cap 10000 default with deterministic generation order           | Bounded blast radius for accidentally-huge captures. Order: endpoints (method, pathTemplate) → representative sample (smallest ID) → mutator (declaration order) → identity (rank, name). Variant ID = sha256(epKey + mutator + identity + canonical_detail)[:16]. |
| D12 | Body size cap 5MB default                                               | P3 needs bodies in memory for similarity scoring; 5MB keeps that affordable. Larger bodies are truncated and Response.Truncated is set. |
| D13 | Refresh extraction selector is minimal dotted-path                      | Supports `$.a.b.c` and `$.a[0].b` only. No wildcards, filters, or recursive descent. Small surface area means small bug surface; full JSONPath is overkill for refresh hooks. |
| D14 | `scan` is self-contained                                                | Runs parse → normalize → scope filter → variant gen → replay in one process. Avoids re-piping `parse --json` into a separate replay tool. |
| D15 | Per-host token-bucket limiter + bounded concurrency + adaptive backoff  | Default 10 req/s/host, concurrency 5. 429/503 honors Retry-After then falls back to exponential 1s/2s/4s, up to 3 retries then errored. `--no-limit` requires a loud warning. Implemented with `golang.org/x/time/rate`. |
| D16 | Pluggable Evaluator interface; ship ComparativeEvaluator only for v1.0   | Realizes D4. One implementation now (Autorize-style: replay-as-self baseline vs replay-as-other comparison) with a clean interface so a future AssertionEvaluator (AuthMatrix-style declarative expectations) can drop in without rework. |
| D17 | Capture-owner attribution by credential match                            | For each CapturedRequest, match its auth components against the matrix identities (bearer/cookie/header/basic-username). First match wins; ties broken by (rank asc, name asc) with a recorded warning. No match falls back to highest-rank identity with attribution `fallback-highest-rank`. Reuses mutate's auth-component heuristic; no reimplementation. |
| D18 | Calibrated baseline — owner self-replay fired N times                    | Default `--baseline-samples 3`, clamped 1..10. Mean pairwise similarity sets per-endpoint stability. Endpoints with stability < `NoisyEndpointThreshold` (0.70) are flagged `noisy` and all verdicts capped at `suspected`. Per-endpoint `effThreshold = stability - SimilarityMargin`, clamped to `[MinThreshold, 1.0]`. N=1 skips calibration with `DefaultThreshold=0.90` and emits an endpoint note. Baseline-not-2xx ⇒ all variants on that endpoint are `inconclusive` with a loud per-endpoint warning. |
| D19 | Four verdicts: bypass, suspected, enforced, inconclusive                 | `bypass` = high-confidence finding. `suspected` = medium, needs review. `enforced` = authz is working, no finding. `inconclusive` = couldn't judge (refresh failure, transport error, baseline failure). Findings emitted only for `bypass` and `suspected`. |
| D20 | Optional per-identity `markers` in role matrix                           | Additive YAML schema: each identity may declare a `markers` list of strings that uniquely identify that identity's data (email, account id, display name). When present, `reflectedOwner` (variant body contains the *resource owner's* marker) is the strongest bypass signal; `reflectedActor` (variant body contains *only the acting identity's own* marker) is a strong benign signal. No markers ⇒ those signals are inert. |
| D21 | drop-cookie one-at-a-time; strip-token bearer vs csrf stays separate     | No combined `drop-all-cookies` or `drop-bearer-and-csrf` variants. Each variant isolates exactly one auth component so any resulting bypass attributes cleanly to that component. Combined cases inflate variant counts without adding diagnostic value. |
| D22 | ASVS v5.0.0 chapter V8 (Authorization) for control mapping               | NOT v4.0.x. IDs emitted in `v5.0.0-8.2.2` form. Fixed mapping by Finding.Class: authn-bypass⇒8.3.1, idor⇒8.2.2, idor-cross-tenant⇒8.4.1+8.2.2, privesc⇒8.2.1, auth-dependency⇒8.3.1. Suspected verdicts drop severity one notch (critical→high, high→medium, low→info). |
| D23 | All tuning constants live in internal/detect/tuning.go                   | Every threshold, weight, regex, volatile-key list, and ASVS map is declared in one file with comments marking them as calibration starting points. Zero magic numbers anywhere else under internal/detect/. Makes calibration a one-file diff. |

## Gate-D additive shape changes for Packet 3

Three additive changes to Packet-1/Packet-2 public types that Packet 3 introduces:

1. **model.Endpoint** gains `OwnerIdentity *Identity` and `OwnerAttribution string` fields (D17 attribution). Existing zero values remain valid.
2. **model.Response** gains `BodySHA256 string` field, always populated by the replay engine for any non-empty body. Existing consumers ignore the new field.
3. **model.Identity** gains `Markers []string` (D20). Optional; existing matrices that omit it parse identically.

Plus model.Variant.Mutation.Class is now populated (by the evaluator, not by Packet-2 mutators — keeps the mutator code frozen).

Plus model.Finding and model.Evidence are filled out per §5 of the Packet 3 brief.

## D7 override note (audit trail)

The original Packet 1 brief, under section D7, specified MIT. Before
implementation began, the project owner explicitly overrode this in
favor of AGPL-3.0-only. The override is captured here, in the LICENSE
file, in the README, and in the Packet 1 final report so that the
deviation is visible at every entry point.
