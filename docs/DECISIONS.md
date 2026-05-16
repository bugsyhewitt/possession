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

## D7 override note (audit trail)

The original Packet 1 brief, under section D7, specified MIT. Before
implementation began, the project owner explicitly overrode this in
favor of AGPL-3.0-only. The override is captured here, in the LICENSE
file, in the README, and in the Packet 1 final report so that the
deviation is visible at every entry point.
