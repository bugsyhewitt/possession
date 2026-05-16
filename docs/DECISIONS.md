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

## D7 override note (audit trail)

The original Packet 1 brief, under section D7, specified MIT. Before
implementation began, the project owner explicitly overrode this in
favor of AGPL-3.0-only. The override is captured here, in the LICENSE
file, in the README, and in the Packet 1 final report so that the
deviation is visible at every entry point.
