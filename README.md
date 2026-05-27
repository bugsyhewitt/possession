# possession

[![CI](https://github.com/bugsyhewitt/possession/actions/workflows/ci.yml/badge.svg)](https://github.com/bugsyhewitt/possession/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go Reference](https://pkg.go.dev/badge/github.com/bugsyhewitt/possession.svg)](https://pkg.go.dev/github.com/bugsyhewitt/possession)

**A standalone CLI authz fuzzer.** Replay a known-good authenticated
HTTP request under every identity in a role matrix, and report which
auth components actually gate access — surfacing IDOR, privilege
escalation, JWT bypasses, and authn-bypass bugs.

The gap it fills: a modern, maintained, standalone (not Burp-coupled)
authz fuzzer with proper detection scoring and SARIF output for CI. The
original Autorize / hodor pattern is right; the existing tooling around
it is either dead (NCC hodor, ~2014) or chained to Burp (Autorize,
AuthMatrix). possession ships the same workflow as a single Go binary
you can invoke from a Makefile, a pipeline, or a Pho3nix-style harness.

## What it does

Pipeline:

```
HAR/curl + role-matrix YAML
    → parse + normalize + scope filter
    → variant generation (identity-swap, object-swap, JWT, … × N identities)
    → replay engine (rate-limited, refresh-aware)
    → calibrated baseline + 10-branch verdict ladder
    → Findings (verdict, confidence, severity, ASVS V8 controls)
    → reporter (human | json | sarif)
```

possession swaps both halves of an access-control test. The `swap-identity`
mutator replays a request under *another identity's credentials* (the Autorize
pattern). The `swap-object` mutator does the inverse — it keeps the original
caller's credentials and substitutes *another identity's owned object
reference* into the path, query, and JSON body, expressing the canonical
horizontal-IDOR / BOLA test: "can alice, using alice's own token, read bob's
object?" Give each identity a `resources` map (e.g. `order_id: "12345"`) and
`swap-object` fires automatically.

## Install

### From source (Go 1.26+)

```bash
go install github.com/bugsyhewitt/possession/cmd/possession@v1.0.0
```

### From release artifacts

Download a prebuilt binary from the
[v1.0.0 release page](https://github.com/bugsyhewitt/possession/releases/tag/v1.0.0):

| Platform        | Artifact                                         |
|-----------------|--------------------------------------------------|
| linux/amd64     | `possession-v1.0.0-linux-amd64.tar.gz`           |
| linux/arm64     | `possession-v1.0.0-linux-arm64.tar.gz`           |
| darwin/amd64    | `possession-v1.0.0-darwin-amd64.tar.gz`          |
| darwin/arm64    | `possession-v1.0.0-darwin-arm64.tar.gz`          |
| windows/amd64   | `possession-v1.0.0-windows-amd64.zip`            |

Verify against `SHA256SUMS` in the same release before extracting.

## Worked example

```bash
# 1. Inspect the bundled example (no network traffic — dry run)
possession scan examples/ecommerce/capture.har \
    --matrix examples/ecommerce/matrix.yaml \
    --dry-run

# 2. Edit examples/ecommerce/matrix.yaml: set target.base_url to a
#    server you own + permission to scan, and replace the identity
#    bearer tokens with real values.

# 3. Run for real, rendered to your terminal
possession scan examples/ecommerce/capture.har \
    --matrix examples/ecommerce/matrix.yaml

# 4. Same scan, emitted as SARIF for GitHub Code Scanning
possession scan examples/ecommerce/capture.har \
    --matrix examples/ecommerce/matrix.yaml \
    --report sarif \
    --out results.sarif
```

See [`examples/ecommerce/README.md`](examples/ecommerce/README.md) for
a full walkthrough.

## Role matrix

The role matrix is YAML. Minimum viable shape:

```yaml
version: "1"
target:
  base_url: "https://api.example.com"
identities:
  - name: anon
    role: unauthenticated
    rank: 0
  - name: alice
    role: customer
    rank: 10
    creds:
      bearer: "alice-token"
    markers:
      - "alice@example.com"
    resources:
      order_id: "12345"
```

| Field                    | Type        | Notes                                                        |
|--------------------------|-------------|--------------------------------------------------------------|
| `version`                | string      | Currently must be `"1"`                                      |
| `target.base_url`        | string      | Used by reporters and as a sanity check on captured requests |
| `identities[].name`      | string      | Unique per matrix                                            |
| `identities[].rank`      | int         | 0 = unauth; higher = more privileged                         |
| `identities[].role`      | string      | Free-form label                                              |
| `identities[].creds`     | object      | Any of: `bearer`, `cookies`, `headers`, `basic`              |
| `identities[].markers`   | string list | Unique data strings (email, account ID) — best IDOR signal   |
| `identities[].resources` | string map  | Object IDs this identity owns (`user_id`, `order_id`, …); drives the `swap-object` mutator |
| `identities[].refresh`   | object      | Optional Tier-1 dynamic refresh hook                         |
| `scope.include`         | string list | Glob patterns (`/api/**`, `**/*.js`)                         |
| `scope.exclude`         | string list | Same syntax                                                  |
| `settings.rate_per_host`| float       | Default 10                                                   |
| `settings.concurrency`  | int         | Default 5                                                    |
| `settings.timeout`      | duration    | Default `30s`                                                |

Full annotated reference: [`testdata/matrix/example.yaml`](testdata/matrix/example.yaml).

## Output formats

### `--report human` (default)

ASCII summary suitable for terminals, log piping, and Markdown
quoting. Findings grouped by severity with a one-line signal trace per
finding; auth-dependency matrix shows which dropped components changed
access; typed endpoint notes for calibration corner cases.

### `--report json`

Deterministic 2-space-indented JSON. Byte-stable across consecutive
runs on the same input — safe for diffing and hashing. The shape is
the `model.RunResult` aggregate (see
[`internal/model/run.go`](internal/model/run.go)).

### `--report sarif`

SARIF 2.1.0, suitable for GitHub Code Scanning. One rule per finding
class (`idor`, `authn-bypass`, `privesc`, `auth-dependency`) with
ASVS v5.0.0 V8 controls in `helpUri` + property bag. One result per
finding with `partialFingerprints` keyed off `Finding.ID` for
dedupe across runs. Round-trips through `owenrumney/go-sarif/v3`.

## Exit codes

| Code | Meaning                                                                        |
|------|--------------------------------------------------------------------------------|
| 0    | Clean scan (no findings), or `--exit-zero` set                                 |
| 1    | Usage error (bad flag, missing file, unknown subcommand)                       |
| 2    | Config error (invalid matrix YAML, unparseable input)                          |
| 3    | Scan completed with at least one finding (suppressable with `--exit-zero`)     |

## Suppression (allowlist)

possession supports a YAML allowlist file that suppresses known findings
from output so that only **new** findings surface on re-runs. This is
particularly useful in CI pipelines where you want `exit 3` to only fire
on findings introduced by the current change.

```bash
# First run: scan and write all findings to possession.allowlist.
possession scan capture.har \
    --matrix matrix.yaml \
    --allowlist possession.allowlist \
    --update-allowlist

# Subsequent runs: suppress every finding already in the allowlist.
# Exit code 3 only fires if a NEW finding appears.
possession scan capture.har \
    --matrix matrix.yaml \
    --allowlist possession.allowlist
```

The allowlist file format:

```yaml
version: "1"
description: "Optional human-readable note."
entries:
  - id: "a1b2c3d4e5f60718"    # deterministic 16-hex Finding.ID
    added_at: "2026-05-26T18:00:00Z"
    added_by: "alice"
    note: "Accepted risk — internal-only endpoint."
```

| Flag                | Behaviour                                                                      |
|---------------------|--------------------------------------------------------------------------------|
| `--allowlist <f>`   | Load suppression file; suppress matching findings from reporters + exit code   |
| `--update-allowlist`| Merge current findings into `--allowlist` file (creates file if absent)       |

`--update-allowlist` requires `--allowlist`. Missing allowlist file is
treated as empty — no error — so CI can reference a file that doesn't
exist yet.

Finding IDs are stable (SHA256 of endpoint key + variant ID + class):
the same bug produces the same ID on every run against the same target.
Allowlist entries that no longer match any finding are silently ignored.

## What ships in v1.0

- 9 mutators total: 5 classic (`strip-auth`, `swap-identity`,
  `downgrade-role`, `drop-cookie`, `strip-token`) + 4 JWT
  (`jwt-alg-none`, `jwt-sig-strip`, `jwt-claim-tamper`,
  `jwt-resign-weak-key`).
- HAR + curl input.
- Per-host token-bucket rate limiter, bounded concurrency, adaptive
  429/503 backoff, Tier-1 dynamic refresh hooks.
- Calibrated N-sample baseline, 10-branch verdict ladder, ASVS V8
  control mapping.
- Three reporters: human, json, sarif.
- Integration corpus with Gate-E enforcement: secureapp scans MUST
  produce zero bypass findings.

## What does NOT ship in v1.0 (v1.1 backlog)

Deliberately deferred to keep v1.0 scope bounded. See
[`docs/ROADMAP.md`](docs/ROADMAP.md) for the full list.

- Deep JWT attacks (RS256→HS256 confusion, kid injection, JKU
  spoofing, HMAC cracking).
- Declarative AuthMatrix-style evaluator (the interface seam is in
  place).
- Stateful login flows (CSRF chains, multi-step OAuth).
- Postman / OpenAPI / mitmproxy input formats.
- HTML and Markdown reporters.
- ASVS V9 (Self-Contained Tokens) control mapping — currently
  omitted (Gate F: not inventing control IDs we can't verify).

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — pipeline + package
  layout
- [`docs/DECISIONS.md`](docs/DECISIONS.md) — architectural decisions
  (D1–D32)
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — v1.1 backlog
- [`CHANGELOG.md`](CHANGELOG.md) — release notes
- [`SECURITY.md`](SECURITY.md) — vulnerability disclosure

## License

[AGPL-3.0-only](LICENSE). The AGPL network clause matters because
possession may be reused inside SaaS products. Per the architectural
contract, downstream tools invoke possession as a subprocess (D2), so
they do not pick up AGPL obligations on their own source — only
modifications to possession itself must be shared.
