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
HAR/curl/OpenAPI + role-matrix YAML
    → parse + normalize + scope filter
    → variant generation (identity-swap, object-swap, JWT, … × N identities)
    → replay engine (rate-limited, refresh-aware)
    → calibrated baseline + 10-branch verdict ladder
    → Findings (verdict, confidence + BOLA band, severity, ASVS V8 controls)
    → reporter (human | json | sarif | markdown)
```

possession swaps both halves of an access-control test. The `swap-identity`
mutator replays a request under *another identity's credentials* (the Autorize
pattern). The `swap-object` mutator does the inverse — it keeps the original
caller's credentials and substitutes *another identity's owned object
reference* into the path, query, and JSON body, expressing the canonical
horizontal-IDOR / BOLA test: "can alice, using alice's own token, read bob's
object?" Give each identity a `resources` map (e.g. `order_id: "12345"`) and
`swap-object` fires automatically.

The optional `--jwt-attack` mutator goes a step further and attacks the token
itself — forging `alg:none` and blank-secret JWTs to probe for verifier
misconfigurations. See [Token-level JWT attacks](#token-level-jwt-attacks---jwt-attack).

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

## Input formats

`scan` and `parse` accept three capture formats, auto-detected by extension
and content (override with `--format har|curl|openapi`):

| Format    | Detected by                              | Produces                          |
|-----------|------------------------------------------|-----------------------------------|
| `har`     | `.har`, or JSON without an `openapi` key | one request per surviving entry   |
| `curl`    | leading `curl`                           | one request                       |
| `openapi` | `.yaml`/`.yml`, or JSON with an `openapi`/`swagger` key | one request per operation |

### OpenAPI 3.x

Point possession at a published OpenAPI 3.x spec (JSON or YAML) to test an
entire documented API surface without capturing every call by hand:

```bash
possession scan api/openapi.yaml \
    --matrix matrix.yaml \
    --dry-run
```

For each operation (`method` + `path`) possession synthesizes a replayable
request:

- the first `servers[]` URL (with variable defaults substituted) is the base;
  specs without a `servers` block yield relative paths;
- `{param}` path segments are filled from the parameter's
  `example`/`examples`/`schema.example`/`default`/`enum` value, falling back to
  `1` for id-shaped names so the URL stays replayable and normalizes back to
  `{id}`;
- required query and header parameters are added with their example values;
- a minimal JSON request body is synthesized from the `requestBody` schema's
  example, or from `properties` (local `$ref` and shallow `allOf` are
  resolved).

This is a pragmatic subset — external `$ref`s and full `oneOf`/`anyOf`
composition are not evaluated — but it covers the paths + required params +
example bodies that most real specs carry. Synthesized endpoints feed every
mutator, including `swap-object`, exactly like HAR/curl captures.

## Token-level JWT attacks (`--jwt-attack`)

possession's default mutators attack *who* a token claims to be (identity
swap, claim tampering). The `--jwt-attack` flag adds a mutator that attacks
the *token itself* — the two most common JWT verification misconfigurations:

```bash
possession scan capture.har \
    --matrix matrix.yaml \
    --jwt-attack
```

For every captured `Authorization: Bearer <jwt>` (and any auth header,
auth cookie, or JSON body token field that decodes as a JWT), it forges two
auth-bypass variants:

| Variant      | Finding ID                     | What it sends                                                              |
|--------------|--------------------------------|---------------------------------------------------------------------------|
| `alg:none`   | `POSSESSION-JWT-NONE`          | header rewritten to `{"alg":"none","typ":"JWT"}`, signature dropped (`<header>.<payload>.`) |
| blank-secret | `POSSESSION-JWT-BLANK-SECRET`  | original claims re-signed with HS256 using an **empty string** as the HMAC key |

Both findings are class `authn-bypass`, severity **HIGH**. A 2xx that
matches the owner baseline means the verifier accepted a token an attacker
can forge with no knowledge of the real signing key.

`--jwt-attack` is **off by default**: forging tokens is noisier than
replaying real ones, so it is opt-in. No external JWT library is used — the
tokens are constructed by base64url-decoding the captured header/payload,
re-encoding, and (for blank-secret) HMAC-signing with `""`.

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

### Learning markers automatically (`--learn-markers`)

`markers` are possession's most decisive IDOR signal — a variant response that
echoes the resource **owner's** unique data string (email, account ID, UUID) is
a near-certain bypass. Hand-curating them per identity is the highest-friction
part of writing a matrix, and on a real target you often don't know every
identity's unique strings up front.

`--learn-markers` learns them for you. During the owner-baseline phase (the same
self-replay possession already runs to calibrate each endpoint), it extracts
high-signal candidate tokens — emails, UUIDs, long digit runs, and
account-id-shaped alphanumerics — from each identity's baseline responses, then
keeps only the tokens that are:

- **stable** — present in *every* one of that identity's baseline samples
  (per-request nonces and timestamps are discarded), and
- **unique** — present for exactly *one* identity across the whole run (shared
  API-version strings, CSRF field names, etc. are discarded).

Surviving tokens are merged into that identity's effective marker set for the
run and feed the existing owner-reflection verdict branch unchanged.

```sh
possession scan capture.har --matrix matrix.yaml --learn-markers
# stderr: learned 3 marker(s) from owner baselines: alice+2, bob+1
```

It is **augment-only and off by default**: operator-supplied `markers` are always
preserved and never overridden — learning only *adds* markers you didn't list.
Because the candidate heuristics carry some false-positive risk, the flag is
opt-in; for fully reproducible/curated runs, supply markers in the matrix instead.

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

### `--report markdown`

GitHub-flavored Markdown built for PR comments and bug-bounty
submissions. Impact-first: a summary header, then one section per
finding (ordered by severity) with an at-a-glance metadata table, the
signal trace, the owner-baseline → variant **differential**, and a
collapsible **Reproduction** block carrying the exact mutated request
as both a raw HTTP block and a `curl` one-liner — paste-ready, no
reconstruction from JSON required.

Credential values (`Authorization`, `Cookie`, `X-Api-Key`, …) are
**redacted by default** to identity-tagged placeholders like
`<bearer:bob>`, so a report is safe to paste publicly. Add
`--repro-creds` to emit live tokens for local triage:

```bash
possession scan capture.har \
    --matrix matrix.yaml \
    --report markdown \
    --out report.md
```

## Exit codes

| Code | Meaning                                                                        |
|------|--------------------------------------------------------------------------------|
| 0    | Clean scan (no findings), or `--exit-zero` set                                 |
| 1    | Usage error (bad flag, missing file, unknown subcommand)                       |
| 2    | Config error (invalid matrix YAML, unparseable input)                          |
| 3    | Scan completed with at least one finding (suppressable with `--exit-zero`)     |

## BOLA confidence band

Every finding carries a numeric `confidence` (0–1, "how likely is this a
real bypass?") **and** a categorical `confidence_band` that answers the
operator-facing question: *is this a true BOLA, or just a 2xx error
wrapper?*

The single most common authz false positive is an API that returns
`200 OK` with an error body (`{"error":"forbidden"}`) instead of a proper
`403`. A naive "2xx ⇒ finding" scanner reports these as bypasses. possession
instead grades each finding by how closely the variant's response body
resembles the resource **owner's** baseline response:

| Band     | Meaning                                                                                   |
|----------|-------------------------------------------------------------------------------------------|
| `high`   | Body near-identical to the owner's resource (or owner marker reflected) — **true BOLA**.  |
| `medium` | Body partially resembles the owner's resource — plausible bypass, verify.                 |
| `low`    | Body diverges from the owner baseline despite a 2xx — **likely an error wrapper**.        |

The band is derived from both the numeric confidence and the body
similarity, so a high-confidence verdict on a divergent body is still
capped at `low`. A decisive owner-marker reflection (the owner's unique
data literally present in the body) always qualifies for `high`, even when
the surrounding body differs.

In the human report the band is its own `BAND` column in the findings
table; in JSON it is the `confidence_band` field; in SARIF it is the
`confidence_band` property. Sort or filter on it to triage the true BOLAs
first and push the 2xx-error-wrapper noise to the bottom.

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

## Record &amp; replay (`--record` / `--replay`)

The network phase of a scan is rate-limited, permission-sensitive, and slow;
detection tuning is fast and iterative. `--record` decouples the two by saving
every baseline and variant response to disk, and `--replay` re-runs detection
over that recording **without firing a single request**.

```bash
# Capture once: scan the live target and persist every response.
possession scan capture.har \
    --matrix matrix.yaml \
    --record runs/2026-05-28

# Iterate offline: re-run detection against the saved recording. No network.
# Tweak --min-confidence, --evaluator, markers, etc. and re-run freely.
possession scan capture.har \
    --matrix matrix.yaml \
    --replay runs/2026-05-28 \
    --min-confidence 0.7
```

The recording is a single versioned `recording.json` written into the directory
(atomically, so a crash never leaves a half-written file). Responses are keyed
by their deterministic variant ID, so a replay regenerates the scan plan from
the same input + matrix and matches saved responses index-for-index — endpoint
attribution, calibration, and finding generation are byte-for-byte identical to
the live run.

| Flag             | Behaviour                                                                       |
|------------------|---------------------------------------------------------------------------------|
| `--record <dir>` | Persist every baseline + variant response to `<dir>/recording.json`             |
| `--replay <dir>` | Re-run detection over a saved recording; fire NO network requests               |

`--record` and `--replay` are mutually exclusive, and `--replay` cannot combine
with `--dry-run`. A variant present in this run but absent from the recording
(because the recording was made with a different input/matrix) is treated as
inconclusive — never a false bypass — and reported on stderr. A base-url
mismatch between the recording and the matrix target warns loudly.

This enables: tuning detection thresholds offline, A/B-testing evaluator
changes, and re-scanning a target you only have permission to hit once.

## What ships in v1.0

- 9 mutators total: 5 classic (`strip-auth`, `swap-identity`,
  `downgrade-role`, `drop-cookie`, `strip-token`) + 4 JWT
  (`jwt-alg-none`, `jwt-sig-strip`, `jwt-claim-tamper`,
  `jwt-resign-weak-key`).
- HAR + curl + OpenAPI 3.x input.
- Per-host token-bucket rate limiter, bounded concurrency, adaptive
  429/503 backoff, Tier-1 dynamic refresh hooks.
- Calibrated N-sample baseline, 10-branch verdict ladder, ASVS V8
  control mapping.
- Four reporters: human, json, sarif, markdown (markdown carries
  paste-ready per-finding HTTP/curl reproduction blocks).
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
- Postman / mitmproxy input formats.
- HTML reporter (the Markdown reporter shipped post-v0.1).
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
