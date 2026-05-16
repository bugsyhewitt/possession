# possession

[![CI](https://github.com/bugsyhewitt/possession/actions/workflows/ci.yml/badge.svg)](https://github.com/bugsyhewitt/possession/actions/workflows/ci.yml)

A standalone CLI that replays a known-good authenticated HTTP request under
different identities and reports which auth components actually gate
access — surfacing IDOR, privilege escalation, and authn/authz bypass
bugs.

**Status:** v1.0 in development (Packets 1 + 2 of 4 complete — replay engine wired, detection still to come).

## What works today

Packets 1 + 2 ship the full input pipeline, deterministic variant
generation, and the replay engine. Detection scoring and reporting land in
Packets 3 and 4.

- `possession parse <input>` — parse a HAR or curl capture, normalize
  identifier-shaped path segments to `{id}`, deduplicate into endpoints,
  and print a table (or `--json`).
- `possession scan <input> --matrix <yaml>` — generate a deterministic
  variant plan (five v1.0 mutators) and replay it against the live
  target under per-host rate limiting, returning a JSON results document
  (no detection verdicts yet — that is Packet 3).
- `possession scan ... --dry-run` — print the variant plan and fire no
  requests. Use this to verify a matrix offline.
- `possession version` — print build info.

## Build and run

```sh
make build
./possession parse testdata/har/ecommerce.har
./possession scan testdata/har/ecommerce.har --matrix testdata/matrix/example.yaml --dry-run
./possession scan testdata/har/ecommerce.har --matrix testdata/matrix/example.yaml \
    --rate 5 --concurrency 3 --out results.json
./possession version
```

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md). The short version:

- **Packet 1:** parsing, normalization, config loading, CLI shell.
- **Packet 2 (this):** replay engine, five mutators, Tier-1 refresh hooks, per-host rate limiter, functional `scan` command.
- **Packet 3:** detection evaluator (IDOR, privesc, authn-bypass).
- **Packet 4:** JWT helpers, SARIF/HTML reporting, v1.0 release.

## License

[AGPL-3.0-only](LICENSE). See [docs/DECISIONS.md](docs/DECISIONS.md) for the
rationale behind the license choice.
