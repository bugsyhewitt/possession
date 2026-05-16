# possession

[![CI](https://github.com/bugsyhewitt/possession/actions/workflows/ci.yml/badge.svg)](https://github.com/bugsyhewitt/possession/actions/workflows/ci.yml)

A standalone CLI that replays a known-good authenticated HTTP request under
different identities and reports which auth components actually gate
access — surfacing IDOR, privilege escalation, and authn/authz bypass
bugs.

**Status:** v1.0 in development (Packet 1 of 4 complete — foundation only).

## What works today

Packet 1 ships the input pipeline and CLI scaffold. Replay, detection,
and reporting land in later packets.

- `possession parse <input>` — parse a HAR or curl capture, normalize
  identifier-shaped path segments to `{id}`, deduplicate into endpoints,
  and print a table (or `--json`).
- `possession version` — print build info.
- `possession scan` — stub; prints "not implemented (Packet 2)" and
  exits non-zero.

## Build and run

```sh
make build
./possession parse testdata/har/ecommerce.har
./possession parse testdata/har/ecommerce.har --json
./possession parse testdata/curl/sample.txt --format curl
./possession version
```

Optionally pass a role-matrix to filter endpoints by scope:

```sh
./possession parse testdata/har/ecommerce.har --scope testdata/matrix/example.yaml
```

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md). The short version:

- **Packet 1 (this):** parsing, normalization, config loading, CLI shell.
- **Packet 2:** replay engine (rate limiting, concurrency, Tier-1 refresh hooks).
- **Packet 3:** detection evaluator (IDOR, privesc, authn-bypass).
- **Packet 4:** JWT helpers, SARIF/HTML reporting, v1.0 release.

## License

[AGPL-3.0-only](LICENSE). See [docs/DECISIONS.md](docs/DECISIONS.md) for the
rationale behind the license choice.
