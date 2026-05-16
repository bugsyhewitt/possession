# Roadmap

possession ships in four packets, then a v1.0 release.

## Packet 1 — Foundation (this packet)

- HAR + curl parsers.
- Path templating + endpoint dedup.
- Role matrix loader + validator.
- CLI scaffold (cobra): `parse`, `scan` (stub), `version`.
- Test data, unit tests, CI.

## Packet 2 — Replay engine

- HTTP client with per-host rate limiting, bounded concurrency,
  configurable timeout, optional redirect following.
- Variant production: strip-auth, swap-identity-{cookies,headers,bearer,basic},
  swap-host (when scoped), method-tamper.
- Per-identity Tier-1 refresh hooks: issue refresh request, extract via
  body-json / body-regex / header / cookie, inject into subsequent replays.
- Response type with status, headers, body (size-capped), timing.
- Wire `scan` command end-to-end (still without detection — emit raw
  variant/response JSON).

## Packet 3 — Detection evaluator

- Implement `detect.Evaluator` (interface seam already in place).
- Heuristics: status-code-class match, content similarity, size delta,
  authn-bypass (variant succeeds with no auth), privesc (lower-rank
  identity gets a higher-rank-only resource), IDOR (peer identity gets
  another user's resource), auth-dependency.
- Findings with confidence + severity + ASVS control refs.

## Packet 4 — JWT + reporting + v1.0

- JWT helpers: alg=none, kid injection, weak-secret crack hooks,
  expiration / audience tampering.
- Reporters: human table (existing), JSON (existing), SARIF (for
  GitHub code scanning), HTML (for human consumption).
- Polish, docs, v1.0 release.

## v1.1 backlog

- Full stateful login flows (multi-step, CSRF chains).
- AuthMatrix-style declarative evaluator.
- SAML / OAuth flows.
- Deep JWT attacks (kid-SQLi, JKU/JWK spoofing).
- Postman + OpenAPI input formats.
