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
HAR/curl/OpenAPI/Postman/mitmproxy/Burp + role-matrix YAML
    → parse + normalize + scope filter
    → variant generation (identity-swap, object-swap, JWT, … × N identities)
    → replay engine (rate-limited, refresh-aware)
    → calibrated baseline + 10-branch verdict ladder
    → Findings (verdict, confidence + BOLA band, severity, ASVS V8 controls)
    → reporter (human | json | sarif | markdown | html)
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

`scan` and `parse` accept six capture formats, auto-detected by extension
and content (override with `--format har|curl|openapi|postman|mitmproxy|burp`):

| Format    | Detected by                              | Produces                          |
|-----------|------------------------------------------|-----------------------------------|
| `har`     | `.har`, or JSON with a `log` key         | one request per surviving entry   |
| `curl`    | leading `curl`                           | one request                       |
| `openapi` | `.yaml`/`.yml`, or JSON with an `openapi`/`swagger` key | one request per operation |
| `postman` | JSON with a `collection/v2` schema marker, `_postman_id`, or `info`+`item` | one request per request item |
| `mitmproxy` | `.jsonl`/`.ndjson`, a top-level JSON array, or a JSON flow object (`request` + `scheme`/`server_conn`, no `log`) | one request per HTTP flow |
| `burp`    | `.xml`, or a leading `<` (Burp `<items>` export) | one request per `<item>` |

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

### Postman Collection v2

Point possession at a Postman Collection v2.0/v2.1 export (the format the
Postman app produces) to test a saved request library without re-capturing it
as a HAR:

```bash
possession scan api.postman_collection.json \
    --matrix matrix.yaml \
    --dry-run
```

For each request item (folders are walked recursively) possession synthesizes a
replayable request:

- the URL is read from the structured `url` object (`protocol`/`host`/`path`/
  `query`) or a bare string URL; disabled query params are dropped;
- headers come from `request.header[]`, skipping entries marked `disabled`;
- the body is read for `raw` (JSON content type inferred from
  `options.raw.language`), `urlencoded`, and text `formdata` modes — file parts
  and `graphql`/`file` body modes synthesize no body;
- `{{variables}}` are resolved from the collection-, folder-, and request-level
  `variable[]` arrays, with the innermost scope winning; an unbound `{{name}}`
  is left literal so missing variables stay visible rather than silently blank.

Synthesized endpoints feed every mutator exactly like HAR/curl/OpenAPI
captures. Postman v1 collections are rejected with a hint to re-export as v2.1.

### mitmproxy

Point possession at a [mitmproxy](https://mitmproxy.org) JSON flow dump to
test traffic you captured with `mitmproxy`/`mitmdump` without re-exporting it
as a HAR. Two text serializations are accepted:

- a **JSON array** of flow objects — the shape the
  [`jsondump`](https://docs.mitmproxy.org/stable/addons-examples/#jsondump)
  addon writes when flows are collected into a list;
- **JSON Lines** (one flow object per line, `.jsonl`/`.ndjson`) — the streaming
  shape `mitmdump` json addons emit.

```bash
mitmdump -r capture.flows -s jsondump.py   # produce flows.jsonl
possession scan flows.jsonl \
    --matrix matrix.yaml \
    --dry-run
```

For each HTTP flow possession reconstructs a replayable request:

- the URL is rebuilt from the request's `scheme` + `host` + `port` + `path`
  (default ports `80`/`443` are elided; a non-default port is preserved); a
  flow that carries only an absolute-form `path` is parsed directly;
- headers are read from the `headers` list in either mitmproxy serialization —
  `["Name","Value"]` pairs or `{"name","value"}` objects; the `Cookie` header
  is split into individual cookies;
- the body is taken from the request's `content` (or `text`) field verbatim.

The same hygiene as the HAR parser applies — static assets (`.js`/`.css`/
images/fonts), `text/css`/`application/javascript` content types, and
well-known analytics hosts are dropped, so a mitmproxy dump and the equivalent
HAR dedup to the same endpoints. Non-HTTP flows (tcp/websocket/dns) are
skipped, and one malformed flow or JSON-Lines line is skipped without failing
the parse. mitmproxy's native binary `.flow`/`.mitm` files are **not** read
directly — export them as JSON (above) or as a HAR. Synthesized endpoints feed
every mutator exactly like HAR/curl captures.

### Burp Suite XML

possession is the standalone alternative to Burp Autorize — but most hunters
already capture their traffic *in* Burp. Point possession straight at a Burp
"Save items" / proxy-history XML export (right-click selected requests →
**Save items**, or the Proxy → HTTP history "Save selected items"), no
re-capture required:

```bash
possession scan history.xml \
    --matrix matrix.yaml \
    --dry-run
```

For each `<item>` possession reconstructs a replayable request:

- the **raw request** (the `<request>` element — `base64="true"` is decoded,
  otherwise the CDATA/text is taken verbatim) is authoritative for method,
  headers, cookies, and body; it is what actually went on the wire;
- the absolute URL is taken from the item's `<url>` field, or assembled from
  `<protocol>`/`<host>`/`<port>`/`<path>` (default ports `80`/`443` are elided;
  a non-default port is preserved);
- the `Cookie` header is split into individual cookies;
- an item with no usable `<request>` falls back to the structured
  `<method>`/`<url>` fields alone.

The same hygiene as the HAR parser applies — static assets, font/image/css/js
content types, and well-known analytics hosts are dropped, so a Burp export and
the equivalent HAR dedup to the same endpoints. One malformed item is skipped
without failing the parse. Synthesized endpoints feed every mutator exactly
like HAR/curl captures.

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

## Mass-assignment / BOPLA (`--mass-assign`)

`swap-identity` attacks *who* the caller is and `swap-object` attacks *which
object* the caller references. The `--mass-assign` flag attacks *which
properties* the caller is allowed to set — Broken Object Property Level
Authorization (OWASP API #3, the "mass assignment" / over-posting bug):

```bash
possession scan capture.har \
    --matrix matrix.yaml \
    --mass-assign
```

For every captured request that carries a JSON **object** body, it keeps the
caller's own credentials untouched and emits one variant per privileged
property, *adding* a field the client should not be permitted to set:

| Injected field | Value     |
|----------------|-----------|
| `admin`        | `true`    |
| `is_admin`     | `true`    |
| `isAdmin`      | `true`    |
| `role`         | `"admin"` |
| `roles`        | `["admin"]` |
| `verified`     | `true`    |

A property the request already sets is skipped (case-insensitive) — injecting
it would prove nothing. Findings are class `privesc`, severity **HIGH**: a 2xx
whose body reflects the smuggled property (e.g. the response now shows
`"role":"admin"`) means the server bound an attacker-controlled field onto its
model.

`--mass-assign` is **off by default**: unlike the read-shaped identity/object
swaps, these variants are write-shaped (they ride POST/PUT/PATCH) and mutate
server state, so they only fire when you opt in. Requests without a JSON object
body (GET, form-encoded, JSON arrays, empty bodies) produce no variants.

## XML External Entity / XXE (`--xxe`)

Where `--mass-assign` attacks *which properties* are bound, `--xxe` attacks *how
the request body itself is parsed*. For APIs that accept **XML** request bodies,
it tests whether the server's XML parser resolves external/internal entities —
the root cause of file disclosure, SSRF, and parser DoS (XXE):

```bash
possession scan capture.har \
    --matrix matrix.yaml \
    --xxe
```

For every captured request that carries an **XML** body (by `Content-Type` or
body shape), it keeps the caller's own credentials untouched and emits one
variant per technique, rewriting the body to carry a malicious `DOCTYPE`:

| Technique         | Payload                                                        | Detection |
|-------------------|---------------------------------------------------------------|-----------|
| `internal-entity` | `<!DOCTYPE … [<!ENTITY xxe "<canary>">]>` + `&xxe;` reference  | A unique per-endpoint **canary** is the entity value; if the response reflects that canary verbatim, the parser expanded the entity ⇒ XXE confirmed (class `xxe-injection`, severity **HIGH**, near-certain confidence). |
| `external-system` | `<!DOCTYPE … [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`     | No canary; judged by the comparative differential (a 2xx whose body differs from the entity-stripped baseline). |

Any pre-existing `DOCTYPE` in the body is stripped first (no double-DOCTYPE),
and an XML `Content-Type` is forced when the original lacked one (some parsers
only resolve entities for declared-XML bodies). The canary signal sits **outside
the comparative ladder** — XXE has no owner/actor baseline — so a reflected
canary is a decisive, false-positive-free bypass.

`--xxe` is **off by default**: the payloads are write-shaped against the parser
and the SYSTEM-entity variant deliberately probes for local-file / SSRF
resolution, so it only fires when you opt in. Non-XML bodies (JSON,
form-encoded, empty) and documents with only a self-closing root produce no
variants.

## GraphQL exposure (`--graphql`)

Where `--xxe` attacks *how an XML body is parsed*, `--graphql` attacks *what the
GraphQL layer exposes*. For endpoints that accept **GraphQL** POST bodies, it
runs the two highest-signal recon probes a hunter checks first, keeping the
caller's own credentials untouched:

```bash
possession scan capture.har \
    --matrix matrix.yaml \
    --graphql
```

A request is recognized as GraphQL when its `Content-Type` is
`application/graphql`, or when its JSON body carries a top-level `query` (or
`mutation`) string field. For each such request it emits one variant per
technique:

| Technique       | Probe                                                                 | Detection |
|-----------------|-----------------------------------------------------------------------|-----------|
| `introspection` | Replaces the operation with the canonical introspection query (`{ __schema { queryType … } }`). | If the response reflects the introspection schema markers (`__schema` **and** `queryType`/`__type`), the server answered introspection ⇒ **schema introspection is enabled** (information disclosure). Decisive, sits **outside the comparative ladder** (class `graphql-exposure`, severity **MEDIUM**, near-certain confidence). |
| `malformed`     | Sends a deliberately invalid GraphQL document.                        | No canary; judged by the comparative differential — a verbose error response (field suggestions, type hints, stack traces) that diverges from the owner baseline surfaces verbose-error leakage. |

The JSON transport is re-encoded to a minimal `{"query": …}` envelope (stale
`operationName`/`variables` referencing the old operation are dropped); the raw
`application/graphql` transport sends the probe document verbatim.

`--graphql` is **off by default**: although the probes are read-shaped (they
never run an operation you authored), they are still active reconnaissance
against the GraphQL layer, so they only fire when you opt in. Non-GraphQL
bodies (plain JSON without a `query` field, form-encoded, XML, empty) produce
no variants.

## Forbidden-response bypass (`--forbidden-bypass`)

The identity/object/property mutators all change *something the caller sends*.
`--forbidden-bypass` attacks *the access-control layer itself*: the case where
the caller's own credentials are correctly rejected for a protected resource
(the endpoint returns 401/403 or a deny redirect), and you want to know whether
that decision can be circumvented by **reshaping the request without changing
identity**. This is the canonical "4xx bypass" technique — every variant keeps
the caller's own credentials (it is emphatically *not* an identity swap; the
bug is "the same rejected caller slips past the gate").

```bash
possession scan capture.har \
    --matrix matrix.yaml \
    --forbidden-bypass
```

Authorization is frequently enforced by a fronting proxy / API gateway / WAF or
by a path-prefix rule in the app, and that layer can be desynchronised from the
upstream router. possession emits two families of variant, each as a separate
finding so a confirmed bypass is attributable to the precise reshape that
worked:

| Family | Techniques | Idea |
|--------|------------|------|
| Path mutation | `trailing-slash` (`/admin` → `/admin/`), `double-leading-slash` (`//admin`), `dot-segment` (`/./admin`), `matrix-param` (`/admin;a=b`), `traversal-semicolon` (`/admin/..;/admin`), `encoded-trailing-dot` (`/admin%2e`), `case-toggle` (`/Admin`) | An equivalent-but-different path encoding the access-control matcher compares literally (and lets through) while the application router still resolves it to the protected handler. The `%2e` payload is emitted single-encoded on the wire (never double-encoded). |
| Rewrite/override headers | `X-Original-URL`, `X-Rewrite-URL` (set to the request path), `X-Forwarded-For: 127.0.0.1` | A reverse proxy enforces access control on the request line but then honours a header-supplied URL/host (or trusts a localhost source IP) when handing the request to the backend. |

Detection rides the existing comparative ladder unchanged: the caller's own
baseline against the unmutated, protected endpoint is (expected to be) a denial;
a variant that returns an owner-shaped 2xx where the baseline was denied is the
bypass. Findings are class `authz-bypass` (ASVS V8.3.1 / V8.2.1, severity
**HIGH**).

`--forbidden-bypass` is **off by default**: the path-mutation and
header-injection payloads are active probes against the routing/access-control
layer (and the rewrite-header variants can reach internal-only paths on a
misconfigured proxy), so they only fire when you opt in. Requests with no URL
path produce no path variants.

## WebSocket upgrade hijack (`--ws-hijack`)

Every mutator above operates on ordinary HTTP request/response pairs.
`--ws-hijack` targets the one request applications most often forget to
authorize: the **HTTP → WebSocket upgrade handshake**. WebSocket endpoints are
frequently mounted behind a handshake that treats the upgrade as a transport
concern rather than a resource access, so the per-route authorization the REST
layer enforces is silently skipped — any caller who can reach the endpoint can
open a live channel they should not be able to.

possession recognizes a captured upgrade handshake by its RFC 6455 headers
(`Upgrade: websocket` + a `Connection` value containing `upgrade`, or the
presence of a `Sec-WebSocket-Key` header) and, **preserving those upgrade
headers**, replays it under modified identities:

```bash
possession scan capture.har \
    --matrix matrix.yaml \
    --ws-hijack
```

| Technique | What it sends | Idea |
|-----------|---------------|------|
| `strip-auth` | The handshake with **all credentials removed** (anonymous). | A `101 Switching Protocols` here means the WebSocket accepts unauthenticated clients (class `authn-bypass`). |
| `swap-identity` | One variant per matrix identity, carrying **that identity's credentials** in place of the caller's. | A `101` to an identity that should not reach this channel is a WebSocket authorization bypass (class `idor`, or `idor-cross-tenant` when the swapped identity's tenant differs from the captured owner's). |

Detection sits **outside the comparative ladder**: a WebSocket handshake has no
meaningful response body to diff, so the decisive, false-positive-free signal is
the response status. A `101 Switching Protocols` returned to a stripped or
swapped identity means the server completed the upgrade without enforcing
authorization ⇒ **bypass** (near-certain confidence). Any non-101 response
(including 401/403, a transport error, or a normal 200) means the handshake did
not complete under the modified identity ⇒ **enforced**. Because `101` is below
the 2xx success band, this branch runs ahead of the usual transport-error
short-circuit so a handshake success is never swallowed as an error.

`--ws-hijack` is **off by default**: attempting to open (or upgrade to) a live
WebSocket channel under a foreign or stripped identity is an active
access-control probe, so it only fires when you opt in. Requests that are not
WebSocket upgrade handshakes produce no variants.

## Anti-CSRF token bypass (`--csrf-header`)

`strip-token` removes a request's CSRF header to probe whether the server even
*depends* on it. `--csrf-header` does the inverse: it **forges or reflects** the
anti-CSRF token to probe whether the server's CSRF validation can be satisfied
with a value the caller controls. The bug being tested is the classic broken
double-submit-cookie / presence-only-check family — *"the same caller submits a
CSRF token the server should reject, and the request still succeeds."* A server
that issues per-session tokens and validates them server-side rejects all of
these; a server that merely checks `header == cookie`, *"a CSRF header is
present and non-empty"*, or that the header reflects the cookie is vulnerable to
cross-site request forgery.

Every variant keeps the **caller's own credentials** (no identity swap, no
token strip):

```bash
possession scan capture.har \
    --matrix matrix.yaml \
    --csrf-header
```

| Technique | When it fires | What it sends |
|-----------|---------------|---------------|
| `forged-double-submit` | A CSRF **header and a CSRF cookie** are both present. | Overwrites *both* with one identical attacker-chosen value. A naive `header == cookie` check still passes. |
| `reflect-cookie-to-header` | A CSRF **cookie** is present. | Copies the cookie's value verbatim into the CSRF header (the canonical `X-CSRF-Token` if no header exists). The textbook double-submit reflection an attacker who can plant the cookie abuses. |
| `inject-missing-header` | **No CSRF header** is present. | Injects `X-CSRF-Token` with a forged value, testing presence-only enforcement (the server accepts any non-empty token). |

A header- or cookie-name is recognised as CSRF-ish when it contains `csrf` or
`xsrf` (case-insensitive), matching the same heuristic `strip-token` uses.

Detection rides the **existing comparative ladder** unchanged: the caller's own
baseline is the legitimate request with its real CSRF token; a variant that
returns an owner-shaped 2xx with a forged or reflected token is the bypass
(class `authz-bypass`, ASVS V8.3.x). Like every mutator it is pure and
deterministic — the forged token is a constant and techniques are emitted in
sorted order — so `--dry-run` and the offline corpus cover it for free.

`--csrf-header` is **off by default**: forging an anti-CSRF token is an active
access-control probe, so it only fires when you opt in. A request with no CSRF
header *and* no CSRF cookie yields a single `inject-missing-header` variant; a
request with a CSRF header but no CSRF cookie yields no variants.

## HTTP verb / method-override bypass (`--method-override`)

Where `--forbidden-bypass` attacks *how the request path is matched* and
`--csrf-header` attacks *the anti-CSRF token*, `--method-override` attacks *which
HTTP verb the access-control layer evaluates* — the canonical "method bypass"
family every 403/401-bypass cheat-sheet lists alongside path mutation. The bug
being tested is *"the same rejected caller slips past the gate by changing the
verb."* A fronting proxy / API gateway frequently gates a specific method (e.g.
`deny DELETE /admin`, `allow GET only`) while the upstream framework is
method-agnostic or honours a method-override header — so the protected handler
runs under a verb the gateway never inspected.

Every variant keeps the **caller's own credentials** (no identity swap):

```bash
possession scan capture.har \
    --matrix matrix.yaml \
    --method-override
```

| Technique | What it sends |
|-----------|---------------|
| `header:X-HTTP-Method-Override` / `header:X-HTTP-Method` / `header:X-Method-Override` | Keeps the request-line verb unchanged but injects a method-override header naming a verb that **crosses the safe/unsafe boundary** (a safe GET/HEAD/OPTIONS request → `POST`; any write request → `GET`). Frameworks that honour the override header dispatch the overridden verb to the protected handler the gateway gated by request-line method. |
| `verb-swap:<VERB>` | Changes the actual request-line method to a sibling verb the gateway may not gate while the handler still serves it — e.g. `GET` → `HEAD`/`OPTIONS`/`POST`, a write → `GET`/`PUT`/`PATCH`. The original verb is never re-emitted (no no-op swap). |
| `case-toggle` | Flips the case of the verb (`GET` → `get`). A case-sensitive gateway matcher denies the differently-cased verb while a case-insensitive framework router still serves it. |

Detection rides the **existing comparative ladder** unchanged: the caller's own
baseline against the protected endpoint is (expected to be) a denial; a variant
that returns an owner-shaped 2xx where the baseline was denied is the bypass
(class `authz-bypass`, ASVS V8.3.x). Like every mutator it is pure and
deterministic — verbs are constants and techniques are emitted in sorted order —
so `--dry-run` and the offline corpus cover it for free.

`--method-override` is **off by default**: the verb-swap variants re-issue
requests under state-changing methods (POST/PUT/DELETE) and the override headers
can reach mutating handlers, so it only fires when you opt in — mirroring the
gating of `--forbidden-bypass`, `--csrf-header`, `--ws-hijack`, `--xxe`, and
`--mass-assign`.

## Host-header bypass (`--host-header`)

Where `--forbidden-bypass` attacks *how the request path is matched* and
`--method-override` attacks *which verb is evaluated*, `--host-header` attacks
*which host the access-control layer believes the request targets* — the
canonical "host-header injection" family. Many deployments route or authorize
from the `Host` (or a forwarded-host header a fronting proxy trusts):
virtual-host routing maps a host to an internal app, an API gateway gates an
`internal`/admin vhost behind a network ACL while serving the public host, a
reverse proxy forwards the client-supplied host straight to the backend, or an
app builds links / cache keys from the host. The bug being tested is *"the same
caller reaches a host-gated resource by lying about the host."*

Every variant keeps the **caller's own credentials** (no identity swap):

```bash
possession scan capture.har \
    --matrix matrix.yaml \
    --host-header
```

| Technique | What it sends |
|-----------|---------------|
| `host-override:<name>` | Replaces the **wire `Host`** with a spoofed value (`127.0.0.1`, `localhost`, `internal`) to reach an internal/loopback virtual host. possession promotes the spoofed `Host` onto the request's wire host (net/http otherwise ignores a `Host` entry in the header map). A no-op (spoof == the request's own host) is skipped. |
| `forwarded-host:<HEADER>` | Keeps the real `Host` on the request line and injects a forwarded-host override header — `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, or RFC 7239 `Forwarded: host=…`. A proxy/framework that trusts the forwarded host for routing, link generation, or cache keys is fooled into treating the request as targeting the spoofed host. These complement `--forbidden-bypass`'s rewrite headers (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For`), which spoof the *URL* and *client IP* but never the *host*. |

Detection rides the **existing comparative ladder** unchanged: the caller's own
baseline against the public host is the reference; a variant that returns an
owner-shaped 2xx where the baseline did not, under a spoofed host, is the bypass
(class `authz-bypass`, ASVS V8.3.x). Like every mutator it is pure and
deterministic — host values are constants and techniques are emitted in sorted
order — so `--dry-run` and the offline corpus cover it for free.

`--host-header` is **off by default**: the spoofed-host variants actively probe
the routing layer and can reach internal-only virtual hosts on a misconfigured
proxy, so it only fires when you opt in — mirroring the gating of
`--forbidden-bypass`, `--method-override`, `--csrf-header`, `--ws-hijack`,
`--xxe`, and `--mass-assign`.

## Cookie-value privilege tampering (`--cookie-tampering`)

Where `--host-header` attacks *which host the access-control layer trusts*,
`--cookie-tampering` attacks *which authorization state the app trusts inside a
cookie it set*. The classic broken-access-control / privilege-escalation pattern:
a server stores a client-readable authorization claim in a cookie value — a
`role=user` cookie it reads back to decide privilege, an `admin=0` flag, an
`is_admin=false` claim, or a base64-wrapped (unsigned) blob carrying the same —
and trusts it on the next request without re-deriving or signing it. The bug
being tested is *"the same caller gains privilege by editing a claim in their own
cookie."*

Where `--drop-cookie` *removes* an auth cookie and `--strip-token` strips the
bearer/CSRF side of the credential pair, `--cookie-tampering` keeps every cookie
present and instead **flips one privilege claim** inside an auth cookie's value
from its unprivileged form to its privileged one. Every variant keeps the
**caller's own credentials** (no identity swap):

```bash
possession scan capture.har \
    --matrix matrix.yaml \
    --cookie-tampering
```

| Technique | What it sends |
|-----------|---------------|
| `value-claim-flip:<cookie>:<claim>` | The auth-cookie value is a delimited claim payload (`role=user;tier=free`, `admin=0`, `is_admin=false`). The matching claim is rewritten in place to its privileged form (`role=admin`, `admin=1`, `is_admin=true`), every other byte preserved. Matching is token-bounded (`role=user` flips; `role=username` does not) and case-insensitive on key and value, preserving the original key casing. |
| `base64-claim-flip:<cookie>:<claim>` | The auth-cookie value base64-decodes (std / URL alphabet, padded or raw) to a printable string that itself carries such a claim. The decoded payload is flipped and **re-encoded in the same alphabet/padding** it arrived in, so a server that base64-decodes the cookie and trusts the inner claim is fooled. JWT-shaped values (three base64url segments with a JSON header) are left to the JWT mutators and skipped here. |

The built-in claim set is small and high-signal — `role` (`user`/`guest` → `admin`),
`admin` / `is_admin` / `isadmin` (`0`/`false` → `1`/`true`), and `verified`
(`false` → `true`) — paralleling the privileged-property set `--mass-assign`
injects, so the variant count stays bounded and the false-positive surface low.
Non-printable / encrypted cookie blobs and values with no matching claim emit
nothing.

Detection rides the **existing comparative ladder** unchanged: the caller's own
baseline against the untampered cookie is the reference; a variant that gains
elevated/owner-shaped access where the baseline did not is the bypass (class
`authz-bypass`, ASVS V8.3.x). Like every mutator it is pure and deterministic —
cookies are processed in name-sorted order and claims in a fixed order — so
`--dry-run` and the offline corpus cover it for free.

`--cookie-tampering` is **off by default**: the flipped-claim variants actively
assert elevated privilege against the access-control layer, so it only fires when
you opt in — mirroring the gating of `--host-header`, `--forbidden-bypass`,
`--method-override`, `--csrf-header`, `--ws-hijack`, `--xxe`, and `--mass-assign`.

## Trusted-header injection (`--header-injection`)

Where `--host-header` attacks *which host the access-control layer trusts* and
`--cookie-tampering` attacks *which authorization state the app trusts inside a
cookie*, `--header-injection` attacks *which trusted-proxy assertion the backend
believes about the caller*. The classic broken-access-control pattern: a backend
trusts request headers it assumes a fronting proxy (load balancer, API gateway,
WAF, auth proxy) populated — and makes a routing or authorization decision from
them — but the header is in fact reachable from the untrusted client edge. A
caller who sets the header directly is treated as though the trusted proxy
vouched for them. The bug being tested is *"the same caller gains access by
asserting a trusted-proxy header the edge should have stripped."*

Every variant keeps the **caller's own credentials** (no identity swap — the
caller stays themselves on the wire; they merely add a header a misconfigured
backend trusts):

```bash
possession scan capture.har \
    --matrix matrix.yaml \
    --header-injection
```

| Technique | What it sends |
|-----------|---------------|
| `client-ip-spoof:<header>` | A trusted-client-IP header (`X-Real-IP`, `X-Client-IP`, `X-Originating-IP`, `X-Remote-IP`, `X-Remote-Addr`) set to the loopback `127.0.0.1`. Apps that grant internal/admin access by trusting a proxy-supplied client IP (an "allow 127.0.0.1" / "internal network" rule) are fooled into treating the caller as originating inside the trust boundary. One variant per header for attribution. |
| `trusted-identity:<header>` | A proxy-set identity-assertion header (`X-Authenticated-User`, `X-Remote-User`, `X-Forwarded-User`, `X-User`, `X-WEBAUTH-USER`) naming a privileged principal (`admin`). Auth proxies (mod_auth, oauth2-proxy, SSO gateways) authenticate the caller and forward the established identity to the backend in such a header; a backend that trusts it without re-verifying lets a client who sets the header directly assert an arbitrary identity. One variant per header for attribution. |

The header set is deliberately **disjoint** from the headers `--forbidden-bypass`
(`X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`) and `--host-header`
(`Forwarded`, `X-Forwarded-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`,
`X-Host`) already inject — no double-coverage, clean per-mutator attribution.

This is **not** CRLF / HTTP response-splitting: the injected values are
well-formed header tokens (an IP, a username). `net/http` (and the replay engine
built on it) rejects raw CR/LF in header values, so a response-splitting payload
would never reach the wire and is intentionally out of scope. The technique here
is trusting a *legitimately-shaped* header the edge failed to strip.

Detection rides the **existing comparative ladder** unchanged: the caller's own
baseline against the request without the injected header is the reference; a
variant that gains owner-shaped access where the baseline did not is the bypass
(class `authz-bypass`, ASVS V8.3.x). Like every mutator it is pure and
deterministic — header names are constants emitted in sorted order — so
`--dry-run` and the offline corpus cover it for free.

`--header-injection` is **off by default**: the spoofed-trust variants actively
assert internal-origin / privileged identity against the access-control layer, so
it only fires when you opt in — mirroring the gating of `--cookie-tampering`,
`--host-header`, `--forbidden-bypass`, `--method-override`, `--csrf-header`,
`--ws-hijack`, `--xxe`, and `--mass-assign`.

## HTTP Parameter Pollution (`--parameter-pollution`)

Where `--swap-object` *replaces* a reference value and `--method-override`
attacks *which verb the gate evaluates*, `--parameter-pollution` attacks *which
copy of a duplicated parameter each layer of the stack reads*. The classic HPP
broken-access-control pattern: a request carries the same parameter name more
than once, and two components disagree on which occurrence is authoritative. A
fronting WAF / API gateway typically reads the **first** occurrence (or
concatenates), while the application framework reads a **different** one (PHP and
ASP.NET take the last; some Java stacks take the first; Express/Rails build an
array). By supplying the original (gate-passing) value once and an
attacker-chosen value in a second occurrence, an unsanitised or
privilege-altering value slips past the gate. The bug being tested is *"the same
caller slips a value past the gate because the WAF and the app read different
copies of the parameter."*

Every variant keeps the **caller's own credentials** (no identity swap — the
caller stays themselves; they merely duplicate a parameter the stack
mis-parses):

```bash
possession scan capture.har \
    --matrix matrix.yaml \
    --parameter-pollution
```

| Technique | What it sends |
|-----------|---------------|
| `query-pollute:append` | For each query parameter, a duplicate occurrence carrying the tamper value placed **after** the original (`?role=user&role=admin`). Exploits last-wins parsers (PHP, ASP.NET) while a first-wins gate still reads the original. One variant per parameter for attribution. |
| `query-pollute:prepend` | The same duplicate placed **before** the original (`?role=admin&role=user`). Exploits first-wins parsers while a last-wins gate still reads the original. One variant per parameter. |
| `body-pollute:append` / `body-pollute:prepend` | The identical duplication applied to an `application/x-www-form-urlencoded` request body — the second-most-common HPP surface. Two variants per body parameter. |

The original occurrence is **always preserved**, so a gate that reads the value
it expects still passes — the bypass rides entirely on the layer disagreement.
The injected tamper value defaults to the privilege-suggestive token `admin`. The
mutator is deliberately **disjoint** from `--swap-object`: swap-object
*substitutes* a value (one occurrence, changed); parameter-pollution
*duplicates* it (two occurrences, original retained). JSON and multipart bodies
are left untouched — duplicate keys there do not exhibit the cross-layer
disagreement HPP relies on.

Detection rides the **existing comparative ladder** unchanged: the caller's own
baseline against the un-polluted request is the reference; a variant that gains
owner-shaped access where the baseline did not is the bypass (class
`authz-bypass`, ASVS V8.3.x). Like every mutator it is pure and deterministic —
parameters are processed in sorted name order and the two orderings emit in a
fixed sequence — so `--dry-run` and the offline corpus cover it for free.

`--parameter-pollution` is **off by default**: the polluted variants re-issue
requests with altered parameter values that can reach mutating handlers, so it
only fires when you opt in — mirroring the gating of `--header-injection`,
`--cookie-tampering`, `--host-header`, `--forbidden-bypass`,
`--method-override`, `--csrf-header`, `--ws-hijack`, `--xxe`, and
`--mass-assign`.

## Origin/Referer spoofing (`--origin-spoof`)

Where `--csrf-header` attacks *the anti-CSRF token*, `--host-header` attacks
*which host the access-control layer believes the request targets*, and
`--header-injection` attacks *which trusted-proxy assertion the backend believes
about the caller*, `--origin-spoof` attacks *which originating site the
access-control layer believes the request came from* — the canonical
"Origin/Referer-validation bypass" family. Many backends and gateways enforce
state-change protection by validating the `Origin` (or `Referer`) header against
an allowlist — the standard OWASP-recommended CSRF defense — and just as
commonly implement the matcher wrong. The bug being tested is *"the same
caller's state-change is honoured when it claims to come from an untrusted (or
cleverly-shaped) origin a correct check would reject."*

Every variant keeps the **caller's own credentials** (no identity swap — the
caller stays themselves; they merely lie about *where the request came from*):

```bash
possession scan capture.har \
    --matrix matrix.yaml \
    --origin-spoof
```

| Technique | What it sends |
|-----------|---------------|
| `null-origin` | `Origin: null` with `Referer` dropped. Sandboxed iframes, `data:` / `javascript:` documents, redirect laundering, and meta-referrer policies all produce the literal origin `null`. Allowlists that special-case or fail-open on `null` (a very common mistake) accept it; a correct check refuses an unrecognised origin. |
| `cross-origin` | `Origin` and `Referer` set to a wholly-foreign attacker site (`https://attacker.example`). Tests the baseline failure: an app that does not validate Origin at all (or only checks presence) honours a blatantly cross-site request. |
| `suffix-confusion:prefix-match` | Crafted attacker host that *contains* the trusted host as a prefix label (`<host>.attacker.example`). Defeats a naive `Contains` / `HasPrefix` allowlist match against the request's own host. |
| `suffix-confusion:suffix-match` | Crafted attacker host embedding the trusted labels (`attacker-<host-with-dots-collapsed>.attacker.example`). Defeats a naive `HasSuffix` match. |
| `suffix-confusion:userinfo-confusion` | Authority of the form `<host>@attacker.example`. A parser splitting on the wrong delimiter mis-reads the trusted host while the real authority is `attacker.example`. |

The injected values are well-formed origin/URL tokens — this is **not**
CRLF/response-splitting (raw CR/LF in header values is rejected by `net/http`
before reaching the wire) and **not** anti-CSRF-token forgery (that is
`--csrf-header`). The technique here is lying about the *origin* of the
request.

Detection rides the **existing comparative ladder** unchanged: the caller's own
baseline against the request with its real Origin/Referer is the reference; a
variant that returns an owner-shaped 2xx (or otherwise differs from a denied
baseline) under a spoofed origin is the bypass (class `authz-bypass`, ASVS
V8.3.x). Like every mutator it is pure and deterministic — technique names and
crafted hosts derive from fixed templates and emit in sorted order — so
`--dry-run` and the offline corpus cover it for free.

`--origin-spoof` is **off by default**: the spoofed-origin variants re-issue
the (often state-changing) request asserting an untrusted/forged origin against
the access-control layer, so it only fires when you opt in — mirroring the
gating of `--parameter-pollution`, `--header-injection`, `--cookie-tampering`,
`--host-header`, `--forbidden-bypass`, `--method-override`, `--csrf-header`,
`--ws-hijack`, `--xxe`, and `--mass-assign`.

## Content-Type confusion (`--content-type-confusion`)

Where `--parameter-pollution` attacks *which copy of a duplicated parameter
each layer reads*, `--host-header` attacks *which host the access-control
layer believes the request targets*, and `--xxe` attacks *how the XML parser
resolves entities*, `--content-type-confusion` attacks *which body parser
each layer of the stack chooses* — the canonical Content-Type confusion /
parser-sniffing family. The body bytes are kept byte-identical; only the
`Content-Type` header is mutated. The bug being tested: a fronting WAF / API
gateway short-circuits its body-inspection rules ("this is text/plain, no
JSON to validate") while the handler still parses the body as JSON, or the
handler is wired to multiple parsers (JSON ↔ XML ↔ form) with different
authz middleware and is coerced onto the alternate path:

```
possession scan capture.har \
    --matrix matrix.yaml \
    --content-type-confusion
```

Three technique sets, one per body shape (deterministic sorted order):

- **JSON body** (declared `*json*` or sniffed `{`/`[`) — four variants:
  `as-form` (`application/x-www-form-urlencoded`), `as-text` (`text/plain`),
  `as-xml` (`application/xml`), and `strip-type` (drop the
  `Content-Type` header entirely so the receiver must sniff).
- **XML body** (declared `*xml*` or sniffed `<?xml` / leading tag) — two
  variants: `as-json` and `as-text`.
- **urlencoded form body** (declared `*x-www-form-urlencoded*`) — one
  variant: `as-json` (the highest-signal mismatch; urlencoded bodies are
  hard to sniff so the technique set is deliberately narrow).

Every variant keeps the caller's own credentials (`Identity == nil`) — this
is NOT an identity swap, the same caller's same body slips past the gate by
claiming a different format. No-op relabels (declared type already matches
the target) are skipped so the comparative ladder sees a real probe, not a
byte-identical baseline. The media-type comparison is parameter-insensitive,
so `application/json; charset=utf-8` and `application/json` compare equal.
Binary, multipart, and empty bodies produce no variants. Findings are class
`authz-bypass` (ASVS V8.3.x, severity HIGH).

`--content-type-confusion` is **off by default**: the relabelled variants
re-issue the request and can reach alternate-parser code paths with weaker
validation, so it only fires when you opt in — mirroring the gating of
`--origin-spoof`, `--parameter-pollution`, `--header-injection`,
`--cookie-tampering`, `--host-header`, `--forbidden-bypass`,
`--method-override`, `--csrf-header`, `--ws-hijack`, `--xxe`, and
`--mass-assign`.

## Web Cache Deception (`--cache-deception`)

Where `--content-type-confusion` attacks *which body parser each layer of
the stack chooses*, `--forbidden-bypass` attacks *how the path is matched
against a deny rule*, and `--host-header` attacks *which host the gate
believes the request targets*, `--cache-deception` attacks *which storage
tier sees the response* — the canonical Web Cache Deception family (Omer
Gil, BlackHat 2017; refreshed in the 2024–2026 BlackHat
Cache-Confusion / CDN-Confusion research). The URL is decorated with
cacheable file-extension shapes a fronting CDN / edge cache stores by
default; the application router strips, ignores, or normalises away the
decoration and still returns the caller's *personal* response. The cache
then serves that personal response under a public-looking key to every
later caller — including the unauthenticated internet:

```
possession scan capture.har \
    --matrix matrix.yaml \
    --cache-deception
```

Four technique shapes, each cross-producted with the cacheable extension
set (`css`, `js`, `png`, `jpg`, `ico`, `gif`, `svg` — the file types every
CDN's default rule stores by extension), emitted in deterministic
sorted-by-name order:

- **path-suffix** — `/api/me` → `/api/me/possession.css`. The Omer-Gil
  original shape; the cache sees a `.css` URL while route-globbing
  frameworks (Express, Rails, greedy Spring path variables) still hit the
  personal handler.
- **path-extension** — `/api/me` → `/api/me.css`. Frameworks that strip a
  known extension before routing (Rails `respond_to`, ASP.NET Core
  content-negotiation) still hit the personal handler, while the cache
  stores the `.css` URL.
- **semicolon-suffix** — `/api/me` → `/api/me;.css`. Tomcat / Spring strip
  the matrix-parameter segment when matching the handler; many caches
  keep the literal `;` in the key.
- **encoded-suffix** — `/api/me` → `/api/me%2fpossession.css`. A cache that
  URL-normalises before key-construction collapses `%2f` → `/` and sees a
  `.css` extension; a router that does NOT normalise treats the whole
  tail as one path segment and still routes to `/api/me` (the same
  gateway/handler URL-normalisation desync class `--forbidden-bypass`'s
  encoded path tricks exploit, applied post-path).

Every variant keeps the caller's own credentials (`Identity == nil`) —
this is NOT an identity swap; the same caller's same fetch is decorated
with a cacheable URL shape. Endpoints whose path already ends in a
cacheable extension are skipped (the response is already at a cacheable
URL by intent). On a trailing-slash path the `path-extension` and
`semicolon-suffix` shapes are skipped (they need a non-empty terminal
segment); `path-suffix` and `encoded-suffix` still fire. The mutation
detail records the original path and the decorated path so the operator
can re-fetch the decorated URL from a cold cache to confirm the leak.
Findings are class `authz-bypass` (ASVS V8.3.x, severity HIGH).

`--cache-deception` is **off by default**: the decorated variants reach
the caller's *own* personal endpoints by design (the bug being tested)
and therefore observably warm an upstream cache at the decorated URL on
the caller's behalf, so it only fires when you opt in — mirroring the
gating of `--content-type-confusion`, `--origin-spoof`,
`--parameter-pollution`, `--header-injection`, `--cookie-tampering`,
`--host-header`, `--forbidden-bypass`, `--method-override`,
`--csrf-header`, `--ws-hijack`, `--xxe`, and `--mass-assign`.

## Prototype pollution (`--prototype-pollution`)

Where `--mass-assign` attacks *which top-level properties the model
binds* (server-side BOPLA at the object layer — set `is_admin` on the
model instance), `--prototype-pollution` attacks *which properties every
object in the JavaScript runtime inherits* (set `is_admin` on
Object.prototype so every object answers `true` for it) — a distinct
authz-bypass class with a distinct fix that the Node.js ecosystem has
been re-discovering since CVE-2018-3721 (lodash), CVE-2019-10744
(lodash), CVE-2019-11358 (jQuery), and the 2024 Express qs / parseUrl
chains. A backend that deep-merges attacker-controlled JSON
(`_.merge`, `_.defaultsDeep`, `$.extend(true, …)`, hand-rolled recursive
Object.assign) walks past the `__proto__` / `constructor.prototype` /
`prototype` keys it should be guarding and writes onto Object.prototype;
every subsequent object the process creates inherits the polluted
property and a downstream authz check that reads `req.user.is_admin`
finds `true` even though the request never legitimately granted it:

```
possession scan capture.har \
    --matrix matrix.yaml \
    --prototype-pollution
```

For each privileged property in the canonical set (`admin`, `is_admin`,
`isAdmin`, `role`, `roles`, `verified` — the same surface
`--mass-assign` covers) and each of the three pollution vectors, a
separate variant is emitted in deterministic sorted-by-field then
sorted-by-vector order:

- **`__proto__`** — `{"__proto__": {"is_admin": true, …}}`. The direct,
  original CVE-2018-3721 vector — naive recursive-merge helpers follow
  the literal `__proto__` key into Object.prototype.
- **`constructor.prototype`** —
  `{"constructor": {"prototype": {"is_admin": true, …}}}`. Every
  object's `constructor` is a function whose `.prototype` IS
  Object.prototype, so this vector bypasses guards that block only the
  literal `__proto__` key.
- **`prototype`** — `{"prototype": {"is_admin": true, …}}`. The bare
  alias used by mongoose / handlebars / some hand-rolled merges that
  walk a key literally named `prototype` thinking it is just data — a
  third pathway documented across the npm-ecosystem CVE chain.

Every variant keeps the caller's own credentials (`Identity == nil`) and
preserves the caller's own top-level body fields verbatim; the pollution
payload is *added* alongside them, never replaces. Arrays, scalars, and
non-JSON bodies emit no variants — there is nothing for a JSON
deep-merge helper to recurse into. If the caller's own body already
contains a top-level `__proto__` / `constructor` / `prototype` key
(vanishingly rare in real traffic), that specific vector is skipped —
injecting a key the caller already sends proves nothing. Findings are
class `privesc`.

`--prototype-pollution` is **off by default**: the polluted JSON reaches
deep-merge code paths whose effect is *process-wide* (the entire Node.js
process answers the polluted property thereafter, including for every
concurrent user, until the runtime restarts), so it only fires when you
opt in — mirroring the gating of `--cache-deception`,
`--content-type-confusion`, `--origin-spoof`, `--parameter-pollution`,
`--header-injection`, `--cookie-tampering`, `--host-header`,
`--forbidden-bypass`, `--method-override`, `--csrf-header`,
`--ws-hijack`, `--xxe`, and `--mass-assign`.

## Directory / path traversal (`--path-traversal`)

Where `--forbidden-bypass` reshapes the request path so a fronting
proxy's deny-rule matcher desynchronises from the upstream router
(`/admin/..;/admin` resolves back to the SAME protected handler), and
`--swap-object` / `--enumerate` stay INSIDE the resource collection
(substitute another identity's known IDs, sweep neighbours), the
`--path-traversal` flag attacks *the resource scope boundary itself*:
the caller breaks OUT of the per-user / per-tenant subtree the route
prefix was supposed to confine them to, and reaches an OS-sensitive
file (`/etc/passwd`, `/proc/self/environ`, `windows/win.ini`) or a
sibling-tenant directory the application never intended to expose. This
is OWASP A01:2021 path traversal / Local File Inclusion at the
request-path layer — the same vuln class behind the long tail of
"directory traversal" advisories that every static-asset handler,
per-user file API, and legacy report-export endpoint keeps
re-discovering:

```
possession scan capture.har \
    --matrix matrix.yaml \
    --path-traversal
```

For each of six disjoint techniques and each of three high-signal
target files, a separate variant is emitted in deterministic
sorted-by-technique then sorted-by-target order. The trailing path
segment of the captured request is replaced with the traversal
payload; the base directory (everything up to and including the final
`/`) is preserved so the variant rides the route the caller
legitimately reached:

| Technique | Wire-form payload | What it defeats |
|---|---|---|
| `dot-dot-slash` | `../../../../../../etc/passwd` | The textbook literal traversal — handlers that concatenate the segment onto a base directory without canonicalisation (`filepath.Join` strips it; many language runtimes do not). |
| `dot-dot-encoded` | `..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd` | Middleware that filters the literal `../` but URL-decodes the path before the file lookup. RawPath keeps `%2f` un-double-encoded on the wire. |
| `dot-dot-double-encoded` | `..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd` | Gateway/handler boundaries that each URL-decode independently — one decode produces `..%2f` (the literal-`../` filter sees no match), the second decode produces the real traversal. |
| `nested-dot-dot` | `....//....//....//....//....//....//etc/passwd` | Hand-written sanitisers that strip a single `../` literal — after the filter removes one `../`, the remaining bytes collapse back into `../`. |
| `null-byte-suffix` | `../../../../../../etc/passwd%00` | Extension-allowlist filters in C-backed handlers — the high-level string comparison sees a (post-NUL) suffix and approves; `read(2)` / `open(2)` terminate the path at NUL. |
| `absolute-path` | `/etc/passwd` | Handlers that strip leading `../` segments but pass the rest through to a `File.open` / `fs.readFile` call that honours absolute paths. The payload has no `..` at all. |

Every variant keeps the caller's own credentials (`Identity == nil`) —
this is a same-caller scope-escape probe, not an identity swap. Root
or empty paths emit no variants (there is no trailing segment to
reshape). Findings are class `authz-bypass` (ASVS V12.3 — file &
resource control). The mutation `Detail` carries both the technique
and the target so the reporter (and any future repro-snippet
generator) can quote both the original URL and the traversal payload
the operator should re-fetch by hand to confirm the bytes returned
match the target file.

`--path-traversal` is **off by default**: the traversal payloads are
active probes that — on a vulnerable target — exfiltrate the contents
of OS-sensitive files, so it only fires when you opt in — mirroring
the gating of `--prototype-pollution`, `--cache-deception`,
`--content-type-confusion`, `--origin-spoof`, `--parameter-pollution`,
`--header-injection`, `--cookie-tampering`, `--host-header`,
`--forbidden-bypass`, `--method-override`, `--csrf-header`,
`--ws-hijack`, `--xxe`, and `--mass-assign`.

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

### `--report html`

A single **self-contained, offline-interactive** HTML document — no
external CSS/JS, no CDN links, no network fetches. Open it in any
browser, archive it, or attach it to a ticket and the styling and
interactivity travel with the file. Findings are grouped by severity
with colour-coded badges; each carries the metadata table, signal
trace, owner-baseline → variant **differential**, and a collapsible
**Reproduction** block (raw HTTP + `curl`), all built on native
`<details>`/`<summary>` so the report stays fully readable with
JavaScript disabled. A small inline script adds severity filtering as
progressive enhancement.

Credentials are **redacted by default** to identity-tagged
placeholders (`<bearer:bob>`); add `--repro-creds` for live tokens in
local triage. Finding data is HTML-escaped, so untrusted response
content can never inject markup.

```bash
possession scan capture.har \
    --matrix matrix.yaml \
    --report html \
    --out report.html
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

## Resume on interrupt (`--resume`)

Long scans against rate-limited targets can take a while, and an interruption —
Ctrl-C, a dropped connection, a quota wall, a host reboot — would otherwise
throw away every request already fired. `--resume` makes a scan restartable:
each completed response is checkpointed to disk as it lands, and re-running with
the same `--resume <dir>` skips every variant already recorded and fires only
the remainder.

```bash
# Start a long scan with a resume checkpoint.
possession scan capture.har \
    --matrix matrix.yaml \
    --resume runs/job-42
# ... interrupted partway through (Ctrl-C, network drop, quota) ...

# Re-run the SAME command. Already-completed variants are skipped;
# only the requests that never finished are fired.
possession scan capture.har \
    --matrix matrix.yaml \
    --resume runs/job-42
```

The checkpoint is an append-only `checkpoint.jsonl` written into the directory —
one line per completed response, flushed immediately. A crash mid-write can at
worst leave a torn final line, which is skipped on reload (that one variant is
simply re-fired), so a checkpoint can never poison a resume. Responses are keyed
by their deterministic variant ID, so a resumed-then-completed scan feeds
detection exactly the same inputs as an uninterrupted run.

| Flag             | Behaviour                                                                       |
|------------------|---------------------------------------------------------------------------------|
| `--resume <dir>` | Checkpoint each response to `<dir>/checkpoint.jsonl`; skip already-done variants on re-run |

`--resume` is mutually exclusive with `--replay` (replay fires no requests, so
there is nothing to resume). Combine `--resume` with `--record` to keep both a
crash-safe checkpoint and a final replayable recording.

## Statistical retry (`--retry-inconclusive`)

Real targets are flaky. A momentary 500, a single connection reset, or a brief
429 squall turns a variant into an `inconclusive` verdict — and an inconclusive
variant is a finding you never got to see. `--retry-inconclusive` re-issues each
transiently-failed variant **exactly once** after the main pass, before
detection runs, so a one-off failure stops masquerading as "we couldn't tell."

```bash
possession scan capture.har \
    --matrix matrix.yaml \
    --retry-inconclusive
```

A variant is re-issued when its response is a transport error, a `429`, or any
`5xx`. The retry goes through the same rate limiter, concurrency, refresh
injections, and body caps as the original request. If the retry succeeds, its
response replaces the failure; if it fails again, the original is preserved — a
flaky target can never make a result *worse* than the first attempt.

Refresh- and flow-setup failures are deliberately **not** retried: those are
per-identity setup failures that one variant re-issue cannot repair, so they
stay inconclusive rather than burning another request for nothing.

| Flag                   | Behaviour                                                                          |
|------------------------|------------------------------------------------------------------------------------|
| `--retry-inconclusive` | Re-issue each transiently-failed variant (transport error / 429 / 5xx) once before detection |

`--retry-inconclusive` has no effect under `--replay` (which fires no requests)
and the two are mutually exclusive. It composes with `--resume` and `--record`:
a recovered retry is checkpointed and recorded in place of the failure. The flag
costs extra requests against an already-struggling target, so it is off by
default and rate-sensitive — pair it with a conservative `--rate`.

## What ships in v1.0

- 9 mutators total: 5 classic (`strip-auth`, `swap-identity`,
  `downgrade-role`, `drop-cookie`, `strip-token`) + 4 JWT
  (`jwt-alg-none`, `jwt-sig-strip`, `jwt-claim-tamper`,
  `jwt-resign-weak-key`).
- HAR + curl + OpenAPI 3.x + Postman v2 + mitmproxy JSON + Burp XML input.
- Per-host token-bucket rate limiter, bounded concurrency, adaptive
  429/503 backoff, Tier-1 dynamic refresh hooks.
- Calibrated N-sample baseline, 10-branch verdict ladder, ASVS V8
  control mapping.
- Five reporters: human, json, sarif, markdown, html (markdown and
  html carry paste-ready per-finding HTTP/curl reproduction blocks; html
  is a single self-contained offline-interactive document).
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
