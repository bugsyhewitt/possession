# Architecture

## Pipeline

```
HAR/curl → []CapturedRequest → dedup → []Endpoint → []Variant → replay → []Response → Evaluator → []Finding → output
RoleMatrix YAML ─────────────────────┘
            ◄────── PACKET 1 BUILDS THIS FAR ──────►   P2     P2        P3            P4
```

Packet 1 delivers INPUT → NORMALIZE → []Endpoint, plus RoleMatrix
loading/validation, plus the CLI shell. The `parse` command exposes the
NORMALIZE output for downstream tools (e.g. Pho3nix, which invokes
possession as a subprocess and consumes `--json`).

## Package layout

```
possession/
├── cmd/possession/main.go      # thin entrypoint → cli.Execute()
├── internal/
│   ├── cli/                    # cobra commands (root, parse, scan-stub, version)
│   ├── model/                  # core domain types (Identity, RoleMatrix, …)
│   ├── parse/                  # HAR + curl parsers
│   ├── config/                 # role-matrix loader + validator + glob matcher
│   ├── normalize/              # path templating + endpoint dedup
│   ├── replay/                 # STUB (P2)
│   ├── detect/                 # STUB + Evaluator interface seam (P3)
│   ├── jwt/                    # STUB (P4)
│   └── report/                 # STUB (P4)
├── docs/                       # ARCHITECTURE, DECISIONS, ROADMAP
├── testdata/                   # har/, curl/, matrix/
└── .github/workflows/ci.yml
```

## Extension seams

These are the dotted lines along which Packets 2–4 cleanly plug in.

| Seam               | Type / package                           | Filled by  |
|--------------------|------------------------------------------|------------|
| Parser             | conceptual `Parse(io.Reader) ([]CapturedRequest, error)` — both HAR and curl already satisfy this shape | extensions |
| Mutator registry   | `model.Mutation` + future registry in `replay`/`jwt` | P2 / P4    |
| Evaluator          | `internal/detect.Evaluator` interface (declared, empty in P1) | P3 |
| Reporter           | conceptual `Render([]Finding, io.Writer) error` (P4) | P4         |
| RoleMatrix loading | `internal/config.LoadFile` already returns the domain type, so Replay and Detect just consume `model.RoleMatrix` | P2+ |

## Normalization heuristics

`internal/normalize.TemplatePath` collapses path segments that look like
machine-generated identifiers into `{id}`. Rules are table-driven:

| Rule           | Matches                                                |
|----------------|--------------------------------------------------------|
| all-digits     | `^[0-9]+$`                                             |
| uuid           | 8-4-4-4-12 hex with dashes                             |
| mongoid        | exactly 24 hex chars                                   |
| long-hex       | ≥16 hex chars                                          |
| base64url-ish  | ≥20 chars, `[A-Za-z0-9_-]`, mixed case AND/OR digits   |

Dictionary-word segments (e.g. `internationalization`) are deliberately
left alone — they are pure-lowercase and fail the base64url-ish rule.

## Glob dialect

`internal/config.MatchGlob` implements a minimal doublestar:

- `*` matches any run of non-slash characters
- `**` matches any run including slashes
- `?` matches a single non-slash character
- character classes (`[a-z]`) are NOT supported (keep it simple)

This is why we don't take a dependency on `gobwas/glob`.
