# Example: ecommerce capture

A minimal worked example showing what possession does end to end.

## Files

- `capture.har` — two HAR entries captured as `alice`: read an order
  and read her account profile.
- `matrix.yaml` — four-identity role matrix (anon + alice + bob +
  admin) with `markers` populated for IDOR detection.

## What this exercises

The two endpoints (`/api/orders/12345` and `/api/account`) are typical
IDOR-shaped surfaces. Running the scan replays alice's captures as
every other identity in the matrix and reports what the server lets
through.

## Run

NOTE: the target URL in `matrix.yaml` (`shop.example.test`) does not
resolve. To actually fire requests you need to point the matrix at a
real server you own and have permission to scan. To inspect the
generated plan without sending traffic:

```bash
possession scan capture.har --matrix matrix.yaml --dry-run
```

To run against your own server (after editing `target.base_url` and
the identity tokens):

```bash
# Human-readable terminal output (default)
possession scan capture.har --matrix matrix.yaml

# JSON for Pho3nix or other downstream tools
possession scan capture.har --matrix matrix.yaml --report json --out results.json

# SARIF for GitHub Code Scanning
possession scan capture.har --matrix matrix.yaml --report sarif --out results.sarif
```

## Exit codes

- `0`  — clean scan (no findings) or `--exit-zero` set
- `1`  — usage error (bad flag, missing file)
- `2`  — config error (invalid matrix YAML)
- `3`  — scan completed with at least one finding (suppressable with
         `--exit-zero` for CI pipelines that gate elsewhere)
