# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `possession`, please report it
privately so we can address it before public disclosure.

**Email:** `robhillman207@gmail.com` with subject line `[possession-security]`.

Please include:

- A description of the vulnerability and its impact
- Steps to reproduce, ideally with a minimal proof-of-concept
- Affected version (`possession version`)
- Your name / handle if you would like credit in the fix

## Response Timeline

- **Acknowledgement:** within 7 days of report
- **Status update:** within 14 days
- **Fix or mitigation:** target 30 days, depending on complexity

We will coordinate a disclosure date with the reporter and credit
researchers who follow this responsible-disclosure process.

## Scope

`possession` is an authn/authz fuzzer — by design it issues unusual HTTP
requests. Vulnerabilities of interest include:

- Code execution via crafted input (HAR, curl, matrix YAML)
- Path traversal or other I/O escapes
- Credential leakage in logs or output
- Bypasses of the rate limiter or scope filter that could amplify the
  tool into a DoS against a victim

Out of scope:

- Behavior against targets the user explicitly opted into scanning
- Issues that require an attacker to already control the matrix YAML or
  binary (the tool is designed to be driven by the operator)
