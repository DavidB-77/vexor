# Security Policy

## Reporting a vulnerability

Please report security issues using [GitHub Security
Advisories](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository (**Security → Report a vulnerability**), rather than a
public issue. This lets us discuss and fix the problem before it's public.

There is currently no dedicated security-contact email; GitHub Security
Advisories is the only reporting channel.

## Response time

Best-effort. This is a single-maintainer project, so please expect a
response typically within a few days, not a formal SLA. We'll keep you
updated as we work through triage and a fix.

## Bug bounty

Vexor does not currently operate a paid bug-bounty program. Reports are
still welcome and will be triaged promptly. This may be revisited if/when
the project reaches production (`1.0.0`) status.

## Scope

Vexor is **testnet-only software**. Mainnet is explicitly out of scope,
because Vexor does not run there. In-scope reports are things like:

- Consensus-affecting bugs (bank_hash divergence, vote-safety violations).
- Memory-safety issues (out-of-bounds access, use-after-free) reachable from
  network input or on-chain data.
- Anything that would let a remote peer crash, hang, or take control of a
  Vexor validator process.

Out of scope: issues that only affect a local operator's own misconfiguration,
denial-of-service that requires resources disproportionate to the impact, and
findings from automated scanners without a demonstrated exploit path.
