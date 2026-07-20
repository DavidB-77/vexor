# Contributing to Vexor

Thanks for your interest in Vexor. This is currently a **single-maintainer
project**, so please set expectations accordingly: response times may be
slower than a foundation-backed project, and large unsolicited subsystem
rewrites should open an issue first so we can agree on direction before you
invest the time.

## Pull request style

- Prefer small, focused PRs over large ones — they're easier to review and
  easier to revert if something's wrong.
- Title in the imperative mood, no trailing period (e.g. "fix compute-budget
  rounding" not "Fixed a bug.").
- Describe the problem and the fix, not just the diff — reviewers (and future
  you) need the "why."

## Testing bar

Vexor doesn't claim a specific test-coverage percentage. What it does claim:

- **Consensus-affecting changes require a KAT** (known-answer-test) —
  differential tests that assert byte-exact output against a known-good
  reference. See `build.zig`'s `test-*` steps for the existing pattern.
- Changes touching bank_hash-affecting code paths should also pass an
  **offline golden-replay gate** where one is available (byte-identical bank
  hashes against the live cluster over a pinned slot window). If you're not
  sure whether your change qualifies, ask in the PR description and we'll
  figure it out together.
- Don't claim a coverage number that isn't actually measured.

## For protocol-behavior questions

If your change is matching specific Agave behavior, **cite the Agave source
file/line you're matching** in the PR description (and, ideally, as a
`PROVENANCE.md` entry — see that file for the format). This is exactly how
Vexor's existing parity story is maintained; treating it as a contribution
requirement rather than an internal-only practice keeps the provenance ledger
trustworthy as the project grows.

## Coding conventions

- `zig fmt` is mandatory — run `zig fmt .` before committing (or let
  `zig build fmt` do it, if wired up in your checkout).
- Avoid `.?` (optional unwrap) without a comment justifying why the value is
  guaranteed non-null at that point; prefer explicit error unions
  (`try`/`catch`) over asserting your way past a `null`/error case.
- Match the naming and layout conventions of the file/subsystem you're
  editing rather than introducing a new house style locally.

## What NOT to send

- Large unsolicited rewrites of a subsystem — open an issue first.
- Changes that alter consensus-affecting behavior without a KAT.
- Undeclared code copied or ported from other clients. Vexor **does** contain
  declared ports and carried upstream files (e.g. the Sig-derived
  `src/vex_crypto/ed25519/{avx512,generic}.zig` IFMA kernels and the
  Firedancer-derived SVM-core ports — see `NOTICE` and `PROVENANCE.md`);
  contributions touching those files must
  preserve their upstream attribution, and any *new* ported or adapted code
  must arrive with its own `PROVENANCE.md` row and license-compatible
  attribution. Vexor's crypto leaf and vote executor (voteforge) are
  deliberately independent — don't reintroduce upstream code dependencies
  there.

## Getting your PR merged

Draft PRs are welcome if you want early feedback before the change is
finished. Please respond to review comments rather than force-pushing over
them silently — it makes the review thread easier to follow.
