#!/bin/bash
# check-single-ladder.sh — ANTI-DRIFT GUARD: there must be exactly ONE program-id dispatch ladder.
#
# ── What this defends against ────────────────────────────────────────────────────────────────────
# Vexor shipped empty blocks for a long time because production and replay had SEPARATE executors.
# Replay ran the full per-instruction ladder; production ran a mini-executor that understood only
# System discriminants 0 and 2, so a VOTE was never "processed" and never got packed. Fixing the
# instance (routing production through the real executor) does not close the CLASS — nothing stopped
# someone from adding a third reduced router next time a path needed "just a little" execution.
#
# Both gold standards keep ONE executor. Agave 4.2's consumer.rs (non-vote) and vote_worker.rs (vote)
# both bottom out in Bank::load_and_execute_transactions, the identical function replay reaches.
# Firedancer splits execrp/execle across separate TILES on separate cores, but both call
# fd_runtime_prepare_and_execute_txn — it separates SCHEDULING, not SEMANTICS.
#
# So: a program-id dispatch arm appearing in a NEW file is a build failure. It is the only layer here
# that closes the bug class rather than this one instance of it.
#
# ── What it detects ──────────────────────────────────────────────────────────────────────────────
# The dispatch-arm shape `std.mem.eql(u8, <x>, &NATIVE_PROGRAM_IDS.<NATIVE>)`. Today that shape lives
# in exactly one file. This pins both facts: the file, and the arm COUNT (so a new ladder inside the
# allowed file also trips and has to be justified rather than absorbed silently).
#
# A trip is NOT automatically a bug — it is a question: "is this a third router?" If the new code
# dispatches execution by program id, route it through the existing ladder instead. If it merely
# CLASSIFIES (an eligibility predicate, a vote-detection helper), re-pin the baseline below and say
# so in the commit message.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 2

# The one file permitted to contain program-id dispatch arms.
ALLOWED_FILE="src/vex_svm/replay_stage.zig"

# Pinned arm count in ALLOWED_FILE as of 2026-07-27 (the produce-oracle change). Re-pin DELIBERATELY,
# never reflexively — read the guard's purpose above first.
BASELINE=30

PATTERN='std\.mem\.eql\(u8, *[^,]+, *&NATIVE_PROGRAM_IDS\.(SYSTEM|VOTE|STAKE|COMPUTE_BUDGET|ZK_ELGAMAL)\)'

fail=0

# (1) The shape must not appear outside the allowed file.
offenders=$(grep -rlE "$PATTERN" src/ 2>/dev/null | grep -v "^${ALLOWED_FILE}$" || true)
if [ -n "$offenders" ]; then
  echo "check-single-ladder: FAIL — program-id dispatch arms found OUTSIDE ${ALLOWED_FILE}:" >&2
  for f in $offenders; do
    echo "  --- $f" >&2
    grep -nE "$PATTERN" "$f" | sed 's/^/      /' >&2
  done
  echo "" >&2
  echo "  A second program-id router is the bug CLASS that made Vexor produce empty blocks." >&2
  echo "  Route execution through the existing ladder (replay_stage.executeDagTx) instead of" >&2
  echo "  teaching a new site about program ids. If this site only CLASSIFIES and does not" >&2
  echo "  dispatch execution, add it to ALLOWED_FILE handling here and justify it in the commit." >&2
  fail=1
fi

# (2) The arm count inside the allowed file must not grow.
if [ ! -f "$ALLOWED_FILE" ]; then
  echo "check-single-ladder: FAIL — ${ALLOWED_FILE} not found (did the tree move?)" >&2
  exit 1
fi
count=$(grep -cE "$PATTERN" "$ALLOWED_FILE" || true)
if [ "$count" -gt "$BASELINE" ]; then
  echo "check-single-ladder: FAIL — dispatch arms in ${ALLOWED_FILE} grew ${BASELINE} -> ${count}." >&2
  echo "  If you added a new ladder, route through the existing one instead." >&2
  echo "  If you extended the existing ladder with a genuinely new native program, re-pin" >&2
  echo "  BASELINE in scripts/check-single-ladder.sh and say why in the commit message." >&2
  fail=1
elif [ "$count" -lt "$BASELINE" ]; then
  echo "check-single-ladder: NOTE — arms shrank ${BASELINE} -> ${count}. Re-pin BASELINE to ${count}." >&2
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "check-single-ladder: OK — ${count} dispatch arms, all in ${ALLOWED_FILE}."
