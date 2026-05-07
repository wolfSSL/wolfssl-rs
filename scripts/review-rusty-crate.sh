#!/usr/bin/env bash
#
# Run /review-rusty-crate for one or more workspace crates, headlessly.
# Each crate gets its own opencode session and its own beads epic.
#
# Usage:
#   ./scripts/review-rusty-crate.sh                 # review every workspace crate
#   ./scripts/review-rusty-crate.sh wolfcrypt-tls   # review one crate
#   ./scripts/review-rusty-crate.sh wolfcrypt wolfcrypt-rs   # review N crates
#
# The script runs SERIALLY by design: bd writes serialize through SQLite,
# parallel cargo builds thrash, and the per-crate runs may produce commits
# that affect each other if cross-crate side effects slip through.
#
# Logs are written to .review-logs/<timestamp>/<crate>.log

set -euo pipefail

WORKSPACE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TS=$(date +%Y%m%d-%H%M%S)
LOG_DIR="$WORKSPACE/.review-logs/$TS"
mkdir -p "$LOG_DIR"

# Resolve crate list.
if [ "$#" -gt 0 ]; then
  CRATES=("$@")
else
  # Enumerate every workspace member by scanning depth-2 Cargo.toml.
  # We use the directory layout rather than `cargo metadata` so that a
  # broken workspace member does not block the enumeration of the others.
  CRATES=()
  while read -r dir; do
    CRATES+=("$(basename "$dir")")
  done < <(find "$WORKSPACE" -mindepth 2 -maxdepth 2 -name Cargo.toml -printf '%h\n' | sort)
fi

if [ "${#CRATES[@]}" -eq 0 ]; then
  echo "no crates to review" >&2
  exit 1
fi

# Verify opencode and bd are on PATH up-front so we fail fast if not.
command -v opencode >/dev/null || { echo "opencode not on PATH" >&2; exit 2; }
command -v bd >/dev/null       || { echo "bd not on PATH" >&2; exit 2; }

# Refuse to run on a dirty tree — the dispatcher commits per-crate and
# starting from dirty state would conflate uncommitted work with review
# results.
if ! git -C "$WORKSPACE" diff --quiet HEAD; then
  echo "working tree is dirty in $WORKSPACE; commit or stash first" >&2
  exit 3
fi

echo "Workspace : $WORKSPACE"
echo "Logs      : $LOG_DIR/"
echo "Crates    : ${#CRATES[@]} (${CRATES[*]})"
echo

ok=0
fail=0
skip=0
declare -a FAILED

for crate in "${CRATES[@]}"; do
  printf '=== %-32s ' "$crate"
  log="$LOG_DIR/$crate.log"

  # Skip crates whose dir doesn't exist (in case the user passed a typo).
  if [ ! -f "$WORKSPACE/$crate/Cargo.toml" ]; then
    echo "SKIP (no Cargo.toml)"
    skip=$((skip + 1))
    continue
  fi

  start=$(date +%s)
  set +e
  opencode run \
    --dangerously-skip-permissions \
    --dir "$WORKSPACE" \
    --print-logs --log-level INFO \
    "/review-rusty-crate $crate" \
    >"$log" 2>&1
  status=$?
  set -e
  elapsed=$(( $(date +%s) - start ))

  if [ "$status" -eq 0 ]; then
    echo "ok ($(printf '%dm%02ds' $((elapsed / 60)) $((elapsed % 60))))"
    ok=$((ok + 1))
  else
    echo "FAIL status=$status ($(printf '%dm%02ds' $((elapsed / 60)) $((elapsed % 60))))"
    fail=$((fail + 1))
    FAILED+=("$crate")
  fi
done

echo
echo "Done. ok=$ok fail=$fail skip=$skip  ($LOG_DIR/)"

if [ "$fail" -gt 0 ]; then
  printf '\nFailed crates:\n'
  for c in "${FAILED[@]}"; do
    printf '  %-30s  %s\n' "$c" "$LOG_DIR/$c.log"
  done
  exit 1
fi
