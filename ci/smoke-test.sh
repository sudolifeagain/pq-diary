#!/usr/bin/env bash
# pq-diary CI smoke test (Unix / macOS)
#
# Usage:
#   ./ci/smoke-test.sh [BIN_PATH]
#
# Verifies:
#   1. `--help` exit 0 for every public top-level subcommand.
#   2. The root `--help` output does NOT advertise `legacy` / `daemon`
#      (TASK-0095: those subcommands must remain hidden).
#   3. Minimum E2E flow: init -> new -> list -> info -> export.
#
# The E2E flow uses `PQ_DIARY_HOME` to redirect the config root to a
# temporary directory and `PQ_DIARY_PASSWORD` to bypass the interactive
# password prompt, so the script can run unattended in CI.

set -euo pipefail

BIN="${1:-./target/release/pq-diary}"
PASS=0
FAIL=0

pass() {
  echo "[PASS] $*"
  PASS=$((PASS + 1))
}

fail() {
  echo "[FAIL] $*" >&2
  FAIL=$((FAIL + 1))
}

if [ ! -x "$BIN" ]; then
  echo "[FATAL] binary not found or not executable: $BIN" >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# 1. All public subcommands respond to --help with exit 0
# ---------------------------------------------------------------------------
SUBCOMMANDS=(
  init sync change-password info export
  new list show edit delete
  today search stats import vault
  git-init git-push git-pull git-sync git-status
  template legacy legacy-access attachment
)

for cmd in "${SUBCOMMANDS[@]}"; do
  if "$BIN" "$cmd" --help >/dev/null 2>&1; then
    pass "$cmd --help"
  else
    fail "$cmd --help"
  fi
done

# ---------------------------------------------------------------------------
# 2. Root --help advertises legacy / legacy-access (S12) but not daemon
# ---------------------------------------------------------------------------
HELP_OUT=$("$BIN" --help 2>&1 || true)
if echo "$HELP_OUT" | grep -qi 'legacy'; then
  pass "help advertises 'legacy'"
else
  fail "help missing 'legacy'"
fi
if echo "$HELP_OUT" | grep -qi 'daemon'; then
  fail "help contains 'daemon' (must stay hidden)"
else
  pass "help no 'daemon'"
fi

# Legacy subcommand listing.
if "$BIN" legacy --help 2>&1 | grep -q 'init'; then
  pass "legacy --help lists 'init'"
else
  fail "legacy --help missing 'init'"
fi

# Attachment subcommand listing (S13).
if "$BIN" attachment --help 2>&1 | grep -q 'add'; then
  pass "attachment --help lists 'add'"
else
  fail "attachment --help missing 'add'"
fi
if "$BIN" attachment --help 2>&1 | grep -q 'extract'; then
  pass "attachment --help lists 'extract'"
else
  fail "attachment --help missing 'extract'"
fi

# ---------------------------------------------------------------------------
# 3. E2E flow: init -> new -> list -> info -> export
# ---------------------------------------------------------------------------
TMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'pqd-smoke')
trap 'rm -rf "$TMPDIR"' EXIT

export PQ_DIARY_HOME="$TMPDIR"
export PQ_DIARY_PASSWORD="SmokeTest123!"
# `get_password` removes PQ_DIARY_PASSWORD from the env after each call, so we
# re-export it before every subsequent invocation that needs it.

VAULT_DIR="$TMPDIR/vaults/default"

if "$BIN" init >/dev/null 2>&1; then
  pass "E2E: init"
else
  fail "E2E: init"
fi

export PQ_DIARY_PASSWORD="SmokeTest123!"
if "$BIN" --vault "$VAULT_DIR" new "smoke" --body "smoke body" >/dev/null 2>&1; then
  pass "E2E: new"
else
  fail "E2E: new"
fi

export PQ_DIARY_PASSWORD="SmokeTest123!"
if "$BIN" --vault "$VAULT_DIR" list 2>/dev/null | grep -q 'smoke'; then
  pass "E2E: list contains smoke"
else
  fail "E2E: list contains smoke"
fi

export PQ_DIARY_PASSWORD="SmokeTest123!"
if "$BIN" --vault "$VAULT_DIR" info >/dev/null 2>&1; then
  pass "E2E: info"
else
  fail "E2E: info"
fi

mkdir -p "$TMPDIR/out"
export PQ_DIARY_PASSWORD="SmokeTest123!"
echo y | "$BIN" --vault "$VAULT_DIR" export "$TMPDIR/out" >/dev/null 2>&1 || true
EXPORT_COUNT=$(find "$TMPDIR/out" -maxdepth 1 -type f | wc -l | tr -d ' ')
if [ "$EXPORT_COUNT" -eq 1 ]; then
  pass "E2E: export 1 file"
else
  fail "E2E: export (expected 1 file, got $EXPORT_COUNT)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "===== $PASS passed, $FAIL failed ====="
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
exit 0
