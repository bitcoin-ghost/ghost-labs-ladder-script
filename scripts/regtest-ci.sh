#!/usr/bin/env bash
#
# regtest-ci.sh -- CI-friendly runner for Ladder Script block type tests on regtest.
# Runs tests/functional/test_rung_regtest.py which covers all 60 block types.
# Returns 0 on success, 1 on failure.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_BIN="$REPO_DIR/ghost-core/build/bin"
GHOSTD="$BUILD_BIN/ghostd"
CLI="$BUILD_BIN/ghost-cli"
TEST_SCRIPT="$REPO_DIR/tests/functional/test_rung_regtest.py"

# ------------------------------------------------------------------
# 1. Check prerequisites
# ------------------------------------------------------------------
echo "=== Regtest CI: checking prerequisites ==="

if [ ! -x "$GHOSTD" ]; then
    echo "FATAL: ghostd not found at $GHOSTD"
    echo "       Run scripts/build.sh first."
    exit 1
fi

if [ ! -x "$CLI" ]; then
    echo "FATAL: ghost-cli not found at $CLI"
    echo "       Run scripts/build.sh first."
    exit 1
fi

if [ ! -f "$TEST_SCRIPT" ]; then
    echo "FATAL: test script not found at $TEST_SCRIPT"
    exit 1
fi

if ! python3 -c "import coincurve" 2>/dev/null; then
    echo "FATAL: Python coincurve module not installed."
    echo "       pip install coincurve"
    exit 1
fi

echo "  ghostd:    $GHOSTD"
echo "  ghost-cli: $CLI"
echo "  test:      $TEST_SCRIPT"
echo

# ------------------------------------------------------------------
# 2. Run the test suite
# ------------------------------------------------------------------
# test_rung_regtest.py is fully self-contained: it starts ghostd on a
# non-default port, creates a wallet, funds it, runs all block type
# tests, prints a summary, stops the node, and cleans up the datadir.
# We just need to invoke it and capture the exit code.

echo "=== Regtest CI: running block type tests ==="
echo

EXIT_CODE=0
python3 "$TEST_SCRIPT" || EXIT_CODE=$?

echo
echo "=== Regtest CI: done ==="

if [ "$EXIT_CODE" -eq 0 ]; then
    echo "RESULT: ALL TESTS PASSED"
else
    echo "RESULT: SOME TESTS FAILED (exit code $EXIT_CODE)"
fi

exit "$EXIT_CODE"
