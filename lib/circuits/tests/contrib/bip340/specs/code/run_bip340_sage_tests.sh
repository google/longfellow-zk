#!/usr/bin/env bash
# Run all Sage BIP-340 tests.  Requires Sage (importable via sage.all).
# Usage: ./run_bip340_sage_tests.sh

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../../../../../" && pwd)"
SHARED_SAGE_DIR="$REPO_ROOT/docs/specs/sage"

if [[ ! -d "$SHARED_SAGE_DIR" ]]; then
  printf 'ERROR: Shared Sage specs not found at %s\n' "$SHARED_SAGE_DIR" >&2
  exit 1
fi

cd "$SCRIPT_DIR"

export PYTHONPATH="$SCRIPT_DIR:$SHARED_SAGE_DIR${PYTHONPATH:+:$PYTHONPATH}"

# Find a Python that can import sage.all.
SAGE_PYTHON_CMD=()
SAGE_PYTHON_LABEL=""

try_sage_python() {
  if "$@" -c "import sage.all" 2>/dev/null; then
    SAGE_PYTHON_CMD=("$@")
    SAGE_PYTHON_LABEL="$*"
    return 0
  fi
  return 1
}

if command -v python3 &>/dev/null; then
  try_sage_python python3 || true
fi

if [ "${#SAGE_PYTHON_CMD[@]}" -eq 0 ] && command -v sage &>/dev/null; then
  try_sage_python sage -python || true
fi

if [ "${#SAGE_PYTHON_CMD[@]}" -eq 0 ]; then
  printf '%s\n' "ERROR: No Python with 'sage.all' found." >&2
  printf '%s\n' "Install SageMath or make its Python interpreter available." >&2
  exit 1
fi

printf 'Using Sage Python: %s\n' "$SAGE_PYTHON_LABEL"

printf '%s\n' "=== Sage BIP-340 tests ==="
"${SAGE_PYTHON_CMD[@]}" -m unittest discover -s tests -p 'test_bip340*.py' -v

printf '\n%s\n' "=== All Sage BIP-340 tests complete ==="
