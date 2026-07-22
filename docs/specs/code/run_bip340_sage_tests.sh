#!/usr/bin/env bash
# Run all Sage BIP-340 tests.  Requires Sage (importable via sage.all).
# Usage: ./run_bip340_sage_tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

export PYTHONPATH="$SCRIPT_DIR"

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

for cand in python3 /home/jrml/miniforge3/bin/python; do
  if command -v "$cand" &>/dev/null; then
    if try_sage_python "$cand"; then
      break
    fi
  fi
done

if [ "${#SAGE_PYTHON_CMD[@]}" -eq 0 ] && command -v sage &>/dev/null; then
  try_sage_python sage -python || true
fi

if [ "${#SAGE_PYTHON_CMD[@]}" -eq 0 ]; then
  echo "ERROR: No Python with 'sage.all' found." >&2
  echo "Try: /home/jrml/miniforge3/bin/python or install SageMath." >&2
  exit 1
fi

echo "Using Sage Python: $SAGE_PYTHON_LABEL"

echo "=== Sage BIP-340 tests ==="
"${SAGE_PYTHON_CMD[@]}" -m unittest discover -s tests -p 'test_bip340*.py' -v

echo ""
echo "=== All Sage BIP-340 tests complete ==="
