#!/usr/bin/env python3
"""Regenerate BIP-340 C++ fixtures from checked-in testdata.

By default this script reads the Bitcoin Core CSV already stored at
lib/circuits/bip340/testdata/bip340_test_vectors.csv and regenerates:

  - lib/circuits/bip340/testdata/bip340_vectors.inc
  - lib/circuits/bip340/testdata/bip340_golden.inc

Use --refresh-bitcoin-core to replace the checked-in CSV from upstream first.
"""

import argparse
import csv
import json
from pathlib import Path
from urllib.request import urlopen


BITCOIN_CORE_BIP340_CSV = (
    "https://raw.githubusercontent.com/bitcoin/bitcoin/refs/heads/master/"
    "test/functional/test_framework/bip340_test_vectors.csv"
)

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[2]
TESTDATA_DIR = REPO_ROOT / "lib" / "circuits" / "bip340" / "testdata"
CSV_PATH = TESTDATA_DIR / "bip340_test_vectors.csv"
JSON_PATH = TESTDATA_DIR / "bip340_golden.json"
VECTORS_INC_PATH = TESTDATA_DIR / "bip340_vectors.inc"
GOLDEN_INC_PATH = TESTDATA_DIR / "bip340_golden.inc"


# Exact Bitcoin Core CSV headers.  Regeneration fails if upstream changes.
EXPECTED_HEADERS = [
    "index", "secret key", "public key", "aux_rand", "message",
    "signature", "verification result", "comment",
]


def cell(row: dict[str, str], name: str) -> str:
    """Read a CSV field by Bitcoin Core column name."""
    if name in row:
        return row[name]
    raise KeyError(f"missing CSV column {name!r}; got {sorted(row)}")


def cxx_string(value: str) -> str:
    """Return a C++ string literal split into readable 64-char chunks."""
    if not value:
        return '""'
    chunks = [value[i:i + 64] for i in range(0, len(value), 64)]
    return "\n     ".join(f'"{chunk}"' for chunk in chunks)


def load_rows() -> list[dict[str, str]]:
    with CSV_PATH.open(newline="", encoding="ascii") as f:
        reader = csv.DictReader(f)
        actual = reader.fieldnames
        if actual is None or list(actual) != EXPECTED_HEADERS:
            raise ValueError(
                f"CSV headers changed.\n"
                f"  expected: {EXPECTED_HEADERS}\n"
                f"  got:      {actual}"
            )
        rows = list(reader)
    if len(rows) != 19:
        raise ValueError(f"expected 19 BIP-340 vectors, got {len(rows)}")
    return rows


def refresh_csv() -> None:
    with urlopen(BITCOIN_CORE_BIP340_CSV, timeout=30) as response:
        data = response.read()
    CSV_PATH.write_bytes(data)


def write_vectors_inc(rows: list[dict[str, str]]) -> None:
    with VECTORS_INC_PATH.open("w", encoding="ascii", newline="\n") as f:
        f.write("// Auto-generated from bip340_test_vectors.csv.  Do not edit.\n")
        f.write("// Source: Bitcoin Core BIP-340 test vectors.\n")
        f.write(f"// Regenerate: {Path(__file__).name}\n\n")
        for i, row in enumerate(rows):
            valid = (
                "true"
                if cell(row, "verification result").upper() == "TRUE"
                else "false"
            )
            comment = cell(row, "comment")
            if comment:
                f.write(f"    // {i}: {comment}\n")
            else:
                f.write(f"    // {i}\n")
            f.write("    {")
            f.write(f'{cxx_string(cell(row, "public key"))},\n')
            f.write(f'     {cxx_string(cell(row, "message"))},\n')
            f.write(f'     {cxx_string(cell(row, "signature"))}, {valid}}},\n')


def write_golden_inc() -> None:
    facts = json.loads(JSON_PATH.read_text(encoding="ascii"))
    if len(facts) != 19:
        raise ValueError(f"expected 19 golden facts, got {len(facts)}")

    with GOLDEN_INC_PATH.open("w", encoding="ascii", newline="\n") as f:
        f.write("// Auto-generated from bip340_golden.json.  Do not edit.\n")
        f.write(f"// Regenerate: {Path(__file__).name}\n\n")
        for fact in facts:
            compute_success = "false" if "compute_error" in fact else "true"
            valid = "true" if fact["valid"] else "false"
            f.write(f"    // {fact['index']}\n")
            f.write(
                f'    {{{fact["index"]}, {valid}, {compute_success},\n'
                f'     "{fact.get("rx_hex", "")}",\n'
                f'     "{fact.get("px_hex", "")}",\n'
                f'     "{fact.get("e_hex", "")}",\n'
                f'     "{fact.get("py_hex", "")}",\n'
                f'     "{fact.get("ry_hex", "")}"}},\n'
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--refresh-bitcoin-core",
        action="store_true",
        help="download the upstream Bitcoin Core BIP-340 CSV before regenerating",
    )
    args = parser.parse_args()

    if args.refresh_bitcoin_core:
        refresh_csv()

    rows = load_rows()
    write_vectors_inc(rows)
    write_golden_inc()
    print(f"Regenerated {VECTORS_INC_PATH}")
    print(f"Regenerated {GOLDEN_INC_PATH}")


if __name__ == "__main__":
    main()
