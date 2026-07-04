"""Sage golden-fact tests for BIP-340.

Compares Sage-generated field values against a checked-in golden.json
fixture.  The C++ tests separately compare the semantic witness facts
that are invariant across the Sage affine model and C++ projective model.
"""

import json
import unittest
from pathlib import Path

from bip340 import semantic_facts

TESTDATA_DIR = Path(__file__).resolve().parents[3] / "testdata"
GOLDEN_PATH = TESTDATA_DIR / "bip340_golden.json"

with GOLDEN_PATH.open(encoding="ascii") as f:
    GOLDEN = json.load(f)


class TestBip340Golden(unittest.TestCase):

    def test_count(self) -> None:
        """Golden facts cover all 19 vectors."""
        self.assertEqual(len(GOLDEN), 19)

    def test_vector_18_length(self) -> None:
        """Vector 18 has 100-byte message."""
        # Check via the CSV, not the golden file.
        import csv
        csv_path = TESTDATA_DIR / "bip340_test_vectors.csv"
        with csv_path.open(encoding="ascii") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(rows[18]['message']), 200,
                         "Vector 18 message hex should be 200 chars (100 bytes)")

    def test_golden_facts_match_sage(self) -> None:
        """For every valid vector, Sage recomputation matches golden."""
        import csv
        csv_path = TESTDATA_DIR / "bip340_test_vectors.csv"
        with csv_path.open(encoding="ascii") as f:
            rows = list(csv.DictReader(f))

        for i, row in enumerate(rows):
            pk = bytes.fromhex(row['public key'])
            msg = bytes.fromhex(row['message']) if row['message'] else b''
            sig = bytes.fromhex(row['signature'])
            valid = row['verification result'].upper() == 'TRUE'

            fact = GOLDEN[i]
            self.assertEqual(fact['index'], i)
            self.assertEqual(fact['valid'], valid)

            if 'compute_error' in fact:
                # This vector cannot be witnessed — must be invalid.
                self.assertFalse(valid,
                                 f"Vector {i}: compute error but marked valid")
                continue

            # Recompute and compare.
            facts = semantic_facts(pk, msg, sig)
            self.assertIsNotNone(facts, f"Vector {i}: no semantic facts")
            assert facts is not None

            def fe_hex(value: int) -> str:
                return hex(value)[2:].upper().zfill(64)

            self.assertEqual(fe_hex(facts['e']), fact['e_hex'],
                             f"Vector {i}: e mismatch")
            self.assertEqual(fe_hex(facts['py']), fact['py_hex'],
                             f"Vector {i}: py mismatch")
            self.assertEqual(fe_hex(facts['ry']), fact['ry_hex'],
                             f"Vector {i}: ry mismatch")
            self.assertEqual(fe_hex(facts['rz_inv']), fact['rz_inv_hex'],
                             f"Vector {i}: rz_inv mismatch")


if __name__ == '__main__':
    unittest.main()
