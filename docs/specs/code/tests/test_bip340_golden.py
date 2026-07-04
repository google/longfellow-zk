"""Sage golden-fact tests for BIP-340.

Compares Sage-generated field values against a checked-in golden.json
fixture.  The C++ tests separately compare the semantic witness facts
that are invariant across the Sage affine model and C++ projective model.
"""

import json
import os
import unittest

from bip340_circuit import (
    make_bip340_witness,
)

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
GOLDEN_PATH = os.path.join(
    THIS_DIR, '..', '..', '..', '..',
    'lib', 'circuits', 'bip340', 'testdata', 'bip340_golden.json')

with open(GOLDEN_PATH) as f:
    GOLDEN = json.load(f)


class TestBip340Golden(unittest.TestCase):

    def test_count(self) -> None:
        """Golden facts cover all 19 vectors."""
        self.assertEqual(len(GOLDEN), 19)

    def test_vector_18_length(self) -> None:
        """Vector 18 has 100-byte message."""
        # Check via the CSV, not the golden file.
        import csv
        import os as _os
        csv_path = _os.path.join(_os.path.dirname(GOLDEN_PATH),
                                 'bip340_test_vectors.csv')
        with open(csv_path) as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(rows[18]['message']), 200,
                         "Vector 18 message hex should be 200 chars (100 bytes)")

    def test_golden_facts_match_sage(self) -> None:
        """For every valid vector, Sage recomputation matches golden."""
        import csv
        import os as _os
        csv_path = _os.path.join(_os.path.dirname(GOLDEN_PATH),
                                 'bip340_test_vectors.csv')
        with open(csv_path) as f:
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
            w = make_bip340_witness(sig, pk, msg)

            def fe_hex(idx: int) -> str:
                return hex(int(w[idx]))[2:].upper().zfill(64)

            self.assertEqual(fe_hex(3), fact['e_hex'],
                             f"Vector {i}: e mismatch")
            self.assertEqual(fe_hex(10), fact['py_hex'],
                             f"Vector {i}: py mismatch")
            self.assertEqual(fe_hex(11), fact['ry_hex'],
                             f"Vector {i}: ry mismatch")
            self.assertEqual(fe_hex(12), fact['rz_inv_hex'],
                             f"Vector {i}: rz_inv mismatch")


if __name__ == '__main__':
    unittest.main()
