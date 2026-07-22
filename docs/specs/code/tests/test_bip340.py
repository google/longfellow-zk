"""Tests for BIP-340 Schnorr verification (Sage reference implementation)."""

import unittest

from bip340 import (
    TEST_VECTORS,
    curve_order,
    field_modulus,
    generator,
    lift_x,
    verify,
)


class TestBip340(unittest.TestCase):
    def test_curve_params(self) -> None:
        """Secp256k1 parameters are well-formed."""
        p = field_modulus()
        n = curve_order()
        Gx, Gy = generator()

        # p is odd prime, n is prime.
        self.assertEqual(p % 2, 1)
        self.assertGreater(n, 1)
        self.assertLess(n, p)

        # Generator is on the curve: y² = x³ + 7 mod p.
        lhs = (Gy * Gy) % p
        rhs = (pow(Gx, 3, p) + 7) % p
        self.assertEqual(lhs, rhs)

    def test_lift_x(self) -> None:
        """lift_x computes the correct even-y point."""
        # G.x lifted should give G.
        Gx, Gy = generator()
        pt = lift_x(Gx)
        self.assertIsNotNone(pt)
        assert pt is not None  # type narrowing for mypy
        self.assertEqual(pt[0], Gx)
        self.assertEqual(pt[1], Gy)
        # Gy should be even.
        self.assertEqual(Gy & 1, 0)

        # x not on curve returns None.
        self.assertIsNone(lift_x(0))

    def test_lift_x_even_y(self) -> None:
        """lift_x always returns an even y-coordinate."""
        from bip340 import _get_curve, _get_G
        E = _get_curve()
        G = _get_G()
        for i in range(5):
            x = int(((i + 2) * G)[0])
            pt = lift_x(x)
            if pt is not None:
                self.assertEqual(pt[1] & 1, 0, f"lift_x({hex(x)}) gave odd y")

    def test_test_vectors(self) -> None:
        """Verify all known BIP-340 test vectors."""
        for i, tv in enumerate(TEST_VECTORS):
            with self.subTest(vector=i):
                result = verify(tv["pk"], tv["msg"], tv["sig"])
                self.assertEqual(
                    result, tv["valid"],
                    f"Vector {i}: expected {tv['valid']}, got {result}"
                )

    def test_empty_signature_fails(self) -> None:
        """Empty/zero signature is rejected."""
        tv = TEST_VECTORS[0]
        self.assertFalse(verify(tv["pk"], tv["msg"], bytes(64)))

    def test_zero_public_key_fails(self) -> None:
        """x=0 is not a valid public key (no even-y point)."""
        tv = TEST_VECTORS[0]
        self.assertFalse(verify(bytes(32), tv["msg"], tv["sig"]))

    def test_tampered_signature_fails(self) -> None:
        """Flipping a bit in a valid signature invalidates it."""
        tv = TEST_VECTORS[0]
        sig = bytearray(tv["sig"])
        sig[10] ^= 0x01
        self.assertFalse(verify(tv["pk"], tv["msg"], bytes(sig)))

    def test_wrong_lengths_rejected(self) -> None:
        """Malformed inputs are rejected gracefully."""
        tv = TEST_VECTORS[0]
        self.assertFalse(verify(b"x" * 31, tv["msg"], tv["sig"]))
        self.assertFalse(verify(b"x" * 33, tv["msg"], tv["sig"]))
        self.assertFalse(verify(tv["pk"], tv["msg"], b"x" * 63))
        self.assertFalse(verify(tv["pk"], tv["msg"], b"x" * 65))

    def test_scalars_s_g(self) -> None:
        """Verify that s·G and e·P are computed correctly."""
        # Use test vector 0.
        tv = TEST_VECTORS[0]
        pk_bytes = tv["pk"]
        sig = tv["sig"]

        from bip340 import (
            _get_curve, _get_G, _int_from_bytes, _tagged_hash, P256K1_N, lift_x,
        )

        r_bytes = sig[:32]
        s_bytes = sig[32:]
        r = _int_from_bytes(r_bytes)
        s = _int_from_bytes(s_bytes)
        e = _int_from_bytes(
            _tagged_hash(r_bytes + pk_bytes + tv["msg"])
        ) % P256K1_N

        E = _get_curve()
        G = _get_G()
        pk_pt = lift_x(_int_from_bytes(pk_bytes))
        assert pk_pt is not None
        P = E(pk_pt[0], pk_pt[1])

        # s·G - e·P should equal R.
        R = int(s) * G - int(e) * P
        self.assertFalse(R.is_zero())
        self.assertEqual(int(R[0]), r)


if __name__ == "__main__":
    unittest.main()
