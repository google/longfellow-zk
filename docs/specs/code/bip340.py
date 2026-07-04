"""
BIP-340 Schnorr signature verification over secp256k1.

Reference implementation in Sage for testing against the C++
Bip340Verify circuit.  Uses Sage's built-in elliptic curve
arithmetic with hashlib for SHA-256.
"""

import hashlib
from typing import Any, Optional, Tuple, TypedDict

import sage.all  # type: ignore[import-untyped]


# secp256k1 parameters -------------------------------------------------------
P256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
P256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P256K1_B = 7

# secp256k1 generator (affine).
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Lazy-initialized Sage objects (avoid module-level Sage for mypy).
_curve = None  # type: ignore[var-annotated]
_generator = None  # type: ignore[var-annotated]


def _get_curve() -> Any:
    """Return the secp256k1 elliptic curve (Sage object)."""
    global _curve
    if _curve is None:
        Fp = sage.all.GF(P256K1_P)
        _curve = sage.all.EllipticCurve(Fp, [0, P256K1_B])
    return _curve


def _get_G() -> Any:
    """Return the secp256k1 generator point (Sage object)."""
    global _generator
    if _generator is None:
        _generator = _get_curve()(_GX, _GY)
    return _generator


# BIP-340 tagged hash tag.
_CHALLENGE_TAG = b"BIP0340/challenge"
_TAG_HASH = hashlib.sha256(_CHALLENGE_TAG).digest()


def _tagged_hash(data: bytes) -> bytes:
    """BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    return hashlib.sha256(_TAG_HASH + _TAG_HASH + data).digest()


def _int_from_bytes(b: bytes) -> int:
    """Convert bytes to integer (big-endian)."""
    return int.from_bytes(b, "big")


def _bytes_from_int(x: int) -> bytes:
    """Convert integer to 32-byte big-endian."""
    return x.to_bytes(32, "big")


def _is_even(y: int) -> bool:
    """Check if an integer is even."""
    return (y & 1) == 0


def lift_x(x: int) -> Optional[Tuple[int, int]]:
    """
    BIP-340 lift_x: given an x-coordinate, compute the corresponding
    curve point with even y-coordinate.  Returns (x, y) or None if
    x is not on the curve.
    """
    if x >= P256K1_P:
        return None
    y_sq = (pow(x, 3, P256K1_P) + P256K1_B) % P256K1_P
    # p ≡ 3 mod 4, so sqrt is y_sq^((p+1)/4).
    y = pow(y_sq, (P256K1_P + 1) // 4, P256K1_P)
    if (y * y) % P256K1_P != y_sq:
        return None  # not a quadratic residue
    if not _is_even(y):
        y = P256K1_P - y
    return (x, y)


def verify(pk_bytes: bytes, msg: bytes, sig_bytes: bytes) -> bool:
    """
    BIP-340 Schnorr signature verification.

    Args:
        pk_bytes: 32-byte x-only public key.
        msg: message bytes.
        sig_bytes: 64-byte signature (r || s).

    Returns True if the signature is valid.
    """
    if len(pk_bytes) != 32 or len(sig_bytes) != 64:
        return False

    r_bytes = sig_bytes[:32]
    s_bytes = sig_bytes[32:]

    r = _int_from_bytes(r_bytes)
    s = _int_from_bytes(s_bytes)

    if r >= P256K1_P or s >= P256K1_N:
        return False

    # Lift public key.
    pk = lift_x(_int_from_bytes(pk_bytes))
    if pk is None:
        return False
    P = _get_curve()(pk[0], pk[1])

    # Challenge e = tagged_hash("BIP0340/challenge", r || P.x || msg) mod n.
    e_bytes = _tagged_hash(r_bytes + pk_bytes + msg)
    e = _int_from_bytes(e_bytes) % P256K1_N

    # Compute R' = s·G - e·P.
    sG = int(s) * _get_G()
    eP = int(e) * P
    Rp = sG - eP

    if Rp.is_zero():
        return False

    # Normalize and check x-coordinate + even y.
    Rx = int(Rp[0])
    Ry = int(Rp[1])
    if not _is_even(Ry):
        return False
    return Rx == r


class _TestVector(TypedDict):
    pk: bytes
    msg: bytes
    sig: bytes
    valid: bool


def _load_test_vectors() -> list[_TestVector]:
    """Load BIP-340 test vectors from the shared CSV fixture.

    Returns a list of dicts with keys: pk, msg, sig, valid.
    """
    import csv
    import os

    # Find the CSV relative to this source file.
    this_dir = os.path.dirname(os.path.abspath(__file__))

    csv_path = os.path.join(this_dir, '..', '..', '..',
                            'lib', 'circuits', 'bip340', 'testdata',
                            'bip340_test_vectors.csv')
    if not os.path.exists(csv_path):
        raise FileNotFoundError("bip340_test_vectors.csv not found at " +
                                csv_path)

    vectors: list[_TestVector] = []
    with open(csv_path, newline='', encoding='ascii') as f:
        reader = csv.DictReader(f)
        for row in reader:
            vectors.append({
                'pk': bytes.fromhex(row['public key']),
                'msg': bytes.fromhex(row['message']) if row['message'] else b'',
                'sig': bytes.fromhex(row['signature']),
                'valid': row['verification result'].upper() == 'TRUE',
            })
    assert len(vectors) == 19, f"Expected 19 vectors, got {len(vectors)}"
    # Vector 18 has a 100-byte message (200 hex chars).
    assert len(vectors[18]['msg']) == 100, (
        f"Vector 18 msg len {len(vectors[18]['msg'])} != 100")
    return vectors


# BIP-340 test vectors loaded from shared CSV fixture.
# Source: Bitcoin Core bip340_test_vectors.csv
TEST_VECTORS = _load_test_vectors()


def curve_order() -> int:
    """Return the secp256k1 curve order."""
    return P256K1_N


def field_modulus() -> int:
    """Return the secp256k1 base field modulus."""
    return P256K1_P


def generator() -> Tuple[int, int]:
    """Return the secp256k1 generator point (affine)."""
    return (_GX, _GY)
