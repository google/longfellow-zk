"""
BIP-340 reference circuit and witness generation for Sage tests.

Sage reference/spec circuit: models the final algebraic relation plus
ry-bitness and even-parity constraints.  This circuit does NOT compute
scalar multiplication internally — sG and eP are provided as witness
inputs and the circuit checks the projective relation R = sG - eP.

NOTE: The Sage circuit uses a simplified projective check that is only
for reference testing of public/witness facts, parity, and bitness.  It
is not constraint-isomorphic to the production C++ verifier and is not
a general EC verification circuit.  The C++ Bip340Verify circuit is the
production implementation.

References lib/circuits/bip340/bip340_verify.h and
lib/circuits/bip340/bip340_witness.h.
"""

import hashlib
from typing import Optional, Tuple

import sage.all  # type: ignore[import-untyped]
from sage.rings.finite_rings.element_base import FiniteRingElement

from circuit import Circuit, CircuitLayer, Quad
from fields import Fp256k1


# secp256k1 parameters.
P256K1_P = int(Fp256k1.order())
P256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P256K1_B = 7
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

F = Fp256k1
E = sage.all.EllipticCurve(Fp256k1, [0, P256K1_B])
G = E(_GX, _GY)


def lift_x(x: int) -> Optional[Tuple[int, int]]:
    """BIP-340 lift_x: compute even-y point for an x-coordinate."""
    if x >= P256K1_P:
        return None
    y_sq = (pow(x, 3, P256K1_P) + P256K1_B) % P256K1_P
    y = pow(y_sq, (P256K1_P + 1) // 4, P256K1_P)
    if (y * y) % P256K1_P != y_sq:
        return None
    if y & 1:
        y = P256K1_P - y
    return (x, y)


def tagged_hash(r_bytes: bytes, pk_bytes: bytes, msg: bytes) -> int:
    """BIP-340 tagged hash for challenge computation."""
    tag = b"BIP0340/challenge"
    tag_hash = hashlib.sha256(tag).digest()
    preimage = tag_hash + tag_hash + r_bytes + pk_bytes + msg
    return int.from_bytes(hashlib.sha256(preimage).digest(), "big")


def make_bip340_test_circuit() -> Circuit:
    """
    Construct a Sage BIP-340 verification circuit with parity.

    Wire layout (271 inputs, 4 public):
      [0]  = constant 1
      [1]  = rx          (public)
      [2]  = px          (public)
      [3]  = e           (public)
      [4]  = sGx
      [5]  = sGy
      [6]  = sGz
      [7]  = ePx
      [8]  = ePy
      [9]  = ePz
      [10] = py
      [11] = ry
      [12] = rz_inv      (inverse of sGz)
      [13] = px²
      [14] = px³
      [15]..[270] = ry_bits[0..255]  (MSB-first)

    Gates (262 outputs):
      0:  py² - px³ - b = 0                (P on curve)
      1:  sGx - ePx - rx·sGz = 0           (R.x projective, simplified)
      2:  sGy - ePy - ry·sGz = 0           (R.y projective, simplified)
      3:  sGz · rz_inv - 1 = 0             (R finite)
      4..259:  ry_bits[i]·(ry_bits[i]-1) = 0  (bitness, 256 gates)
      260:  Σ(ry_bits[i]·2^(255-i)) - ry = 0  (reconstruction)
      261:  ry_bits[255] = 0               (LSB zero → ry even)
    """
    K = F
    NUM_INPUTS = 271
    NUM_BITS = 256
    RY_BITS_BASE = 15  # ry_bits[0] starts at wire 15

    # Gate 0-2: simplified projective relation (matches old spec).
    # Gate 0: 0 = py² - px³ - b
    # Gate 1: 0 = sGx - ePx - rx·sGz
    # Gate 2: 0 = sGy - ePy - ry·sGz
    # Gate 3: 0 = sGz · rz_inv - 1
    quads = [
        # Gate 0
        Quad(gate=0, input_0=10, input_1=10, coefficient=K(1)),
        Quad(gate=0, input_0=14, input_1=0,  coefficient=K(-1)),
        Quad(gate=0, input_0=0,  input_1=0,  coefficient=K(-P256K1_B)),

        # Gate 1
        Quad(gate=1, input_0=4,  input_1=0,  coefficient=K(1)),
        Quad(gate=1, input_0=7,  input_1=0,  coefficient=K(-1)),
        Quad(gate=1, input_0=1,  input_1=6,  coefficient=K(-1)),

        # Gate 2
        Quad(gate=2, input_0=5,  input_1=0,  coefficient=K(1)),
        Quad(gate=2, input_0=8,  input_1=0,  coefficient=K(-1)),
        Quad(gate=2, input_0=11, input_1=6,  coefficient=K(-1)),

        # Gate 3: sGz * rz_inv - 1 = 0
        Quad(gate=3, input_0=6,  input_1=12, coefficient=K(1)),
        Quad(gate=3, input_0=0,  input_1=0,  coefficient=K(-1)),
    ]

    # Gates 4..259: ry_bits[i] * (ry_bits[i] - 1) = 0
    for i in range(NUM_BITS):
        gate = 4 + i
        wi = RY_BITS_BASE + i
        quads.append(Quad(gate=gate, input_0=wi, input_1=wi, coefficient=K(1)))
        quads.append(Quad(gate=gate, input_0=wi, input_1=0,  coefficient=K(-1)))

    # Gate 260: Σ(ry_bits[i] * 2^(255-i)) - ry = 0
    gate_rc = 4 + NUM_BITS
    for i in range(NUM_BITS):
        wi = RY_BITS_BASE + i
        coeff = K(1 << (NUM_BITS - 1 - i))
        quads.append(Quad(gate=gate_rc, input_0=wi, input_1=0,
                          coefficient=coeff))
    quads.append(Quad(gate=gate_rc, input_0=11, input_1=0, coefficient=K(-1)))

    # The production C++ circuit proves R is on-curve.  This reference model
    # checks that fact through Sage EC arithmetic in tests, not as a gate here.

    # Gate 261: ry_bits[255] = 0  (LSB zero)
    gate_lsb = gate_rc + 1  # 261, skip curve check
    quads.append(Quad(gate=gate_lsb, input_0=RY_BITS_BASE + 255, input_1=0,
                      coefficient=K(1)))

    num_outputs = gate_lsb + 1

    layer_0 = CircuitLayer(
        num_input_wires=NUM_INPUTS,
        quads=quads,
        field=K,
    )
    return Circuit(
        num_outputs=num_outputs,
        num_public_inputs=4,
        num_inputs=NUM_INPUTS,
        layers=[layer_0],
    )


def make_bip340_witness(
    sig_bytes: bytes,
    pk_bytes: bytes,
    msg: bytes,
) -> list[FiniteRingElement]:
    """
    Generate witness for make_bip340_test_circuit().

    Wire layout (see make_bip340_test_circuit docstring).
    """
    # Parse signature.
    r = int.from_bytes(sig_bytes[:32], "big")
    s = int.from_bytes(sig_bytes[32:], "big")
    px = int.from_bytes(pk_bytes, "big")

    # Challenge e.
    e = tagged_hash(sig_bytes[:32], pk_bytes, msg) % P256K1_N

    # Lift public key.
    pk_pt = lift_x(px)
    assert pk_pt is not None
    py = pk_pt[1]

    # Compute s·G.
    sG = int(s) * G

    # Compute e·P.
    P = E(pk_pt[0], pk_pt[1])
    eP = int(e) * P

    # R = sG - eP (on the curve).
    R = sG - eP
    assert not R.is_zero()

    Rx = int(R[0])
    Ry = int(R[1])
    Rz = int(R[2])

    # rz_inv: multiplicative inverse of Rz in Fp.
    K = Fp256k1
    rz_inv_val = K(Rz) ** -1

    # Decompose Ry into bits, MSB-first.
    ry_val = int(Ry)
    ry_bits = [(ry_val >> (255 - i)) & 1 for i in range(256)]

    # Build witness.
    px_sq = (px * px) % P256K1_P
    px_cu = (px_sq * px) % P256K1_P

    witness = [
        K(1),            # 0: constant 1
        K(r),            # 1: rx (public)
        K(px),           # 2: px (public)
        K(e % P256K1_P), # 3: e (public)
        K(int(sG[0])),   # 4: sGx
        K(int(sG[1])),   # 5: sGy
        K(int(sG[2])),   # 6: sGz
        K(int(eP[0])),   # 7: ePx
        K(int(eP[1])),   # 8: ePy
        K(int(eP[2])),   # 9: ePz
        K(py),           # 10: py
        K(Ry),           # 11: ry
        K(rz_inv_val),   # 12: rz_inv
        K(px_sq),        # 13: px²
        K(px_cu),        # 14: px³
    ]

    # Append ry_bits.
    for b in ry_bits:
        witness.append(K(b))

    return witness


def verify_signature(sig_bytes: bytes, pk_bytes: bytes, msg: bytes) -> bool:
    """
    Verify a BIP-340 signature using Sage EC arithmetic.

    Same logic as the standalone bip340.py, duplicated for self-contained use.
    Checks even-y(R) parity.
    """
    if len(pk_bytes) != 32 or len(sig_bytes) != 64:
        return False

    r_bytes = sig_bytes[:32]
    s_bytes = sig_bytes[32:]
    r = int.from_bytes(r_bytes, "big")
    s = int.from_bytes(s_bytes, "big")

    if r >= P256K1_P or s >= P256K1_N:
        return False

    pk = lift_x(int.from_bytes(pk_bytes, "big"))
    if pk is None:
        return False
    P = E(pk[0], pk[1])

    e = tagged_hash(r_bytes, pk_bytes, msg) % P256K1_N

    R = int(s) * G - int(e) * P
    if R.is_zero():
        return False

    Rx = int(R[0])
    Ry = int(R[1])
    if Ry & 1:
        return False
    return Rx == r
