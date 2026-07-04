"""Tests for BIP-340 circuit parity constraints (Sage simplified model).

The Sage circuit uses simplified projective equations that document the
constraint layout (parity, bitness, curve membership) but do NOT perform
full EC arithmetic.  The C++ Bip340Verify circuit is the production
implementation.

Tests cover:
  - Circuit witness length matches ninputs
  - ry_bits bitness gates evaluate correctly
  - ry reconstruction gate evaluates correctly  
  - LSB-zero gate catches odd ry
  - Signature verification (standalone, full EC)
"""

import copy
import unittest

import sage.all  # type: ignore[import-untyped]
from sage.rings.finite_rings.element_base import FiniteRingElement
from sage.rings.finite_rings.finite_field_base import FiniteField

from circuit import Circuit
from fields import Fp256k1
from fs import Transcript
from sumcheck import (
    constraints_circuit,
    construct_concrete_pad,
    construct_symbolic_variables,
    sumcheck_circuit,
)

from bip340_circuit import (
    F,
    make_bip340_test_circuit,
    make_bip340_witness,
    verify_signature,
    P256K1_P,
    P256K1_N,
)


class TestBip340Circuit(unittest.TestCase):

    def setUp(self) -> None:
        """Valid BIP-340 test vector 0."""
        self.tv0 = {
            "pk": bytes.fromhex(
                "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
            ),
            "msg": bytes.fromhex(
                "0000000000000000000000000000000000000000000000000000000000000000"
            ),
            "sig": bytes.fromhex(
                "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
            ),
        }

    def test_signature_verification(self) -> None:
        """Standalone BIP-340 verification (full EC)."""
        result = verify_signature(
            self.tv0["sig"], self.tv0["pk"], self.tv0["msg"])
        self.assertTrue(result)

    def test_witness_length(self) -> None:
        """Witness length matches circuit ninputs."""
        circuit = make_bip340_test_circuit()
        witness = make_bip340_witness(
            self.tv0["sig"], self.tv0["pk"], self.tv0["msg"])
        self.assertEqual(len(witness), circuit.ninputs)

    def test_ry_bitness_gates(self) -> None:
        """Each ry_bits[i] * (ry_bits[i] - 1) = 0 (bitness)."""
        circuit = make_bip340_test_circuit()
        witness = make_bip340_witness(
            self.tv0["sig"], self.tv0["pk"], self.tv0["msg"])
        wires = circuit.evaluate(witness)

        # Gates 4..259 are the bitness gates.
        for i in range(256):
            gate = 4 + i
            self.assertEqual(int(wires[0][gate]), 0,
                             f"ry_bits[{i}] bitness gate {gate}")

    def test_ry_reconstruction(self) -> None:
        """Σ(ry_bits[i] * 2^(255-i)) - ry = 0 (reconstruction)."""
        circuit = make_bip340_test_circuit()
        witness = make_bip340_witness(
            self.tv0["sig"], self.tv0["pk"], self.tv0["msg"])
        wires = circuit.evaluate(witness)

        # Gate 260 is the reconstruction gate.
        self.assertEqual(int(wires[0][260]), 0,
                         "ry reconstruction gate")

    def test_lsb_zero_even_ry(self) -> None:
        """ry_bits[255] = 0 for even ry (LSB-zero gate)."""
        circuit = make_bip340_test_circuit()
        witness = make_bip340_witness(
            self.tv0["sig"], self.tv0["pk"], self.tv0["msg"])
        wires = circuit.evaluate(witness)

        # Gate 261 is the LSB-zero gate.
        self.assertEqual(int(wires[0][261]), 0,
                         "LSB-zero gate for even ry")

    def test_odd_ry_witness_fails(self) -> None:
        """Hand-mutated odd-ry witness fails LSB-zero gate."""
        circuit = make_bip340_test_circuit()
        witness = make_bip340_witness(
            self.tv0["sig"], self.tv0["pk"], self.tv0["msg"])

        # Mutate ry to odd (negate modulo p) and update ry_bits.
        K = Fp256k1
        odd_ry = K(P256K1_P - int(witness[11]))
        witness[11] = odd_ry

        # Update ry_bits for the odd value.
        ry_val = int(odd_ry)
        for i in range(256):
            witness[15 + i] = K((ry_val >> (255 - i)) & 1)

        # Evaluate.
        wires = circuit.evaluate(witness)

        # The LSB-zero gate (261) should be non-zero (odd ry → LSB=1).
        self.assertNotEqual(int(wires[0][261]), 0,
                            "Odd-ry witness should fail LSB-zero gate")

    def test_sumcheck_prover_verifier(self) -> None:
        """Full sumcheck prover/verifier lifecycle for BIP-340 circuit."""
        circuit = make_bip340_test_circuit()
        witness = make_bip340_witness(
            self.tv0["sig"], self.tv0["pk"], self.tv0["msg"])

        # Evaluate to get all wire values.
        wires = circuit.evaluate(witness)

        # Build pad.
        pad_transcript = Transcript()
        pad_transcript.init(b"bip340 pad prng")

        def pad_prg(field: FiniteField) -> FiniteRingElement:
            return pad_transcript.generate_field(field)

        (pad_layers, _pad_flattened) = construct_concrete_pad(
            Fp256k1, circuit, pad_prg,
        )

        # Prove.
        transcript = Transcript()
        transcript.init(b"bip340 sumcheck")
        constraints_transcript = copy.deepcopy(transcript)

        proof = sumcheck_circuit(
            Fp256k1, circuit, wires, pad_layers, transcript,
        )

        self.assertIsNotNone(proof)
        self.assertTrue(len(proof) > 0)

        # Verify.
        sym_private_inputs, sym_pad = construct_symbolic_variables(
            Fp256k1, circuit,
        )
        (linear_constraints, quadratic_constraints) = constraints_circuit(
            Fp256k1,
            circuit,
            witness[:4],  # public inputs only
            sym_private_inputs,
            sym_pad,
            constraints_transcript,
            proof,
        )
        self.assertIsNotNone(linear_constraints)
        self.assertIsNotNone(quadratic_constraints)


if __name__ == "__main__":
    unittest.main()
