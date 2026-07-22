import copy
import unittest

import sage.all
from sage.rings.finite_rings.finite_field_base import FiniteField
from sage.rings.finite_rings.finite_field_constructor import GF

from circuit import Circuit, CircuitLayer, Quad
from fields import Fp256
from fs import Transcript
from sumcheck import (
    bindeq, constraints_circuit, construct_concrete_pad,
    construct_symbolic_variables, sumcheck_circuit,
)


class TestSumcheck(unittest.TestCase):
    def test_bindeq(self) -> None:
        gf17 = GF(17)
        assert bindeq(gf17, []) == [gf17.one()]
        assert bindeq(gf17, [gf17(2)]) == [gf17(16), gf17(2)]
        assert bindeq(gf17, [gf17(2), gf17(5)]) == [
            gf17(16) * gf17(13),
            gf17(2) * gf17(13),
            gf17(16) * gf17(5),
            gf17(2) * gf17(5),
        ]

    def test_smoke_test_witness(self) -> None:
        gf17 = GF(17)
        circuit = make_test_circuit(gf17)
        construct_symbolic_variables(gf17, circuit)
        construct_concrete_pad(gf17, circuit)

    def test_smoke_test_sumcheck_prover(self) -> None:
        gf17 = GF(17)
        circuit = make_test_circuit(gf17)
        transcript = Transcript()
        transcript.init(b"unit test")
        constraints_transcript = copy.deepcopy(transcript)
        inputs = [gf17.one(), gf17(2)]
        wires = circuit.evaluate(inputs)
        (pad_layers, _pad_flattened) = construct_concrete_pad(gf17, circuit)
        proof = sumcheck_circuit(
            gf17,
            circuit,
            wires,
            pad_layers,
            transcript,
        )
        sym_private_inputs, sym_pad = construct_symbolic_variables(
            gf17,
            circuit,
        )
        (_, _) = constraints_circuit(
            gf17,
            circuit,
            inputs[:1],
            sym_private_inputs,
            sym_pad,
            constraints_transcript,
            proof,
        )

    def test_sumcheck_prover_dump_proof(self) -> None:
        pad_transcript = Transcript()
        pad_transcript.init(b"pad prng")
        pad_prg = lambda field: pad_transcript.generate_field(field)

        circuit = make_test_circuit(Fp256)
        transcript = Transcript()
        transcript.init(b"test")
        constraints_transcript = copy.deepcopy(transcript)
        inputs = [Fp256(1), Fp256(2)]
        wires = circuit.evaluate(inputs)
        (pad_layers, _pad_flattened) = construct_concrete_pad(
            Fp256,
            circuit,
            pad_prg,
        )
        proof = sumcheck_circuit(
            Fp256,
            circuit,
            wires,
            pad_layers,
            transcript,
        )
        sym_private_inputs, sym_pad = construct_symbolic_variables(
            Fp256,
            circuit,
        )
        (linear_constraints, quadratic_constraints) = constraints_circuit(
            Fp256,
            circuit,
            inputs[:1],
            sym_private_inputs,
            sym_pad,
            constraints_transcript,
            proof,
        )

        for layer_idx, proof_layer in enumerate(proof):
            print(f"Layer {layer_idx}:")
            for polynomials in proof_layer.evals:
                print("Left hand, P0", polynomials[0].p0.to_bytes().hex())
                print("Left hand, P2", polynomials[0].p2.to_bytes().hex())
                print("Right hand, P0", polynomials[1].p0.to_bytes().hex())
                print("Right hand, P2", polynomials[1].p2.to_bytes().hex())
            print("VL", proof_layer.vl.to_bytes().hex())
            print("VR", proof_layer.vr.to_bytes().hex())
        for i, linear_constraint in enumerate(linear_constraints):
            print(f"Linear constraint {i}:")
            rhs = Fp256.zero()
            for (exponents, coeff) in linear_constraint.monomial_coefficients().items():
                if exponents.is_constant():
                    rhs = -coeff
                elif exponents.unweighted_degree() == 1:
                    variable, _ = next(exponents.sparse_iter())
                    print(f"{coeff.to_bytes().hex()} * w{variable}")
                else:
                    raise Exception(f"degree of term is too high: {exponents}")
            print(f"RHS: {rhs.to_bytes().hex()}")
        print("Quadratic constraints:")
        for quadratic_constraint in quadratic_constraints:
            print(
                f"{quadratic_constraint.x} * {quadratic_constraint.y} "
                f"= {quadratic_constraint.z}"
            )


def make_test_circuit(field: FiniteField) -> Circuit:
    """
    Constructs a very small circuit for use in tests.

    This circuit outputs two values, (x - 1) * (x - 2) and
    x * (x - 1) * (x - 2), and has an in-circuit assrtion checking
    x - 2 = 0. This circuit assumes that the field has large
    characteristic.
    """
    layer_0 = CircuitLayer(
        num_input_wires=4,
        quads=[
            # Propagate x^2 - 3x + 2 to output.
            # V[0][0] = 1 * V[1][0] * V[1][1]
            Quad(gate=0, input_0=0, input_1=1, coefficient=field(1)),
            # Propagate x^3 - 3x^2 + 2x to output.
            # V[0][1] = 1 * V[1][0] * V[1][3]
            Quad(gate=1, input_0=0, input_1=3, coefficient=field(1)),
        ],
        field=field,
    )
    layer_1 = CircuitLayer(
        num_input_wires=4,
        quads=[
            # Propagate 1 to next layer.
            # V[1][0] = 1 * V[2][0] * V[2][0]
            Quad(gate=0, input_0=0, input_1=0, coefficient=field(1)),
            # Propagate x^2 - 3x + 2 to next layer.
            # V[1][1] = 1 * V[2][0] * V[2][1]
            Quad(gate=1, input_0=0, input_1=1, coefficient=field(1)),
            # Assert x - 2 = 0.
            # 0 = V[2][0] * V[2][2] + V[2][0] * V[2][3]
            Quad(gate=2, input_0=0, input_1=2, coefficient=field(0)),
            Quad(gate=2, input_0=0, input_1=3, coefficient=field(0)),
            # Compute x^3 - 3x^2 + 2x.
            # V[1][3] = 1 * V[2][1] * V[2][2]
            Quad(gate=3, input_0=1, input_1=2, coefficient=field(1)),
        ],
        field=field,
    )
    layer_2 = CircuitLayer(
        num_input_wires=2,
        quads=[
            # Propagate 1 to next layer.
            # V[2][0] = 1 * V[3][0] * V[3][0]
            Quad(gate=0, input_0=0, input_1=0, coefficient=field(1)),
            # Calculate x^2 - 3x + 2x.
            # V[2][1] = 1 * V[3][1] * V[3][1] + -3 * V[3][0] * V[3][1]
            #           + 2 * V[3][0] * V[3][0]
            Quad(gate=1, input_0=1, input_1=1, coefficient=field(1)),
            Quad(gate=1, input_0=0, input_1=1, coefficient=-field(3)),
            Quad(gate=1, input_0=0, input_1=0, coefficient=field(2)),
            # Propagate x to next layer (for assertion).
            # V[2][2] = 1 * V[3][0] * V[3][1]
            Quad(gate=2, input_0=0, input_1=1, coefficient=field(1)),
            # Calculate -2 (for assertion).
            # V[2][3] = -2 * V[3][0] * V[3][0]
            Quad(gate=3, input_0=0, input_1=0, coefficient=-field(2)),
        ],
        field=field,
    )
    return Circuit(
        num_outputs=2,
        num_public_inputs=1,
        num_inputs=2,
        layers=[layer_0, layer_1, layer_2],
    )
