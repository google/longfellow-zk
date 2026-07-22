from __future__ import annotations

import sage.all
from sage.rings.finite_rings.element_base import FiniteRingElement
from sage.rings.finite_rings.finite_field_base import FiniteField

from sparse import SparseArray


class Circuit:
    def __init__(
            self,
            num_outputs: int,
            num_public_inputs: int,
            num_inputs: int,
            layers: list[CircuitLayer]) -> None:
        self.num_outputs = num_outputs
        self.log_num_outputs = (num_outputs - 1).bit_length()
        self.pub_in = num_public_inputs
        self.ninputs = num_inputs
        self.layers = layers

    def evaluate(self, inputs: list[FiniteRingElement]) -> list[list[FiniteRingElement]]:
        """
        Evaluates the circuit and returns all wire values.

        This takes in the circuit's inputs as a list of field elements. By
        convention, the first field element in the input list should be one.
        """
        field = inputs[0].parent()
        wires: list[list[FiniteRingElement]] = [[] for layer in self.layers]
        wires.append(inputs)
        for j in range(len(self.layers) - 1, -1, -1):
            layer = self.layers[j]
            inputs = wires[j + 1]
            outputs = wires[j]
            if j == 0:
                num_outputs = self.num_outputs
            else:
                num_outputs = self.layers[j - 1].num_input_wires
            outputs += [field.zero() for _ in range(num_outputs)]
            z_gates = set()
            for quad in layer.quads:
                if quad.coefficient.is_zero():
                    z_gates.add(quad.gate)
                    outputs[quad.gate] += (
                        inputs[quad.input_0] * inputs[quad.input_1]
                    )
                else:
                    outputs[quad.gate] += (
                        quad.coefficient
                        * inputs[quad.input_0]
                        * inputs[quad.input_1]
                    )
            for gate in z_gates:
                if not outputs[gate].is_zero():
                    raise ValueError("In-circuit assertion failed")
        return wires


class CircuitLayer:
    def __init__(
            self,
            num_input_wires: int,
            quads: list[Quad],
            field: FiniteField) -> None:
        """
        Constructs a layer of a circuit.

        Arguments:
        * `num_input_wires`: Number of input wires for this layer.
        * `quads`: List of quad terms in this layer, following the
          circuit serialization conventions. A value of zero indicates
          the term is part of the Z quad instead.
        """
        self.log_num_input_wires = (num_input_wires - 1).bit_length()
        self.num_input_wires = num_input_wires
        self.quads = quads
        self.quad = SparseArray(field)
        self.Z = SparseArray(field)
        for quad in quads:
            if quad.coefficient.is_zero():
                self.Z[
                    quad.gate,
                    quad.input_0,
                    quad.input_1,
                ] = quad.coefficient.parent().one()
            else:
                self.quad[
                    quad.gate,
                    quad.input_0,
                    quad.input_1,
                ] = quad.coefficient


class Quad:
    def __init__(
            self,
            gate: int,
            input_0: int,
            input_1: int,
            coefficient: FiniteRingElement) -> None:
        self.gate = gate
        self.input_0 = input_0
        self.input_1 = input_1
        self.coefficient = coefficient
