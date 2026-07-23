from typing import overload

from sage.rings.finite_rings.element_base import FiniteRingElement
from sage.rings.polynomial.multi_polynomial import MPolynomial

class MPolynomialRing_base:
    def gens(self) -> tuple[MPolynomial, ...]: ...

    # Hoisted from Ring, so we can exactly specify the return type.
    def zero(self) -> MPolynomial: ...

    # Moved from PolynomialRing_field for simplicity.
    def lagrange_polynomial(self, points: list[tuple[FiniteRingElement, FiniteRingElement]]) -> MPolynomial: ...
