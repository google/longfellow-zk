from sage.rings.finite_rings.finite_field_base import FiniteField
from sage.rings.polynomial.polynomial_element import Polynomial


def polygen(ring: FiniteField, name: str = "x") -> Polynomial: ...
