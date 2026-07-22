from sage.rings.finite_rings.element_base import FiniteRingElement
from sage.rings.finite_rings.finite_field_base import FiniteField


class FiniteFieldFactory:
    def __init__(self, name: str) -> None: ...

    def __call__(self, order: int) -> FiniteField: ...


GF = FiniteFieldFactory("FiniteField")
