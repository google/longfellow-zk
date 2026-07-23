from sage.rings.finite_rings.element_base import FiniteRingElement


class FiniteFieldHomomorphism_generic:
    def __call__(self, x: FiniteRingElement) -> FiniteRingElement: ...
