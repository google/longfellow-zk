from __future__ import annotations

from collections.abc import Iterator

import sage.all
from sage.rings.finite_rings.element_base import FiniteRingElement
from sage.rings.finite_rings.finite_field_base import FiniteField


class DenseArray:
    entries: list[FiniteRingElement]

    def __init__(
            self,
            field: FiniteField,
            values: list[FiniteRingElement]) -> None:
        self.field = field
        self.values = values

    def __iter__(self) -> Iterator[FiniteRingElement]:
        return iter(self.values)

    def __getitem__(self, index: int) -> FiniteRingElement:
        if index < len(self.values):
            return self.values[index]
        else:
            return self.field.zero()

    def bind(self, x: FiniteRingElement) -> DenseArray:
        new = []
        for i in range(0, len(self.values), 2):
            new.append(
                (self.field.one() - x) * self[i]
                + x * self[i + 1]
            )
        return DenseArray(self.field, new)
