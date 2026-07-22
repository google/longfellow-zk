from __future__ import annotations

import collections
import copy
from typing import DefaultDict, Self

import sage.all
from sage.rings.finite_rings.element_base import FiniteRingElement
from sage.rings.finite_rings.finite_field_base import FiniteField


class SparseArray:
    entries: DefaultDict[tuple[int, ...], FiniteRingElement]

    def __init__(self, field: FiniteField) -> None:
        self.field = field
        self.entries = collections.defaultdict(field.zero)

    def __getitem__(self, key: tuple[int, ...]) -> FiniteRingElement:
        return self.entries[key]

    def __setitem__(self, key: tuple[int, ...], value: FiniteRingElement) -> None:
        self.entries[key] = value

    def __mul__(self, other: FiniteRingElement) -> SparseArray:
        result = SparseArray(self.field)
        for key, value in self.entries.items():
            result.entries[key] = value * other
        return result

    def __rmul__(self, other: FiniteRingElement) -> SparseArray:
        return self * other

    def __add__(self, other: Self) -> SparseArray:
        result = SparseArray(self.field)
        result.entries = copy.copy(self.entries)
        for key, value in other.entries.items():
            result.entries[key] += value
        return result

    def bind(self, x: FiniteRingElement, axis: int = 0) -> SparseArray:
        result = SparseArray(x.parent())
        for key, value in self.entries.items():
            new_key = key[:axis] + (key[axis] // 2,) + key[axis + 1:]
            if key[axis] & 1:
                result[new_key] += x * value
            else:
                result[new_key] += value - x * value
        return result

    def bindv(self, xs: list[FiniteRingElement], axis: int = 0) -> SparseArray:
        result = self
        for x in xs:
            result = result.bind(x, axis)
        return result

    def drop_dimension(self) -> SparseArray:
        """
        Removes the first dimension from a sparse array.

        Every nonzero element should already have a zero index along
        this dimension.
        """
        result = SparseArray(self.field)
        for key, value in self.entries.items():
            if key[0] != 0:
                raise ValueError("Tried to drop dimension with non-zero indices")
            result[key[1:]] = value
        return result
