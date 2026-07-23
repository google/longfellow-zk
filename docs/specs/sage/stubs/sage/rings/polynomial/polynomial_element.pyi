from typing import Self, overload


class Polynomial:
    @overload
    def __add__(self, right: Self) -> Self: ...
    @overload
    def __add__(self, right: int) -> Self: ...

    def __pow__(self, right: int) -> Self: ...
