import sage.all
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.rings.polynomial.polynomial_ring import polygen


def _make_gf2_128():
    x = polygen(GF2)
    return GF2.extension(x ** 128 + x ** 7 + x ** 2 + x + 1, name="x")


def _make_quadratic_extension(base):
    x = polygen(base)
    return base.extension(x ** 2 + 1, name="x")


# Construct prime-order fields.
Fp64 = GF(2 ** 64 - 59)
Fp128 = GF(2 ** 128 - 2 ** 108 + 1)
Fp256 = GF(2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1)
Fp384 = GF(2 ** 384 - 2 ** 128 - 2 ** 96 + 2 ** 32 - 1)
Fp521 = GF(2 ** 521 - 1)

# Construct fields of characteristic two.
GF2 = GF(2)
GF2_128 = _make_gf2_128()
GF2_16, GF2_16_inclusion_map = GF2_128.subfield(16, name="g", map=True)

# Construct quadratic extension fields.
Fp64_2 = _make_quadratic_extension(Fp64)
Fp256_2 = _make_quadratic_extension(Fp256)

if __name__ == "__main__":
    # Confirm that GF(2^16) was constructed with the specified generator.
    power = (2 ** 128 - 1) // (2 ** 16 - 1)
    (x,) = GF2_128.gens()
    g_want = x ** power
    (g,) = GF2_16.gens()
    assert GF2_16_inclusion_map(g) == g_want

