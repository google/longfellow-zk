import unittest

from fields import Fp256, GF2_128, GF2_16, GF2_16_inclusion_map, random_element

class TestFields(unittest.TestCase):
    def test_gf2_16_inclusion_map(self) -> None:
        # Confirm that GF(2^16) was constructed with the specified generator.
        power = (2 ** 128 - 1) // (2 ** 16 - 1)
        (x,) = GF2_128.gens()
        g_want = x ** power
        (g,) = GF2_16.gens()
        assert GF2_16_inclusion_map(g) == g_want

    def test_random(self) -> None:
        # Perform sanity check using Sage's Parent.__contains__. Note that
        # isinstance() does not work here, due to behind-the-scenes aspects
        # of Sage's factory methods, coercion rules, etc.
        r_prime = random_element(Fp256)
        assert r_prime in Fp256
        r_2k = random_element(GF2_128)
        assert r_2k in GF2_128
