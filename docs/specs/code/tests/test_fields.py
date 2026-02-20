import unittest

from fields import GF2_128, GF2_16, GF2_16_inclusion_map

class TestFields(unittest.TestCase):
    def test_gf2_16_inclusion_map(self):
        # Confirm that GF(2^16) was constructed with the specified generator.
        power = (2 ** 128 - 1) // (2 ** 16 - 1)
        (x,) = GF2_128.gens()
        g_want = x ** power
        (g,) = GF2_16.gens()
        assert GF2_16_inclusion_map(g) == g_want
