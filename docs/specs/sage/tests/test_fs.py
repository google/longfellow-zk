import unittest

from fields import Fp256, GF2_128
from fs import Transcript


class TestFiatShamir(unittest.TestCase):
    def test_example(self) -> None:
        t = Transcript()

        field = Fp256
        session_id = b"test"
        t.init(session_id)

        arr = bytearray()
        for bi in range(0, 100):
            arr.append(bi)
        t.write_bytes(bytes(arr))

        tv1 = [t.generate_field(field) for i in range(0,16)]
        for ti in tv1:
            print(ti.to_bytes().hex())
        
        t.write_field(field(7))

        tv2 = [t.generate_field(field) for i in range(0,16)]
        for ti in tv2:
            print(ti.to_bytes().hex())

        fe_array = [field(8), field(9)]
        t.write_field_element_array(fe_array)

        tv3 = [t.generate_field(field) for i in range(0,16)]
        for ti in tv3:
            print(ti.to_bytes().hex())

        t.write_bytes(b'nats')

        ns = [1, 1, 1, 2, 2, 2,  7,    7,    7,     7,     32,     32,     32,    32,
        256, 256, 256, 256, 1000, 10000, 60000, 65535, 100000, 100000]
        nats = [t.generate_nat(n) for n in ns]
        print(nats)

        t.write_bytes(b'choose')
        choose_sizes = [31, 32, 63, 64, 1000, 65535]
        for cs in choose_sizes:
            gotc = t.generate_nats_wo_replacement(cs, 20)
            print(gotc)

    def test_gf2_128(self) -> None:
        field = GF2_128
        t = Transcript()
        t.init(b"transcript binary field test")

        elem = t.generate_field(field)
        assert elem in field
        assert elem != field.zero()
        assert elem != field.one()

        t.write_field(elem)

        t.write_field_element_array([
            field.from_integer(10),
            field.from_integer(20),
            field.from_integer(30),
        ])
