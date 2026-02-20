import unittest

from fs import Transcript


class TestFiatShamir(unittest.TestCase):
    def test_example(self):
        t = Transcript()

        p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
        session_id = b"test"
        t.init(session_id)

        arr = bytearray()
        for bi in range(0, 100):
            arr.append(bi)
        t.write_bytes(arr)

        tv1 = [t.generate_field(p) for i in range(0,16)]
        for ti in tv1:
            print(hex(ti))
        
        t.write_field(7)

        tv2 = [t.generate_field(p) for i in range(0,16)]
        for ti in tv2:
            print(hex(ti))

        fe_array = [(8), (9)]
        t.write_field_element_array(fe_array)

        tv3 = [t.generate_field(p) for i in range(0,16)]
        for ti in tv3:
            print(hex(ti))

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
