import unittest

from merkle import MerkleTree


class TestMerkleTree(unittest.TestCase):
    def test_appendix_example(self):
        # Example from the test vector section in the Appendix.
        n = 5
        mt = MerkleTree(n)

        c0 = bytes.fromhex('4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a')
        c1 = bytes.fromhex('dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986')
        c3 = bytes.fromhex('e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71')
        mt.set_leaf(0, c0)
        mt.set_leaf(1, c1)
        mt.set_leaf(2,bytes.fromhex('084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5'))
        mt.set_leaf(3, c3)
        mt.set_leaf(4,bytes.fromhex('e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db'))

        root_hash = mt.build_tree()

        print(f"Merkle Root: {root_hash.hex()}")

        print(f"Requesting [0,1]:")
        req_leaves = [0, 1]
        proof = mt.compressed_proof(req_leaves)
        for p in proof:
            print(p.hex())
        assert mt.verify_merkle(root_hash, n, 2, [c0, c1], [0, 1], proof), "Bad proof"

        print(f"Requesting [1,3]:")
        req_leaves = [1, 3]
        proof = mt.compressed_proof(req_leaves)
        for p in proof:
            print(p.hex())
        assert mt.verify_merkle(root_hash, n, 2, [c1, c3], [1, 3], proof), "Bad proof"
