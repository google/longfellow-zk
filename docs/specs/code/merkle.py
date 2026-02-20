## Code from the spec for operating on MerkleTree datastructures.

import hashlib

def hash(data):
    assert isinstance(data, bytes), "data not bytes"
    return hashlib.sha256(data).digest()

class MerkleTree:
    def __init__(self, n):
        self.n = n
        self.a = [b''] * (2 * n)

    def set_leaf(self, pos, leaf):
        """
        Sets a leaf at a specific position.
        pos: 0-based index relative to the leaves (0 to n-1)
        """
        assert 0 <= pos < self.n, f"{pos} is out of bounds"
        self.a[pos + self.n] = leaf

    def build_tree(self):
        """
        Computes the internal nodes from n-1 down to 1.
        Returns the root (M.a[1]).
        """
        for i in range(self.n - 1, 0, -1):
            left = self.a[2 * i]
            right = self.a[2 * i + 1]

            self.a[i] = hash(left + right)

        return self.a[1]
    
    def mark_tree(self, requested_leaves):
        marked = [False] * (2 * self.n)

        for i in requested_leaves:
            assert 0 <= i < self.n, f"invalid requested index {i}"
            marked[i + self.n] = True

        for i in range(self.n - 1, 0, -1):
            marked[i] = marked[2 * i] or marked[2 * i + 1]

        return marked

    def compressed_proof(self, requested_leaves):
        """
        Generates a compressed proof for the requested leaves.
        """
        proof = []

        marked = self.mark_tree(requested_leaves)

        for i in range(self.n - 1, 0, -1):
            if marked[i]:
                child = 2 * i

                # If the left child is marked, we need the right child (sibling).
                if marked[child]:
                    child += 1

                # If the identified child/sibling is NOT marked,
                # we must provide its hash in the proof so the verifier can calculate the parent.
                if not marked[child]:
                    proof.append(self.a[child])

        return proof

    def verify_merkle(self, root, n, k, s, indices, proof):
        """
        Verifies that the provided leaves (s) at specific positions (indices)
        are part of the Merkle tree defined by 'root'.
        
        :param root: The expected Root Hash
        :param n: Total number of leaves in the tree
        :param k: Number of leaves being verified
        :param s: List of leaf data/hashes to verify
        :param indices: List of positions for the leaves in 's'
        :param proof: List of proof hashes
        """
        tmp = [None] * (2 * n)
        defined = [False] * (2 * n)

        proof_index = 0

        if n != self.n: return False
        
        marked = self.mark_tree(indices)

        for i in range(n - 1, 0, -1):
            if marked[i]:
                child = 2 * i
                if marked[child]:
                    child += 1

                if not marked[child]:
                    if proof_index >= len(proof):
                        return False

                    tmp[child] = proof[proof_index]
                    proof_index += 1
                    defined[child] = True

        for i in range(k):
            pos = indices[i] + n
            tmp[pos] = s[i]
            defined[pos] = True

        for i in range(n - 1, 0, -1):
            if defined[2 * i] and defined[2 * i + 1]:
                left = tmp[2 * i]
                right = tmp[2 * i + 1]
                tmp[i] = hash(left + right)
                defined[i] = True

        return defined[1] and (tmp[1] == root)
