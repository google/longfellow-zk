// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "merkle/merkle_tree.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <algorithm>
#include <vector>

#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

TEST(MerkleTree, BuildTree) {
  MerkleTree mt(4);
  Digest leaves[4] = {Digest{100}, Digest{101}, Digest{102}, Digest{103}};
  for (size_t i = 0; i < 4; i++) {
    mt.set_leaf(i, leaves[i]);
  }
  Digest root = mt.build_tree();
  EXPECT_EQ(mt.layers_[4], leaves[0]);
  EXPECT_EQ(mt.layers_[2], Digest::hash2(leaves[0], leaves[1]));
  EXPECT_EQ(mt.layers_[3], Digest::hash2(leaves[2], leaves[3]));
  EXPECT_EQ(mt.layers_[1], Digest::hash2(Digest::hash2(leaves[0], leaves[1]),
                                         Digest::hash2(leaves[2], leaves[3])));
  EXPECT_EQ(root, Digest::hash2(Digest::hash2(leaves[0], leaves[1]),
                                Digest::hash2(leaves[2], leaves[3])));
}


MerkleTree setupBatch(size_t n, size_t batch_size, std::vector<Digest>& leaves,
                      std::vector<size_t>& idx) {
  MerkleTree prover(n);
  uint8_t data = 1;
  for (size_t i = 0; i < n; i++) {
    prover.set_leaf(i, Digest{data});
    data += 1;
  }

  // Pick a random set of leaf indices with no repeats.
  for (size_t i = 0; i < batch_size; ++i) {
    size_t j = random() % n;
    // Rejection sampling is OK for small batch sizes.
    while (std::find(idx.begin(), idx.end(), j) != idx.end()) {
      j = random() % n;
    }
    idx.push_back(j);
    leaves.push_back(prover.layers_[j + n]);
  }
  return prover;
}

TEST(MerkleTree, VerifyCompressedProof) {
  std::vector<size_t> sizes{1, 10, 80};
  for (size_t testSize : sizes) {
    for (size_t n = 200; n <= 300; ++n) {
      std::vector<size_t> idx;
      std::vector<Digest> leaves;
      MerkleTree prover = setupBatch(n, testSize, leaves, idx);
      Digest root = prover.build_tree();
      std::vector<Digest> proof;
      size_t len = prover.generate_compressed_proof(proof, &idx[0], testSize);

      MerkleTreeVerifier verifier(n, root);
      EXPECT_TRUE(verifier.verify_compressed_proof(
          proof.data(), len, leaves.data(), idx.data(), idx.size()));
    }
  }
}

TEST(MerkleTree, VerifyCompressedProofFailure) {
  const size_t kTestSize = 80;
  for (size_t n = 200; n <= 300; ++n) {
    std::vector<size_t> idx;
    std::vector<Digest> leaves;
    MerkleTree prover = setupBatch(n, kTestSize, leaves, idx);
    Digest root = prover.build_tree();

    std::vector<Digest> proof;
    size_t len = prover.generate_compressed_proof(proof, &idx[0], kTestSize);
    MerkleTreeVerifier verifier(n, root);

    // Check that any bit flip fails the verification.
    for (size_t ei = 0; ei < proof.size(); ++ei) {
      proof[ei].data[0] ^= 1;
      EXPECT_FALSE(verifier.verify_compressed_proof(&proof[0], len, &leaves[0],
                                                    &idx[0], idx.size()));
      proof[ei].data[0] ^= 1;
    }
  }
}

TEST(MerkleTree, ZeroLengthProof) {
  Digest leaves[4] = {Digest{100}, Digest{101}, Digest{102}, Digest{103}};
  MerkleTree mt(4);
  for (size_t i = 0; i < 4; i++) {
    mt.set_leaf(i, leaves[i]);
  }
  Digest root = mt.build_tree();

  size_t ids[] = {0, 1, 2, 3};
  std::vector<Digest> empty_leaves;
  MerkleTreeVerifier verifier(4, root);
  std::vector<Digest> empty_proof;

  // Empty proof should fail.
  EXPECT_FALSE(
      verifier.verify_compressed_proof(empty_proof.data(), 0, leaves, ids, 1));

  // The valid case for a zero-length proof is when all the leaves are given.
  EXPECT_TRUE(
      verifier.verify_compressed_proof(empty_proof.data(), 0, leaves, ids, 4));
}

TEST(MerkleTree, UniqueLeaves) {
  Digest leaves[4] = {Digest{100}, Digest{101}, Digest{102}, Digest{103}};
  MerkleTree mt(4);
  for (size_t i = 0; i < 4; i++) {
    mt.set_leaf(i, leaves[i]);
  }
  Digest root = mt.build_tree();
  size_t ids[] = {1, 1};
  std::vector<Digest> ll = {leaves[1], leaves[1]};
  MerkleTreeVerifier verifier(4, root);
  std::vector<Digest> proof = {Digest::hash2(leaves[1], leaves[1])};

  EXPECT_DEATH(
      verifier.verify_compressed_proof(proof.data(), 1, leaves, ids, 2),
      "duplicate position in merkle tree requested");
}

TEST(MerkleTree, BatchVerifyProofTooShort) {
  std::vector<size_t> idx;
  std::vector<Digest> leaves;
  MerkleTree prover = setupBatch(300, 20, leaves, idx);
  Digest root = prover.build_tree();
  std::vector<Digest> proof;
  size_t len = prover.generate_compressed_proof(proof, &idx[0], 20);
  MerkleTreeVerifier verifier(300, root);

  EXPECT_FALSE(verifier.verify_compressed_proof(&proof[0], len - 1, &leaves[0],
                                                &idx[0], idx.size()));
}

void print_digest(const Digest& d) {
  for (size_t i = 0; i < Digest::kLength; ++i) {
    printf("%02x", d.data[i]);
  }
  printf("\n");
}

// Generates the test vectors for the RFC.
TEST(MerkleTree, TestVectors) {
  MerkleTree mt(5);
  Digest leaves[5] =
      {
          Digest{0x4b, 0xf5, 0x12, 0x2f, 0x34, 0x45, 0x54, 0xc5,
                 0x3b, 0xde, 0x2e, 0xbb, 0x8c, 0xd2, 0xb7, 0xe3,
                 0xd1, 0x60, 0x0a, 0xd6, 0x31, 0xc3, 0x85, 0xa5,
                 0xd7, 0xcc, 0xe2, 0x3c, 0x77, 0x85, 0x45, 0x9a},  // hash(01)
          Digest{0xdb, 0xc1, 0xb4, 0xc9, 0x00, 0xff, 0xe4, 0x8d,
                 0x57, 0x5b, 0x5d, 0xa5, 0xc6, 0x38, 0x04, 0x01,
                 0x25, 0xf6, 0x5d, 0xb0, 0xfe, 0x3e, 0x24, 0x49,
                 0x4b, 0x76, 0xea, 0x98, 0x64, 0x57, 0xd9, 0x86},  // hash(02)
          Digest{0x08, 0x4f, 0xed, 0x08, 0xb9, 0x78, 0xaf, 0x4d,
                 0x7d, 0x19, 0x6a, 0x74, 0x46, 0xa8, 0x6b, 0x58,
                 0x00, 0x9e, 0x63, 0x6b, 0x61, 0x1d, 0xb1, 0x62,
                 0x11, 0xb6, 0x5a, 0x9a, 0xad, 0xff, 0x29, 0xc5},  // hash(03)
          Digest{0xe5, 0x2d, 0x9c, 0x50, 0x8c, 0x50, 0x23, 0x47,
                 0x34, 0x4d, 0x8c, 0x07, 0xad, 0x91, 0xcb, 0xd6,
                 0x06, 0x8a, 0xfc, 0x75, 0xff, 0x62, 0x92, 0xf0,
                 0x62, 0xa0, 0x9c, 0xa3, 0x81, 0xc8, 0x9e, 0x71},  // hash(04)
          Digest{0xe7, 0x7b, 0x9a, 0x9a, 0xe9, 0xe3, 0x0b, 0x0d,
                 0xbd, 0xb6, 0xf5, 0x10, 0xa2, 0x64, 0xef, 0x9d,
                 0xe7, 0x81, 0x50, 0x1d, 0x7b, 0x6b, 0x92, 0xae,
                 0x89, 0xeb, 0x05, 0x9c, 0x5a, 0xb7, 0x43, 0xdb}  // hash(05)
      };
  for (size_t i = 0; i < 5; i++) {
    mt.set_leaf(i, leaves[i]);
  }
  Digest root = mt.build_tree();
  print_digest(root);

  std::vector<size_t> idx;
  std::vector<Digest> proof;
  idx.push_back(0);
  idx.push_back(1);
  size_t len = mt.generate_compressed_proof(proof, &idx[0], 2);
  printf("len = %zu\n", len);
  for (size_t i = 0; i < len; ++i) {
    print_digest(proof[i]);
  }

  // Example requires 3 elements in the proof.
  idx[0] = 1;
  idx[1] = 3;
  std::vector<Digest> proof2;
  len = mt.generate_compressed_proof(proof2, &idx[0], 2);
  printf("len = %zu\n", len);
  for (size_t i = 0; i < len; ++i) {
    print_digest(proof2[i]);
  }
}

// ============================= Benchmarks ===================================

void BM_MerkleTree_BuildTree(benchmark::State& state) {
  const size_t size = state.range(0);

  MerkleTree mt(size);
  std::vector<Digest> leaves(size);
  for (size_t i = 0; i < size; i++) {
    leaves[i] = Digest{static_cast<uint8_t>(i)};
    mt.set_leaf(i, leaves[i]);
  }

  for (auto s : state) {
    mt.build_tree();
  }
}
BENCHMARK(BM_MerkleTree_BuildTree)->RangeMultiplier(4)->Range(1024, 1 << 20);

}  // namespace
}  // namespace proofs
