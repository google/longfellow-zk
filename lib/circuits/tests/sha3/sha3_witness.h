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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_SHA3_SHA3_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_SHA3_SHA3_WITNESS_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "arrays/dense.h"
#include "circuits/tests/sha3/sha3_slicing.h"

namespace proofs {

struct Sha3Witness {
  struct BlockWitness {
    // The witnesses are not sliced---we produce a witness for
    // every round.  The circuit and the filler may or may
    // not use all values depending on the slicing parameters
    uint64_t a_intermediate[24][5][5];
  };

  // Runs one block of the keccak permutation on state A, recording
  // intermediates into bw. Note: state A is updated in-place to the new state.
  static void compute_witness_block(uint64_t A[5][5], BlockWitness& bw);

  // Generate BlockWitnesses for a shake256 computation.
  static void compute_witness_shake256(const std::vector<uint8_t>& seed,
                                       size_t outlen,
                                       std::vector<BlockWitness>& witnesses);

  // Generate BlockWitnesses for a keccak256 computation (Ethereum's hash).
  // Padding byte is 0x01 instead of SHAKE256's 0x1F.  Output is always 32
  // bytes so no squeeze-phase witnesses are needed.
  static void compute_witness_keccak256(const std::vector<uint8_t>& seed,
                                        std::vector<BlockWitness>& witnesses);

  // Fills a Dense array mapping with exactly the bit outputs of the block
  // witnesses.
  template <class Field>
  static void fill_witness(DenseFiller<Field>& filler, const BlockWitness& w,
                           const Field& f) {
    for (size_t round = 0; round < 24; ++round) {
      if (sha3_slice_at(round)) {
        for (size_t x = 0; x < 5; ++x) {
          for (size_t y = 0; y < 5; ++y) {
            uint64_t val = w.a_intermediate[round][x][y];
            filler.push_back(val, 64, f);
          }
        }
      }
    }
  }
  template <class Field>
  static void fill_witness(DenseFiller<Field>& filler,
                           const std::vector<BlockWitness>& bws,
                           const Field& f) {
    for (const auto& w : bws) {
      fill_witness(filler, w, f);
    }
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_SHA3_SHA3_WITNESS_H_
