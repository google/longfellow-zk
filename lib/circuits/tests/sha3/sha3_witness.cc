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

#include "circuits/tests/sha3/sha3_witness.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

#include "circuits/tests/sha3/sha3_reference.h"

namespace proofs {

void Sha3Witness::compute_witness_block(uint64_t A[5][5], BlockWitness& bw) {
  for (size_t round = 0; round < 24; ++round) {
    Sha3Reference::theta(A);
    Sha3Reference::rho(A);
    uint64_t A1[5][5];
    Sha3Reference::pi(A, A1);
    Sha3Reference::chi(A1, A);
    Sha3Reference::iota(A, round);

    std::memcpy(bw.a_intermediate[round], A, 25 * sizeof(uint64_t));
  }
}

void Sha3Witness::compute_witness_shake256(
    const std::vector<uint8_t>& seed, size_t outlen,
    std::vector<BlockWitness>& witnesses) {
  size_t rate = 136;
  uint64_t A[5][5];
  std::memset(A, 0, sizeof(A));

  uint8_t block[200] = {0};
  size_t ptr = 0;

  // Absorb phase
  for (size_t i = 0; i < seed.size(); ++i) {
    block[ptr++] = seed[i];
    if (ptr == rate) {
      Sha3Reference::xorin(A, block, rate);
      BlockWitness bw;
      compute_witness_block(A, bw);
      witnesses.push_back(bw);
      ptr = 0;
      std::memset(block, 0, rate);
    }
  }

  // Pad and absorb the last block (which might be empty or partial)
  block[ptr] ^= 0x1F;
  block[rate - 1] ^= 0x80;
  Sha3Reference::xorin(A, block, rate);
  BlockWitness bw;
  compute_witness_block(A, bw);
  witnesses.push_back(bw);

  // Squeeze phase
  size_t out_ptr = 0;
  while (out_ptr < outlen) {
    size_t take = std::min(rate, outlen - out_ptr);
    out_ptr += take;
    if (out_ptr < outlen) {
      BlockWitness bw_next;
      compute_witness_block(A, bw_next);
      witnesses.push_back(bw_next);
    }
  }
}

void Sha3Witness::compute_witness_keccak256(
    const std::vector<uint8_t>& seed, std::vector<BlockWitness>& witnesses) {
  constexpr size_t rate = 136;
  uint64_t A[5][5];
  std::memset(A, 0, sizeof(A));

  uint8_t block[200] = {0};
  size_t ptr = 0;

  for (size_t i = 0; i < seed.size(); ++i) {
    block[ptr++] = seed[i];
    if (ptr == rate) {
      Sha3Reference::xorin(A, block, rate);
      BlockWitness bw;
      compute_witness_block(A, bw);
      witnesses.push_back(bw);
      ptr = 0;
      std::memset(block, 0, rate);
    }
  }

  // Keccak-256 padding: 0x01 (SHAKE256 uses 0x1F, SHA3-256 uses 0x06).
  block[ptr] ^= 0x01;
  block[rate - 1] ^= 0x80;
  Sha3Reference::xorin(A, block, rate);
  BlockWitness bw;
  compute_witness_block(A, bw);
  witnesses.push_back(bw);
  // No squeeze phase: 32-byte output < 136-byte rate, already in final state.
}

}  // namespace proofs
