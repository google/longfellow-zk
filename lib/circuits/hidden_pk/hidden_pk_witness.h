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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HIDDEN_PK_HIDDEN_PK_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HIDDEN_PK_HIDDEN_PK_WITNESS_H_

// Witness computation for HiddenPKCircuit.
//
// Given (pkx, pky, e, r, s) in the secp256k1 scalar/base fields, this class
// computes all private witness values needed by the circuit and fills a
// DenseFiller for use with ZkProver.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "arrays/dense.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/tests/sha3/sha3_reference.h"
#include "circuits/tests/sha3/sha3_witness.h"
#include "ec/p256k1.h"

namespace proofs {

class HiddenPKWitness {
 public:
  using Field  = Fp256k1Base;
  using EC     = P256k1;
  using Scalar = Fp256k1Scalar;
  using Elt    = typename Field::Elt;
  using Nat    = typename Field::N;

  static constexpr size_t kBits         = EC::kBits;
  static constexpr size_t kKeccakBlocks = 1;

  // Field elements (Montgomery-encoded).
  Elt pkx_;
  Elt pky_;

  // Keccak-256 block witness (1 block for 64-byte input).
  Sha3Witness::BlockWitness keccak_bw_;

  // ECDSA verify witness.
  VerifyWitness3<EC, Scalar> ecdsa_;

  explicit HiddenPKWitness() : ecdsa_(p256k1_scalar, p256k1) {}

  // Compute all witness values.
  // Returns false if the ECDSA witness computation fails (bad signature).
  bool compute(const Elt& pkx, const Elt& pky,
               const Nat& e, const Nat& r, const Nat& s) {
    pkx_ = pkx;
    pky_ = pky;

    const Field& F = p256k1_base;

    // 1. Compute ECDSA witnesses.
    if (!ecdsa_.compute_witness(pkx, pky, e, r, s)) {
      return false;
    }

    // 2. Build the 64-byte Keccak message: pkx_bytes || pky_bytes (big-endian).
    uint8_t msg[64] = {};
    Nat nx = F.from_montgomery(pkx);
    Nat ny = F.from_montgomery(pky);

    for (size_t i = 0; i < 32; ++i) {
      uint8_t bx = 0, by = 0;
      for (int j = 0; j < 8; ++j) {
        if (nx.bit(255 - (i * 8 + j))) bx |= (1u << (7 - j));
        if (ny.bit(255 - (i * 8 + j))) by |= (1u << (7 - j));
      }
      msg[i]      = bx;
      msg[32 + i] = by;
    }

    // 3. Compute Keccak-256 block witnesses.
    std::vector<uint8_t> seed(msg, msg + 64);
    std::vector<Sha3Witness::BlockWitness> bws;
    Sha3Witness::compute_witness_keccak256(seed, bws);
    keccak_bw_ = bws[0];

    return true;
  }

  // Return the Ethereum address: last 20 bytes of keccak256(pkx || pky).
  std::vector<uint8_t> eth_address_bytes() const {
    const Field& F = p256k1_base;
    uint8_t msg[64] = {};
    Nat nx = F.from_montgomery(pkx_);
    Nat ny = F.from_montgomery(pky_);
    for (size_t i = 0; i < 32; ++i) {
      uint8_t bx = 0, by = 0;
      for (int j = 0; j < 8; ++j) {
        if (nx.bit(255 - (i * 8 + j))) bx |= (1u << (7 - j));
        if (ny.bit(255 - (i * 8 + j))) by |= (1u << (7 - j));
      }
      msg[i]      = bx;
      msg[32 + i] = by;
    }
    uint8_t hash[32];
    Sha3Reference::keccak256Hash(msg, 64, hash);
    return std::vector<uint8_t>(hash + 12, hash + 32);
  }

  // Fill a DenseFiller with all private witness values.
  void fill_witness(DenseFiller<Field>& filler) const {
    const Field& F = p256k1_base;

    // pk_x and pk_y as field elements.
    filler.push_back(pkx_);
    filler.push_back(pky_);

    // Bit decompositions: LSB-first (bit 0 = LSB of the integer).
    Nat nx = F.from_montgomery(pkx_);
    Nat ny = F.from_montgomery(pky_);
    for (size_t i = 0; i < kBits; ++i)
      filler.push_back(F.of_scalar(nx.bit(i)));
    for (size_t i = 0; i < kBits; ++i)
      filler.push_back(F.of_scalar(ny.bit(i)));

    // Keccak-256 block witness bits.
    Sha3Witness::fill_witness(filler, keccak_bw_, F);

    // ECDSA verify witnesses.
    ecdsa_.fill_witness(filler);
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HIDDEN_PK_HIDDEN_PK_WITNESS_H_
