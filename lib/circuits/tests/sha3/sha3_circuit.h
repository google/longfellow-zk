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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_SHA3_SHA3_CIRCUIT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_SHA3_SHA3_CIRCUIT_H_

// ----------------------------------------------------------------------------
//
// !!!!! DO NOT USE IN PRODUCTION !!!!!
//
// This SHA3 circuit is an experimental implementation for research purposes.
// It has not been fully vetted and is not recommended for production use cases
// at this time.
//
// Sha3 and SHAKE256 are specified in
//
//      FIPS PUB 202
//      SHA-3 Standard: Permutation-Based Hash and
//      Extendable-Output Functions
//
//      https://nvlpubs.nist.gov/nistPubs/fips/nist.fips.202.pdf
//
// ----------------------------------------------------------------------------

#include <stddef.h>

#include <algorithm>
#include <cstdint>
#include <vector>

#include "circuits/tests/sha3/sha3_round_constants.h"
#include "circuits/tests/sha3/sha3_slicing.h"
#include "util/panic.h"

namespace proofs {
template <class LogicCircuit>
class Sha3Circuit {
  typedef typename LogicCircuit::template bitvec<64> v64;
  typedef typename LogicCircuit::template bitvec<8> v8;

  const LogicCircuit& lc_;

  v64 of_scalar(uint64_t x) const { return lc_.template vbit<64>(x); }

  // Implementation of Step 6 in Algorithm 8, page 18--19 of the spec.
  void xorin_block(v64 A[5][5], const std::vector<v8>& block, size_t rate) {
    size_t x = 0, y = 0;
    for (size_t i = 0; i < rate; i += 8) {
      v64 a;
      for (size_t b = 0; b < 8; ++b) {
        for (size_t j = 0; j < 8; ++j) {
          a[b * 8 + j] = block[i + b][j];
        }
      }
      A[x][y] = lc_.vxor(A[x][y], a);
      ++x;
      if (x == 5) {
        ++y;
        x = 0;
      }
    }
  }

  // FIPS 202 3.2.1, theta
  void theta(v64 A[5][5]) {
    // The reference computes a five-way xor
    //
    // C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]
    //
    // However, computing C[x] requires three levels of xor.
    // Instead, we write C[x] = C0[x] ^ C1[x] where
    //
    // C0[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3]
    // C1[x] = A[x][4]
    //
    // C0 requires two XOR levels, C1 is free.
    //
    // Later, the reference computes
    //
    //  D_x = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1)
    //
    // Similarly, we split D_x = D0_x ^ D1_x.
    v64 C0[5], C1[5];
    for (size_t x = 0; x < 5; ++x) {
      auto a01 = lc_.vxor(A[x][0], A[x][1]);
      auto a23 = lc_.vxor(A[x][2], A[x][3]);
      C0[x] = lc_.vxor(a23, a01);
      C1[x] = A[x][4];
    }

    for (size_t x = 0; x < 5; ++x) {
      v64 D0_x = lc_.vxor(C0[(x + 4) % 5], lc_.vrotl(C0[(x + 1) % 5], 1));
      v64 D1_x = lc_.vxor(C1[(x + 4) % 5], lc_.vrotl(C1[(x + 1) % 5], 1));
      for (size_t y = 0; y < 5; ++y) {
        // D1_x is available two levels before D0_x, so we xor
        // it in first.
        A[x][y] = lc_.vxor(A[x][y], D1_x);
        A[x][y] = lc_.vxor(A[x][y], D0_x);
      }
    }
  }

  // FIPS 202 3.2.2, rho
  void rho(v64 A[5][5]) {
    size_t x = 1, y = 0;
    for (size_t t = 0; t < 24; ++t) {
      A[x][y] = lc_.vrotl(A[x][y], sha3::sha3_rotc[t]);
      size_t nx = y, ny = (2 * x + 3 * y) % 5;
      x = nx;
      y = ny;
    }
  }

  // FIPS 202 3.2.3, pi
  void pi(const v64 A[5][5], v64 A1[5][5]) {
    for (size_t x = 0; x < 5; ++x) {
      for (size_t y = 0; y < 5; ++y) {
        A1[x][y] = A[(x + 3 * y) % 5][x];
      }
    }
  }

  // FIPS 202 3.2.4, chi
  void chi(const v64 A1[5][5], v64 A[5][5]) {
    for (size_t x = 0; x < 5; ++x) {
      for (size_t y = 0; y < 5; ++y) {
        A[x][y] = lc_.vxor(A1[x][y], lc_.vand(A1[(x + 2) % 5][y],
                                              lc_.vnot(A1[(x + 1) % 5][y])));
      }
    }
  }

  // FIPS 202 3.2.5, iota
  void iota(v64 A[5][5], size_t round) {
    A[0][0] = lc_.vxor(A[0][0], of_scalar(sha3::sha3_rc[round]));
  }

 public:
  explicit Sha3Circuit(const LogicCircuit& lc) : lc_(lc) {}

  struct BlockWitness {
    // One set of wires per round.  However the circuit only
    // uses rounds satisfying SHA3_SLICE_AT()
    v64 a_intermediate[24][5][5];

    void input(const LogicCircuit& lc) {
      for (size_t round = 0; round < 24; ++round) {
        if (sha3_slice_at(round)) {
          for (size_t x = 0; x < 5; ++x) {
            for (size_t y = 0; y < 5; ++y) {
              a_intermediate[round][x][y] = lc.template vinput<64>();
            }
          }
        }
      }
    }
  };

  // This version of the Keccak-f[1600] permutation does not use any witnesses.
  // It provides a baseline to measure the depth and computation required.
  void keccak_f_1600(v64 A[5][5]) {
    for (size_t round = 0; round < 24; ++round) {
      theta(A);
      rho(A);
      v64 A1[5][5];
      pi(A, A1);
      chi(A1, A);
      iota(A, round);
    }
  }

  void keccak_f_1600(v64 A[5][5], const BlockWitness& bw) {
    for (size_t round = 0; round < 24; ++round) {
      theta(A);
      rho(A);
      v64 A1[5][5];
      pi(A, A1);
      chi(A1, A);
      iota(A, round);

      if (sha3_slice_at(round)) {
        for (size_t x = 0; x < 5; ++x) {
          for (size_t y = 0; y < 5; ++y) {
            sha3_vassert_eq(A[x][y], bw.a_intermediate[round][x][y]);
            A[x][y] = bw.a_intermediate[round][x][y];
          }
        }
      }
    }
  }

  // Computes SHAKE256 hash of seed with output length outlen bytes, and stores
  // result in out.
  //
  // SHAKE256 is an extendable-output function (XOF) from Keccak family,
  // standardized in FIPS 202.
  //
  // Arguments:
  // - seed: Input message as a vector of v8.
  // - outlen: Desired output length in bytes.
  // - out: Output vector for hash result, resized to outlen v8.
  // - bws: Block witnesses for Keccak rounds. One witness is required for each
  //        call to keccak_f_1600, which occurs once per 136-byte block of
  //        padded input, and once per 136-byte block of squeezed output
  //        (except for the last block).
  //
  // Constraints:
  // The number of block witnesses bws.size() must be exactly equal to:
  // (seed.size() + 136) / 136 + (outlen == 0 ? 0 : (outlen - 1) / 136).
  void assert_shake256(const std::vector<v8>& seed, size_t outlen,
                       std::vector<v8>& out,
                       const std::vector<BlockWitness>& bws) {
    size_t rate = 136;  // shake256 rate
    // Calculate expected number of blocks
    size_t num_absorb_blocks = (seed.size() + rate) / rate;
    size_t num_squeeze_blocks = (outlen == 0) ? 0 : (outlen - 1) / rate;
    check(bws.size() == num_absorb_blocks + num_squeeze_blocks,
          "Incorrect number of BlockWitnesses");

    // Eagerly populate output
    out.resize(outlen);
    size_t out_ptr = 0;
    size_t sqz_req = 0;
    while (out_ptr < outlen) {
      std::vector<v8> squeeze_block(200);
      // It is possible to use a single index into A here,
      // but this more verbose sx,sy makes it easier to map
      // to the Fips spec.
      size_t sx = 0, sy = 0;
      for (size_t i = 0; i < rate; i += 8) {
        // Handle the awkward copy of v64 into v8s.
        for (size_t b = 0; b < 8; ++b) {
          for (size_t j = 0; j < 8; ++j) {
            squeeze_block[i + b][j] =
                bws[num_absorb_blocks - 1 + sqz_req]
                    .a_intermediate[23][sx][sy][b * 8 + j];
          }
        }
        ++sx;
        if (sx == 5) {
          ++sy;
          sx = 0;
        }
      }
      size_t take = std::min(rate, outlen - out_ptr);
      for (size_t i = 0; i < take; ++i) {
        out[out_ptr++] = squeeze_block[i];
      }
      sqz_req++;
    }

    // Evaluate blocks in parallel
    // Absorb phase
    std::vector<v8> block(200);  // invariant: block[] is zero-padded.
    for (size_t i = 0; i < 200; ++i) block[i] = lc_.template vbit<8>(0);
    size_t bw_idx = 0;
    size_t ptr = 0;

    for (size_t i = 0; i < seed.size(); ++i) {
      block[ptr++] = seed[i];
      if (ptr == rate) {
        v64 A_in[5][5];
        for (int x = 0; x < 5; ++x) {
          for (int y = 0; y < 5; ++y) {
            if (bw_idx == 0) {
              A_in[x][y] = lc_.template vbit<64>(0);
            } else {
              A_in[x][y] = bws[bw_idx - 1].a_intermediate[23][x][y];
            }
          }
        }

        xorin_block(A_in, block, rate);
        keccak_f_1600(A_in, bws[bw_idx++]);
        ptr = 0;
        for (size_t j = 0; j < 200; ++j) block[j] = lc_.template vbit<8>(0);
      }
    }

    // Pad and process the last block
    auto pad1 = lc_.template vbit<8>(0x1F);
    auto pad2 = lc_.template vbit<8>(0x80);
    block[ptr] = pad1;
    block[rate - 1] = lc_.vxor(block[rate - 1], pad2);

    v64 A_in[5][5];
    for (int x = 0; x < 5; ++x) {
      for (int y = 0; y < 5; ++y) {
        if (bw_idx == 0) {
          A_in[x][y] = lc_.template vbit<64>(0);
        } else {
          A_in[x][y] = bws[bw_idx - 1].a_intermediate[23][x][y];
        }
      }
    }

    xorin_block(A_in, block, rate);
    keccak_f_1600(A_in, bws[bw_idx++]);

    // Squeeze phase blocks
    for (size_t i = 0; i < num_squeeze_blocks; ++i) {
      v64 A_sqz[5][5];
      for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
          A_sqz[x][y] = bws[num_absorb_blocks - 1 + i].a_intermediate[23][x][y];
        }
      }
      keccak_f_1600(A_sqz, bws[bw_idx++]);
    }

    check(bw_idx == bws.size(), "Did not consume all BlockWitnesses");
  }

  // Identical to assert_shake256
  // except the padding byte is 0x01 instead of 0x1F, and output is fixed at
  // 32 bytes so there is no squeeze phase.
  //
  // For Ethereum address derivation: call with the 64-byte uncompressed public
  // key (x || y, no 0x04 prefix) and take out[12..31] as the address.
  void assert_keccak256(const std::vector<v8>& seed, std::vector<v8>& out,
                        const std::vector<BlockWitness>& bws) {
    constexpr size_t rate = 136;
    constexpr size_t outlen = 32;
    size_t num_absorb_blocks = (seed.size() + rate) / rate;
    // 32-byte output fits in the first rate-sized squeeze, so no extra blocks.
    check(bws.size() == num_absorb_blocks, "Incorrect number of BlockWitnesses");

    out.resize(outlen);

    // Eagerly bind output wires to the final absorbed state (round 23).
    // Must happen before the absorb loop so the wire refs are available.
    size_t out_ptr = 0;
    size_t sx = 0, sy = 0;
    for (size_t i = 0; i < outlen; i += 8) {
      for (size_t b = 0; b < 8; ++b) {
        for (size_t j = 0; j < 8; ++j) {
          out[out_ptr][j] =
              bws[num_absorb_blocks - 1].a_intermediate[23][sx][sy][b * 8 + j];
        }
        ++out_ptr;
      }
      ++sx;
      if (sx == 5) {
        ++sy;
        sx = 0;
      }
    }

    // Absorb phase.
    std::vector<v8> block(200);
    for (size_t i = 0; i < 200; ++i) block[i] = lc_.template vbit<8>(0);
    size_t bw_idx = 0;
    size_t ptr = 0;

    for (size_t i = 0; i < seed.size(); ++i) {
      block[ptr++] = seed[i];
      if (ptr == rate) {
        v64 A_in[5][5];
        for (int x = 0; x < 5; ++x) {
          for (int y = 0; y < 5; ++y) {
            if (bw_idx == 0) {
              A_in[x][y] = lc_.template vbit<64>(0);
            } else {
              A_in[x][y] = bws[bw_idx - 1].a_intermediate[23][x][y];
            }
          }
        }
        xorin_block(A_in, block, rate);
        keccak_f_1600(A_in, bws[bw_idx++]);
        ptr = 0;
        for (size_t j = 0; j < 200; ++j) block[j] = lc_.template vbit<8>(0);
      }
    }

    // Keccak-256 padding: 0x01 at ptr, 0x80 XOR'd at rate-1.
    // (SHAKE256 uses 0x1F here; SHA3-256 uses 0x06.)
    block[ptr] = lc_.vxor(block[ptr], lc_.template vbit<8>(0x01));
    block[rate - 1] = lc_.vxor(block[rate - 1], lc_.template vbit<8>(0x80));

    v64 A_in[5][5];
    for (int x = 0; x < 5; ++x) {
      for (int y = 0; y < 5; ++y) {
        if (bw_idx == 0) {
          A_in[x][y] = lc_.template vbit<64>(0);
        } else {
          A_in[x][y] = bws[bw_idx - 1].a_intermediate[23][x][y];
        }
      }
    }
    xorin_block(A_in, block, rate);
    keccak_f_1600(A_in, bws[bw_idx++]);

    check(bw_idx == bws.size(), "Did not consume all BlockWitnesses");
  }

  template <size_t I0, size_t I1>
  void sha3_vassert_eq_range(const v64& x, const v64& y) const {
    auto xx = lc_.as_scalar(lc_.template slice<I0, I1>(x));
    auto yy = lc_.as_scalar(lc_.template slice<I0, I1>(y));
    lc_.assert_eq(xx, yy);
  }

  void sha3_vassert_eq(const v64& x, const v64& y) const {
    if (LogicCircuit::Field::kSubFieldBits == 16) {
      sha3_vassert_eq_range<0, 16>(x, y);
      sha3_vassert_eq_range<16, 32>(x, y);
      sha3_vassert_eq_range<32, 48>(x, y);
      sha3_vassert_eq_range<48, 64>(x, y);
    } else {
      sha3_vassert_eq_range<0, 22>(x, y);
      sha3_vassert_eq_range<22, 43>(x, y);
      sha3_vassert_eq_range<43, 64>(x, y);
    }
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_SHA3_SHA3_CIRCUIT_H_
