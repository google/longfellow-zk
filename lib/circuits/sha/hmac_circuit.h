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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SHA_HMAC_CIRCUIT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SHA_HMAC_CIRCUIT_H_

#include <stddef.h>
#include <vector>

#include "circuits/sha/flatsha256_circuit.h"

namespace proofs {

// HMAC_Circuit
//
// Implements the HMAC-SHA256 function as an arithmetic circuit over field F.
// HMAC(K, m) = H((K ^ opad) || H((K ^ ipad) || m))
//
// Where:
// - H is SHA256
// - K is the key (padded with 0s to the block size of SHA256, 64 bytes)
// - m is the message
// - opad is the byte 0x5c repeated 64 times
// - ipad is the byte 0x36 repeated 64 times
template <class Logic, class BitPlucker>
class HMAC_Circuit {
 public:
  using v8 = typename Logic::v8;
  using v256 = typename Logic::v256;
  using Flatsha = FlatSHA256Circuit<Logic, BitPlucker>;
  using BlockWitness = typename Flatsha::BlockWitness;

  const Logic& l_;
  const Flatsha& sha_;

  HMAC_Circuit(const Logic& l, const Flatsha& sha) : l_(l), sha_(sha) {}

  // Computes the HMAC-SHA256 hash of a message using the provided key.
  // This circuit assumes the caller has already padded the message according to 
  // the SHA-256 specification. It prepends the K^ipad block internally before 
  // computing the inner hash.
  //
  // Arguments:
  // - key:               The 64-byte HMAC key. If the original key is shorter, it must be 
  //                      0-padded to 64 bytes by the caller.
  // - inner_max_blocks:  The maximum number of 64-byte blocks in the padded inner hash input.
  //                      This reflects the upper bound of the inner message length.
  // - inner_nb:          The actual number of 64-byte blocks used in the inner hash input (1-indexed).
  // - inner_padded_m:    The padded message 'm_pad'. MUST NOT INCLUDE THE KEY. It only 
  //                      contains the message 'm' and its SHA-256 padding. Its length must
  //                      be (inner_max_blocks - 1) * 64 bytes.
  // - inner_bw:          The circuit witness for the inner hashing operation.
  // - outer_bw:          The circuit witness for the outer hashing operation.
  //
  // Returns:
  //   A 256-bit vector (v256) representing the computed HMAC.
  v256 compute_hmac(const v8 key[64], 
                   size_t inner_max_blocks, const v8 inner_nb, const v8 inner_padded_m[], const BlockWitness inner_bw[],
                   const BlockWitness outer_bw[1]) const {
    // 1. Compute K ^ ipad and K ^ opad
    v8 k_ipad[64];
    v8 k_opad[64];
    for (size_t i = 0; i < 64; ++i) {
      v8 ipad_byte = l_.template vbit<8>(0x36);
      v8 opad_byte = l_.template vbit<8>(0x5c);
      k_ipad[i] = l_.vxor(&key[i], ipad_byte);
      k_opad[i] = l_.vxor(&key[i], opad_byte);
    }

    // 2. Inner Hash: H( (K ^ ipad) || m_pad )
    // We construct the full input to the inner hash by prepending K^ipad
    // to inner_padded_m.
    // inner_padded_m has size (inner_max_blocks - 1) * 64
    std::vector<v8> inner_in(inner_max_blocks * 64);
    for (size_t i = 0; i < 64; ++i) {
      inner_in[i] = k_ipad[i];
    }
    for (size_t i = 0; i < (inner_max_blocks - 1) * 64; ++i) {
      inner_in[64 + i] = inner_padded_m[i];
    }
    
    // Check that inner_bw calculates the correct hash
    // We don't verify the final target yet, we just reconstruct it from the witness.
    sha_.assert_message(inner_max_blocks, inner_nb, inner_in.data(), inner_bw);

    // Extract the inner hash from the witness at block index inner_nb - 1
    v256 inner_hash;
    // We must conditionally extract the hash based on inner_nb just like FlatSHA256Circuit::assert_hash does
    typename BitPlucker::packed_v32 x[8];
    for (size_t b = 0; b < inner_max_blocks; ++b) {
      auto bt = l_.veq(inner_nb, b + 1); /* b is zero-indexed */
      auto ebt = l_.eval(bt);
      for (size_t i = 0; i < 8; ++i) {
        for (size_t k = 0; k < sha_.bp_.kNv32Elts; ++k) {
          if (b == 0) {
            x[i][k] = l_.mul(&ebt, inner_bw[b].h1[i][k]);
          } else {
            auto maybe_sha = l_.mul(&ebt, inner_bw[b].h1[i][k]);
            x[i][k] = l_.add(&x[i][k], maybe_sha);
          }
        }
      }
    }
    
    // Unpack inner hash into v256 (reverse byte order)
    for (size_t j = 0; j < 8; ++j) {
      auto hj = sha_.bp_.unpack_v32(x[j]);
      for (size_t k = 0; k < 32; ++k) {
        inner_hash[((7 - j) * 32 + k)] = hj[k];
      }
    }

    // Convert v256 (32 bytes) inner hash into v8[32] for padding
    v8 inner_hash_bytes[32];
    for (size_t i = 0; i < 32; ++i) {
      for (size_t k = 0; k < 8; ++k) {
        size_t j = 8 * (31 - i) + k;
        inner_hash_bytes[i][k] = inner_hash[j];
      }
    }

    // 3. Outer Hash: H( (K ^ opad) || inner_hash )
    // The length of (K ^ opad) || inner_hash is 64 + 32 = 96 bytes.
    // This requires 2 blocks of SHA256 when padded.
    // Padding: append 0x80, then 0s, then length in bits (96 * 8 = 768 = 0x0300).
    const size_t outer_max_blocks = 2;
    v8 outer_in[outer_max_blocks * 64];
    for (size_t i = 0; i < 64; ++i) {
      outer_in[i] = k_opad[i];
    }
    for (size_t i = 0; i < 32; ++i) {
      outer_in[64 + i] = inner_hash_bytes[i];
    }
    
    // Add SHA256 padding for 96 bytes
    outer_in[96] = l_.template vbit<8>(0x80);
    for (size_t i = 97; i < 126; ++i) {
      outer_in[i] = l_.template vbit<8>(0x00);
    }
    outer_in[126] = l_.template vbit<8>(0x03); // 768 bits
    outer_in[127] = l_.template vbit<8>(0x00); 

    v8 outer_nb = l_.template vbit<8>(2);

    // Generate outer hash
    sha_.assert_message(outer_max_blocks, outer_nb, outer_in, outer_bw);

    // Extract outer hash
    typename BitPlucker::packed_v32 y[8];
    for (size_t b = 0; b < outer_max_blocks; ++b) {
      auto bt = l_.veq(outer_nb, b + 1);
      auto ebt = l_.eval(bt);
      for (size_t i = 0; i < 8; ++i) {
        for (size_t k = 0; k < sha_.bp_.kNv32Elts; ++k) {
          if (b == 0) {
            y[i][k] = l_.mul(&ebt, outer_bw[b].h1[i][k]);
          } else {
            auto maybe_sha = l_.mul(&ebt, outer_bw[b].h1[i][k]);
            y[i][k] = l_.add(&y[i][k], maybe_sha);
          }
        }
      }
    }

    v256 outer_hash;
    for (size_t j = 0; j < 8; ++j) {
      auto hj = sha_.bp_.unpack_v32(y[j]);
      for (size_t k = 0; k < 32; ++k) {
        outer_hash[((7 - j) * 32 + k)] = hj[k];
      }
    }
    return outer_hash;
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SHA_HMAC_CIRCUIT_H_
