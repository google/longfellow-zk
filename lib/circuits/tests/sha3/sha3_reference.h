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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_SHA3_SHA3_REFERENCE_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_SHA3_SHA3_REFERENCE_H_

// !!!!! DO NOT USE IN PRODUCTION !!!!!

/* This is a simple reference implementation of sha3
   to be used to design zero-knowledge circuits.  DO NOT USE
   THIS CODE IN PRODUCTION. */
#include <cstdint>
#include <cstdlib>

namespace proofs {
class Sha3Reference {
  size_t mdlen_;
  size_t rate_;
  size_t wrptr_;
  uint8_t buf_[200];
  uint64_t a_[5][5];

  static void keccak_f_1600(uint64_t A[5][5]);
  static void shake(size_t rate, const uint8_t* in, size_t inlen, uint8_t* out,
                    size_t outlen);

 public:
  explicit Sha3Reference(size_t mdlen)
      : mdlen_(mdlen), rate_(200 - 2 * mdlen), wrptr_(0), buf_{}, a_{} {}

  void update(const char* data, size_t n);
  void final(uint8_t digest[/*mdlen*/]);

  static void keccak_f_1600_DEBUG_ONLY(uint64_t A[5][5]);
  static void theta(uint64_t A[5][5]);
  static void rho(uint64_t A[5][5]);
  static void pi(const uint64_t A[5][5], uint64_t A1[5][5]);
  static void chi(const uint64_t A1[5][5], uint64_t A[5][5]);
  static void iota(uint64_t A[5][5], size_t round);
  static void shake128Hash(const uint8_t* in, size_t inlen, uint8_t* out,
                           size_t outlen);
  static void shake256Hash(const uint8_t* in, size_t inlen, uint8_t* out,
                           size_t outlen);
  static void xorin(uint64_t A[5][5], const uint8_t* d, size_t n);

  // Keccak-256 as used by Ethereum.  Identical to SHA3-256 except the padding
  // byte is 0x01 instead of 0x06.  To derive an Ethereum address from a 64-byte
  // uncompressed public key (without the 0x04 prefix), hash those 64 bytes with
  // this function and take the last 20 bytes of the result.
  static void keccak256Hash(const uint8_t* in, size_t inlen, uint8_t out[32]);
};

}  // namespace proofs
#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_SHA3_SHA3_REFERENCE_H_
