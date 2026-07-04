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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BIP340_BIP340_GUARD_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BIP340_BIP340_GUARD_H_

#include <cstddef>
#include <cstdint>
#include <string>

#include "algebra/crt.h"

namespace proofs {

/// Returns the smallest power of two >= n.
inline size_t next_pow2(size_t n) {
  size_t p = 1;
  while (p < n) {
    p *= 2;
  }
  return p;
}

/// Guard: checks that the block_enc parameter for a CRT-backed secp256k1
/// proof is within the supported FFT size.  The CRT auxiliary primes support
/// a maximum FFT order of 2^22 (4,194,304).  If the padding required by
/// block_enc exceeds this, the proof will fail inside twiddle-factor
/// computation.  This function catches the problem early.
///
/// Returns a human-readable error string, or empty string if OK.
template <typename CRT>
inline std::string check_crt_block_enc(size_t block_enc) {
  constexpr uint64_t kMaxOrder = crt::kOmegaOrder;  // 2^22
  size_t pad = next_pow2(block_enc);
  if (pad > kMaxOrder) {
    return "CRT block_enc=" + std::to_string(block_enc) +
           " requires padding=" + std::to_string(pad) +
           " which exceeds CRT omega_order=" + std::to_string(kMaxOrder) +
           " (2^22).  Reduce circuit size or use a larger auxiliary prime "
           "basis.";
  }
  return "";
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_BIP340_BIP340_GUARD_H_
