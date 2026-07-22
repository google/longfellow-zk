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

#ifndef PRIVACY_PROOFS_ZK_LIB_UTIL_POWER_OF_TWO_H_
#define PRIVACY_PROOFS_ZK_LIB_UTIL_POWER_OF_TWO_H_

#include <cstddef>

namespace proofs {

// Returns the smallest power of two that is at least n.
inline size_t next_power_of_two(size_t n) {
  size_t result = 1;
  while (result < n) {
    result *= 2;
  }
  return result;
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_UTIL_POWER_OF_TWO_H_
