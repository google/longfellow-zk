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

#include "util/crypto.h"

#include <cstddef>
#include <cstdint>

#include "util/panic.h"

#ifdef __APPLE__
#include <Security/SecRandom.h>
#else
#include "openssl/rand.h"
#endif

namespace proofs {

void rand_bytes(uint8_t out[/*n*/], size_t n) {
#ifdef __APPLE__
  int ret = SecRandomCopyBytes(kSecRandomDefault, n, out);
  check(ret == errSecSuccess, "SecRandomCopyBytes failed");
#else
  int ret = RAND_bytes(out, n);
  check(ret == 1, "openssl RAND_bytes failed");
#endif
}

void hex_to_str(char out[/* 2*n + 1*/], const uint8_t in[/*n*/], size_t n) {
  for (size_t i = 0; i < n; ++i) {
    out[2 * i] = "0123456789abcdef"[in[i] >> 4];
    out[2 * i + 1] = "0123456789abcdef"[in[i] & 0xf];
  }
  out[2 * n] = '\0';
}


}  // namespace proofs
