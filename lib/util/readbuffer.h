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

#ifndef PRIVACY_PROOFS_ZK_LIB_UTIL_READBUFFER_H_
#define PRIVACY_PROOFS_ZK_LIB_UTIL_READBUFFER_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "util/panic.h"

namespace proofs {

class ReadBuffer {
 public:
  explicit ReadBuffer(const uint8_t *buf, size_t sz)
      : buf_(buf), size_(sz), next_(0) {}

  explicit ReadBuffer(const std::vector<uint8_t> &v)
      : ReadBuffer(v.data(), v.size()) {}

  // no copies
  ReadBuffer(const ReadBuffer &) = delete;

  // TRUE if at least N bytes remain
  bool have(size_t n) const { return remaining() >= n; }

  size_t remaining() const {
    check(next_ <= size_, "next_ <= size_");
    return size_ - next_;
  }

  const uint8_t *next(size_t n) {
    check(have(n), "have(n)");
    const uint8_t *p = &buf_[next_];
    next_ += n;
    return p;
  }

  void next(size_t n, uint8_t dest[/*n*/]) {
    const uint8_t *p = next(n);
    for (size_t i = 0; i < n; ++i) {
      dest[i] = p[i];
    }
  }

 private:
  const uint8_t *buf_;
  size_t size_;
  size_t next_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_UTIL_READBUFFER_H_
