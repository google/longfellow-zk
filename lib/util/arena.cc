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

#include "util/arena.h"

namespace proofs {

static thread_local std::pmr::memory_resource* tl_resource = nullptr;

std::pmr::memory_resource* current_resource() {
  return tl_resource ? tl_resource : std::pmr::get_default_resource();
}

ArenaGuard::ArenaGuard(uint8_t* buf, size_t buf_size)
    : mbr_(buf, buf_size, std::pmr::null_memory_resource()),
      prev_(tl_resource) {
  tl_resource = &mbr_;
}

ArenaGuard::~ArenaGuard() { tl_resource = prev_; }

}  // namespace proofs
