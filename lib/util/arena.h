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

#ifndef PRIVACY_PROOFS_ZK_LIB_UTIL_ARENA_H_
#define PRIVACY_PROOFS_ZK_LIB_UTIL_ARENA_H_

#include <cstddef>
#include <cstdint>
#include <memory_resource>

namespace proofs {

// Returns the current thread-local PMR memory resource.
// If an ArenaGuard is active, returns the arena resource.
// Otherwise, returns std::pmr::get_default_resource().
std::pmr::memory_resource* current_resource();

// RAII guard that installs a monotonic_buffer_resource backed by a
// caller-provided buffer as the thread-local memory resource.
// When the guard is destroyed, the previous resource is restored.
//
// The upstream is null_memory_resource(), so exhaustion throws
// std::bad_alloc rather than silently falling back to malloc.
class ArenaGuard {
 public:
  ArenaGuard(uint8_t* buf, size_t buf_size);
  ~ArenaGuard();
  ArenaGuard(const ArenaGuard&) = delete;
  ArenaGuard& operator=(const ArenaGuard&) = delete;

 private:
  std::pmr::monotonic_buffer_resource mbr_;
  std::pmr::memory_resource* prev_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_UTIL_ARENA_H_
