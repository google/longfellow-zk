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

pub mod array;
pub mod memoize;
pub mod morton;

/// Computes the ceiling of the base-2 logarithm: ceil(log2(n)).
/// Panics if n == 0.
#[must_use]
pub fn ceil_log2(n: usize) -> usize {
    match n {
        0 => panic!("log2 of zero is undefined"),
        1 => 0,
        _ => (n - 1).ilog2() as usize + 1,
    }
}
