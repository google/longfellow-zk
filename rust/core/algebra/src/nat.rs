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

pub trait Nat<const W: usize>: Clone + Eq + Ord + PartialOrd + std::fmt::Debug {
    fn to_limbs(&self) -> [u64; W];
    fn from_limbs(limbs: &[u64; W]) -> Self;
    fn from_u64(val: u64) -> Self;
    fn to_bytes_le(&self) -> Vec<u8>;
    fn from_bytes_le(bytes: &[u8]) -> Self;
    #[must_use]
    fn from_bytes_be(bytes: &[u8]) -> Self {
        let mut le_bytes = bytes.to_vec();
        le_bytes.reverse();
        le_bytes.resize(W * 8, 0);
        Self::from_bytes_le(&le_bytes)
    }

    fn bit(&self, i: usize) -> bool;

    fn to_bits(&self, n: usize) -> Vec<bool>;
}
