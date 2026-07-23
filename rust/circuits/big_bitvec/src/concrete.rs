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

use core_algebra::Nat;
use runtime_algebra::field::RuntimeField;

#[cfg(feature = "testonly")]
pub fn push_bitvec_nat<
    const W: usize,
    FR: RuntimeField<W> + core_algebra::SupportsNatConversions<W>,
>(
    fr: &FR,
    val: &FR::N,
    bits: usize,
    dest: &mut Vec<FR::E>,
) {
    for i in 0..bits {
        dest.push(if val.bit(i) { fr.one() } else { fr.zero() });
    }
}
