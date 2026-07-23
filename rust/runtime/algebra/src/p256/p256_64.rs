// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{
    fp_generic::MontgomeryStrategy,
    limb::{accum, sub_limb},
    p256::P256Strategy,
    Limb,
};

#[inline(always)]
pub(crate) fn p256_reduction_step(a: &mut [Limb; 6]) {
    let r = a[0];
    let r_lo = r << 32;
    let r_hi = r >> 32;
    // Subtract r at index 0, and [r_lo, r_hi] at index 3 (2^224):
    sub_limb(a, &[r, 0, 0, r_lo, r_hi, 0]);
    // Add [r_lo, r_hi] at index 1 (2^96), and [r, r] at index 3 (2^192, 2^256):
    accum(a, 1, &[r_lo, r_hi, r, r]);
}

impl MontgomeryStrategy<{ 4 * crate::LIMBS_PER_U64 }> for P256Strategy {
    #[inline(always)]
    fn montgomery_mul(
        a: &mut [Limb; 4],
        b: &[Limb; 4],
        _modulo: &[Limb; 4],
        negm: &[Limb; 4],
        _m_prime: Limb,
    ) {
        let mut t = [0 as Limb; 9];
        crate::limb::mul_accum_zero(&mut t, 0, a[0], b);
        p256_reduction_step((&mut t[0..6]).try_into().unwrap());

        t[6] = 0;
        crate::limb::mul_accum(&mut t, 1, a[1], b);
        p256_reduction_step((&mut t[1..7]).try_into().unwrap());

        t[7] = 0;
        crate::limb::mul_accum(&mut t, 2, a[2], b);
        p256_reduction_step((&mut t[2..8]).try_into().unwrap());

        t[8] = 0;
        crate::limb::mul_accum(&mut t, 3, a[3], b);
        p256_reduction_step((&mut t[3..9]).try_into().unwrap());

        a.copy_from_slice(&t[4..8]);
        crate::limb::maybe_minus_m(a, t[8], negm);
    }
}
