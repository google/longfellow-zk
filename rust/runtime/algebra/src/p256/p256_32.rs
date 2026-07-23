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

#[inline]
pub(crate) fn p256_reduction_step(a: &mut [Limb; 10]) {
    let r = a[0];
    // Subtract r at index 0 and 7:
    let l = [r, 0, 0, 0, 0, 0, 0, r, 0, 0];
    sub_limb(a, &l);
    // Add r at index 3, 6, and 8:
    let h = [r, 0, 0, r, 0, r];
    accum(a, 3, &h);
}

impl MontgomeryStrategy<{ 4 * crate::LIMBS_PER_U64 }> for P256Strategy {
    #[inline(always)]
    fn montgomery_mul(
        a: &mut [Limb; 8],
        b: &[Limb; 8],
        _modulo: &[Limb; 8],
        negm: &[Limb; 8],
        _m_prime: Limb,
    ) {
        let mut t = [0 as Limb; 17];
        crate::limb::mul_accum_zero(&mut t, 0, a[0], b);
        p256_reduction_step((&mut t[0..10]).try_into().unwrap());

        t[10] = 0;
        crate::limb::mul_accum(&mut t, 1, a[1], b);
        p256_reduction_step((&mut t[1..11]).try_into().unwrap());

        t[11] = 0;
        crate::limb::mul_accum(&mut t, 2, a[2], b);
        p256_reduction_step((&mut t[2..12]).try_into().unwrap());

        t[12] = 0;
        crate::limb::mul_accum(&mut t, 3, a[3], b);
        p256_reduction_step((&mut t[3..13]).try_into().unwrap());

        t[13] = 0;
        crate::limb::mul_accum(&mut t, 4, a[4], b);
        p256_reduction_step((&mut t[4..14]).try_into().unwrap());

        t[14] = 0;
        crate::limb::mul_accum(&mut t, 5, a[5], b);
        p256_reduction_step((&mut t[5..15]).try_into().unwrap());

        t[15] = 0;
        crate::limb::mul_accum(&mut t, 6, a[6], b);
        p256_reduction_step((&mut t[6..16]).try_into().unwrap());

        t[16] = 0;
        crate::limb::mul_accum(&mut t, 7, a[7], b);
        p256_reduction_step((&mut t[7..17]).try_into().unwrap());

        a.copy_from_slice(&t[8..16]);
        crate::limb::maybe_minus_m(a, t[16], negm);
    }
}
