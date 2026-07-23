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

pub use crate::arch::{
    gf2_128_accum_reduce as arch_accum_reduce, gf2_128_mac as arch_mac, gf2_128_mul as arch_mul,
    Gf2_128, Gf2_128Accum,
};
use crate::field::{AlgebraicField, RuntimeBinaryField, RuntimeField};

impl Gf2_128 {
    #[inline(always)]
    const fn new(v: u128) -> Self {
        Self::from_u128(v)
    }

    #[inline(always)]
    #[must_use]
    pub fn bit(&self, i: usize) -> bool {
        if i < 128 {
            ((self.to_u128() >> i) & 1) != 0
        } else {
            false
        }
    }

    #[inline(always)]
    pub(crate) fn add(&mut self, other: &Self) {
        self.xor_in_place(other);
    }
}

impl From<u128> for Gf2_128 {
    #[inline(always)]
    fn from(v: u128) -> Self {
        Self::from_u128(v)
    }
}

const XINV: Gf2_128 = Gf2_128::new(0x8000_0000_0000_0000_0000_0000_0000_0043);

#[inline(always)]
fn invert(e: Gf2_128) -> Gf2_128 {
    let zero = Gf2_128::from_u128(0);
    let one = Gf2_128::from_u128(1);

    let mut a_curr = e;
    let mut bm1ox = XINV;
    let mut u = one;
    let mut v = zero;

    while a_curr != zero {
        let val = a_curr.to_u128();
        let bit = (val & 1) as u64;
        let atmp = Gf2_128::from_u128(val >> 1);
        if bit == 0 {
            a_curr = atmp;
            u = arch_mul(XINV, u);
        } else {
            let am1ox = atmp;
            let (new_am1ox, new_bm1ox, new_u, new_v) = if am1ox.to_u128() < bm1ox.to_u128() {
                (bm1ox, am1ox, v, u)
            } else {
                (am1ox, bm1ox, u, v)
            };

            a_curr = new_am1ox.xor(&new_bm1ox);
            bm1ox = new_bm1ox;
            let sub_u_v = new_u.xor(&new_v);
            u = arch_mul(XINV, sub_u_v);
            v = new_v;
        }
    }
    v
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gf2_128Field {
    cantor_basis: [Gf2_128; 128],
    poly_evaluation_points: [Gf2_128; 6],
    newton_denominators: [[Gf2_128; 6]; 6],
}

impl Gf2_128Field {
    pub fn new() -> Self {
        let cantor_basis = core_algebra::CANTOR_BASIS_U128.map(Gf2_128::from);

        let mut poly_evaluation_points = [Gf2_128::default(); 6];
        for (pt, raw) in poly_evaluation_points
            .iter_mut()
            .zip(core_algebra::proto::POLY_EVALUATION_POINTS)
        {
            *pt = Gf2_128::from(raw);
        }

        let mut newton_denominators = [[Gf2_128::default(); 6]; 6];
        for k in 1..6 {
            for i in 1..=k {
                let diff = poly_evaluation_points[k].xor(&poly_evaluation_points[k - i]);
                newton_denominators[k][i] = invert(diff);
            }
        }

        Self {
            cantor_basis,
            poly_evaluation_points,
            newton_denominators,
        }
    }
}

impl Default for Gf2_128Field {
    fn default() -> Self {
        Self::new()
    }
}

impl core_algebra::BareField for Gf2_128Field {
    type E = Gf2_128;
}

impl core_algebra::AlgebraicField for Gf2_128Field {
    #[inline(always)]
    fn zero(&self) -> Self::E {
        Gf2_128::default()
    }

    #[inline(always)]
    fn one(&self) -> Self::E {
        Gf2_128::from(1)
    }

    #[inline(always)]
    fn add(&self, e1: &mut Self::E, e2: &Self::E) {
        e1.xor_in_place(e2);
    }

    #[inline(always)]
    fn sub(&self, e1: &mut Self::E, e2: &Self::E) {
        e1.xor_in_place(e2);
    }

    #[inline(always)]
    fn mul(&self, e1: &mut Self::E, e2: &Self::E) {
        *e1 = arch_mul(*e1, *e2);
    }

    #[inline(always)]
    fn invert(&self, e: &Self::E) -> Self::E {
        invert(*e)
    }

    #[inline(always)]
    fn neg(&self, e: &Self::E) -> Self::E {
        *e
    }

    #[inline(always)]
    fn mone(&self) -> Self::E {
        self.one()
    }

    #[inline(always)]
    fn is_zero(&self, e: &Self::E) -> bool {
        e.to_u128() == 0
    }
}

impl RuntimeField<2> for Gf2_128Field {
    type Accum = Gf2_128Accum;

    #[inline(always)]
    fn fma(&self, e1: &mut Self::E, a: &Self::E, b: &Self::E) {
        let mut prod = *a;
        self.mul(&mut prod, b);
        e1.xor_in_place(&prod);
    }

    #[inline(always)]
    fn fnms(&self, e1: &mut Self::E, a: &Self::E, b: &Self::E) {
        self.fma(e1, a, b);
    }

    #[inline(always)]
    fn zero_accum(&self) -> Self::Accum {
        Gf2_128Accum::default()
    }

    #[inline(always)]
    fn mac(&self, acc: &mut Self::Accum, x: &Self::E, y: &Self::E) {
        arch_mac(acc, x, y);
    }

    #[inline(always)]
    fn accum_reduce(&self, acc: &Self::Accum) -> Self::E {
        arch_accum_reduce(acc)
    }
}

impl crate::field::SupportsSampling<2> for Gf2_128Field {
    fn sample<R: FnMut(usize) -> Vec<u8>>(&self, mut rng: R) -> Self::E {
        let buf = rng(16);
        let val = u128::from_le_bytes(buf.try_into().unwrap());
        Gf2_128::from(val)
    }
}

impl RuntimeBinaryField<2> for Gf2_128Field {}

impl crate::poly::InterpolationField<2> for Gf2_128Field {
    #[inline(always)]
    fn poly_evaluation_point(&self, i: usize) -> Self::E {
        self.poly_evaluation_points[i]
    }

    #[inline(always)]
    fn newton_denominator(&self, k: usize, i: usize) -> Self::E {
        self.newton_denominators[k][i]
    }
}

impl core_algebra::SerializableField for Gf2_128Field {
    fn is_binary(&self) -> bool {
        true
    }

    fn serialized_size_bytes(&self) -> usize {
        16
    }

    #[inline(always)]
    fn to_bytes_into(&self, e: &Self::E, dst: &mut [u8]) {
        assert_eq!(
            dst.len(),
            16,
            "destination slice length mismatch: {} != 16",
            dst.len()
        );
        dst.copy_from_slice(&e.to_u128().to_le_bytes());
    }

    fn bytes_to_element(&self, bytes: &[u8]) -> Result<Self::E, String> {
        if bytes.len() != 16 {
            return Err("Invalid size".to_string());
        }
        let val = u128::from_le_bytes(bytes.try_into().unwrap());
        Ok(Gf2_128::from(val))
    }

    fn serialized_mone(&self) -> Vec<u8> {
        let mone = self.mone();
        self.to_bytes(&mone)
    }
}

impl crate::field::RuntimeSerializableField<2> for Gf2_128Field {
    #[inline(always)]
    fn to_words64(&self, e: &Self::E) -> [u64; 2] {
        let val = e.to_u128();
        [val as u64, (val >> 64) as u64]
    }

    #[inline(always)]
    fn words64_to_element(&self, words: &[u64; 2]) -> Result<Self::E, String> {
        Ok(Gf2_128::from(
            u128::from(words[0]) | (u128::from(words[1]) << 64),
        ))
    }
}

impl core_algebra::SupportsNatConversions<2> for Gf2_128Field {
    type N = crate::RuntimeNat<2>;

    #[inline(always)]
    fn nat_to_element(&self, n: &Self::N) -> Self::E {
        let limbs = n.limbs();
        Gf2_128::from(u128::from(limbs[0]) | (u128::from(limbs[1]) << 64))
    }

    #[inline(always)]
    fn to_nat(&self, e: &Self::E) -> Self::N {
        let val = e.to_u128();
        crate::RuntimeNat::from_limbs([val as u64, (val >> 64) as u64])
    }
}

impl core_algebra::HasLookupPoints for Gf2_128Field {
    fn lookup_point(&self, _n: usize, i: usize) -> Self::E {
        let mut pt = Gf2_128::default();
        for j in 0..(usize::BITS as usize) {
            if (i & (1usize << j)) != 0 {
                self.add(&mut pt, &self.cantor_basis[j]);
            }
        }
        pt
    }
}

impl core_algebra::SupportsU128Conversions for Gf2_128Field {
    #[inline(always)]
    fn u128_to_element(&self, n: u128) -> Self::E {
        Gf2_128::from(n)
    }
}

pub type Gf2_128RuntimeField = Gf2_128Field;
