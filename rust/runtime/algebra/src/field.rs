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

pub use core_algebra::AlgebraicField;

pub trait RuntimeSerializableField<const W: usize>:
    RuntimeField<W> + core_algebra::SerializableField
{
    fn to_words64(&self, e: &Self::E) -> [u64; W];
    fn words64_to_element(&self, words: &[u64; W]) -> Result<Self::E, String>;
}

pub trait RuntimeField<const W: usize>: core_algebra::AlgebraicField {
    type Accum: Clone + std::fmt::Debug;

    // Arithmetic operations

    #[inline]
    fn fma(&self, e1: &mut Self::E, a: &Self::E, b: &Self::E) {
        let mut prod = a.clone();
        self.mul(&mut prod, b);
        self.add(e1, &prod);
    }

    #[inline]
    fn fnms(&self, e1: &mut Self::E, a: &Self::E, b: &Self::E) {
        let mut prod = a.clone();
        self.mul(&mut prod, b);
        self.sub(e1, &prod);
    }

    fn zero_accum(&self) -> Self::Accum;
    fn mac(&self, acc: &mut Self::Accum, x: &Self::E, y: &Self::E);
    fn accum_reduce(&self, acc: &Self::Accum) -> Self::E;
}

pub use core_algebra::{SupportsNatConversions, SupportsU128Conversions, SupportsU64Conversions};

pub trait SupportsSampling<const W: usize>: RuntimeField<W> {
    fn sample<R: FnMut(usize) -> Vec<u8>>(&self, rng: R) -> Self::E;
}

pub trait RuntimeBinaryField<const W: usize>: RuntimeField<W> {}

/// Marker for base fields that support [`crate::fp2::Fp2Field`].
///
/// `Fp2Field` uses the fixed polynomial `x^2 + 1`, so implementors must ensure
/// that `-1` is not a square in the base field. This property depends on the
/// concrete modulus and cannot be inferred from a generic prime-field type.
pub trait SupportsQuadraticExtension<const W: usize>: RuntimeField<W> {}

pub trait SupportsFFT<const W: usize>: RuntimeField<W> {
    fn omega(&self) -> Self::E;
    fn omega_order(&self) -> u64;
}
