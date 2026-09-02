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
pub mod arch;
pub mod blas;
pub mod fft;
pub mod field;
pub mod fp2;
pub mod fp_generic;
pub mod gf2_128;
pub mod interpolator;
pub mod lch14;
pub mod lch14_reed_solomon;
pub mod limb;
pub mod mem;
pub mod middle_product;
pub mod nat;
pub mod p256;
pub(crate) mod permutations;
pub mod poly;
pub mod q256;
pub mod reed_solomon;
pub mod rfft;
pub mod secp256r1;
pub mod subfield;
pub(crate) mod utility;

pub use core_algebra::{AlgebraicField, Curve as RuntimeCurve, ElementOf};
pub use field::{
    RuntimeBinaryField, RuntimeField, SupportsFFT, SupportsQuadraticExtension, SupportsSampling,
};
pub use interpolator::{Interpolator, InterpolatorFactory};
pub use limb::{
    limbs_to_u64, limbs_to_words64, u64_to_limbs, words64_to_limbs, Limb, LIMBS_PER_U64, LIMB_BITS,
};
pub use mem::*;
pub use nat::RuntimeNat;
pub use poly::{InterpolationField, LagrangeBasis, Poly};
pub use q256::{Q256Element, Q256Field};
pub use secp256r1::Secp256r1 as RuntimeSecp256r1;
pub use subfield::Subfield;

/// Stable trait alias bundling requirements for zero-knowledge proving.
pub trait ZkField<const W: usize>:
    InterpolationField<W> + core_algebra::SerializableField + SupportsSampling<W>
{
}
impl<const W: usize, F> ZkField<W> for F where F: InterpolationField<W> + core_algebra::SerializableField + SupportsSampling<W>
{}
