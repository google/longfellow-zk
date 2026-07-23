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

use crate::field::RuntimeField;

pub trait Interpolator<const W: usize, F: RuntimeField<W>> {
    fn interpolate(&self, y: &mut [F::E]);
}

pub trait InterpolatorFactory<const W: usize, F: RuntimeField<W>> {
    type Interpolator: Interpolator<W, F>;
    fn make(&self, ylen: usize, block_enc: usize) -> Self::Interpolator;

    /// Returns whether this interpolator factory can support encoding `ylen` input points
    /// to `block_enc` output points (where `block_enc` includes the `ylen` original points).
    ///
    /// Depending on the underlying algorithm, the capacity bounds vary:
    /// - **Additive/Subspace FFTs (LCH14)**: Evaluate over an additive subspace directly, so we
    ///   only require the total evaluation domain size `block_enc` to fit in the subfield
    ///   (`block_enc <= 1 << subfield_dim`).
    /// - **Multiplicative/Convolutive FFTs**: Perform polynomial convolution to interpolate. To
    ///   prevent aliasing, the FFT size must be at least `(ylen + block_enc -
    ///   1).next_power_of_two()`, requiring a root of unity subgroup of at least that order.
    fn can_encode(&self, ylen: usize, block_enc: usize) -> bool;
}

impl<const W: usize, F: RuntimeField<W>, IF: InterpolatorFactory<W, F> + ?Sized>
    InterpolatorFactory<W, F> for &IF
{
    type Interpolator = IF::Interpolator;
    fn make(&self, ylen: usize, block_enc: usize) -> Self::Interpolator {
        (*self).make(ylen, block_enc)
    }
    fn can_encode(&self, ylen: usize, block_enc: usize) -> bool {
        (*self).can_encode(ylen, block_enc)
    }
}
