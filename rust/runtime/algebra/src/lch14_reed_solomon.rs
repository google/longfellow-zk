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

use crate::{field::RuntimeBinaryField, lch14::Lch14, subfield::BinarySubfield, Interpolator};

pub struct Lch14ReedSolomon<
    'a,
    const W: usize,
    F: RuntimeBinaryField<W, E = crate::gf2_128::Gf2_128>,
> {
    f: &'a F,
    n: usize,
    m: usize,
    lch14: Lch14<'a, W, F>,
}

impl<'a, const W: usize, F: RuntimeBinaryField<W, E = crate::gf2_128::Gf2_128>>
    Lch14ReedSolomon<'a, W, F>
{
    pub fn new(n: usize, m: usize, f: &'a F, subfield: &'a BinarySubfield) -> Self {
        Self {
            f,
            n,
            m,
            lch14: Lch14::new(f, subfield),
        }
    }
}

impl<const W: usize, F: RuntimeBinaryField<W, E = crate::gf2_128::Gf2_128>> Interpolator<W, F>
    for Lch14ReedSolomon<'_, W, F>
{
    fn interpolate(&self, y: &mut [F::E]) {
        let fftn = self.n.next_power_of_two();
        let l = fftn.trailing_zeros() as usize;

        let mut c = vec![self.f.zero(); fftn];
        c[..self.n].clone_from_slice(&y[..self.n]);

        self.lch14.bidirectional_fft(l, self.n, &mut c);

        let limit = std::cmp::min(self.m, fftn);
        y[self.n..limit].clone_from_slice(&c[self.n..limit]);

        crate::blas::clear(&mut c[self.n..fftn], self.f);

        let mut temp = vec![self.f.zero(); fftn];
        let mut coset = 1;
        while (coset << l) < self.m {
            let b = coset << l;
            let chunk_limit = std::cmp::min(self.m - b, fftn);
            crate::blas::copy(&mut temp, &c);
            self.lch14.fft(l, b, &mut temp);
            y[b..(chunk_limit + b)].clone_from_slice(&temp[..chunk_limit]);
            coset += 1;
        }
    }
}

pub struct Lch14InterpolatorFactory<
    'a,
    const W: usize,
    F: RuntimeBinaryField<W, E = crate::gf2_128::Gf2_128>,
> {
    f: &'a F,
    subfield: &'a BinarySubfield,
}

impl<'a, const W: usize, F: RuntimeBinaryField<W, E = crate::gf2_128::Gf2_128>>
    Lch14InterpolatorFactory<'a, W, F>
{
    pub fn new(f: &'a F, subfield: &'a BinarySubfield) -> Self {
        Self { f, subfield }
    }
}

impl<'a, const W: usize, F: RuntimeBinaryField<W, E = crate::gf2_128::Gf2_128>>
    crate::interpolator::InterpolatorFactory<W, F> for Lch14InterpolatorFactory<'a, W, F>
{
    type Interpolator = Lch14ReedSolomon<'a, W, F>;

    fn make(&self, n: usize, m: usize) -> Self::Interpolator {
        Lch14ReedSolomon::new(n, m, self.f, self.subfield)
    }

    fn can_encode(&self, ylen: usize, block_enc: usize) -> bool {
        // LCH14 evaluates polynomials over an additive subspace (the subfield).
        // Since all evaluation points (including coset offsets) must belong to the subfield,
        // the total number of evaluation points (`block_enc`) cannot exceed the subfield size.
        let max_size = 1 << self.subfield.dimension();
        ylen <= max_size && block_enc <= max_size
    }
}
