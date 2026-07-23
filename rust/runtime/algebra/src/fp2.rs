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

use crate::field::{AlgebraicField, FieldElement, RuntimeField, SupportsQuadraticExtension};

pub struct Fp2Element<const W: usize, F: SupportsQuadraticExtension<W>> {
    pub re: F::E,
    pub im: F::E,
}

impl<const W: usize, F: SupportsQuadraticExtension<W>> Clone for Fp2Element<W, F> {
    fn clone(&self) -> Self {
        Self {
            re: self.re.clone(),
            im: self.im.clone(),
        }
    }
}

impl<const W: usize, F: SupportsQuadraticExtension<W>> Copy for Fp2Element<W, F> where F::E: Copy {}

impl<const W: usize, F: SupportsQuadraticExtension<W>> std::fmt::Debug for Fp2Element<W, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fp2Element")
            .field("re", &self.re)
            .field("im", &self.im)
            .finish()
    }
}

impl<const W: usize, F: SupportsQuadraticExtension<W>> PartialEq for Fp2Element<W, F> {
    fn eq(&self, other: &Self) -> bool {
        self.re == other.re && self.im == other.im
    }
}

impl<const W: usize, F: SupportsQuadraticExtension<W>> Eq for Fp2Element<W, F> {}

impl<const W: usize, F: SupportsQuadraticExtension<W>> std::hash::Hash for Fp2Element<W, F> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.re.hash(state);
        self.im.hash(state);
    }
}

impl<const W: usize, F: SupportsQuadraticExtension<W>> FieldElement for Fp2Element<W, F> {}

/// Arithmetic in the quadratic extension `F[i] / (i² + 1)`.
///
/// This field deliberately does not implement serialization. Protocol values
/// must remain in the base field, which has a canonical encoding.
#[derive(Clone, Debug)]
pub struct Fp2Field<'a, const W: usize, F: SupportsQuadraticExtension<W>> {
    base: &'a F,
    mone: Fp2Element<W, F>,
}

impl<'a, const W: usize, F: SupportsQuadraticExtension<W>> Fp2Field<'a, W, F> {
    /// Constructs the non-serializable quadratic extension of `base`.
    pub fn new(base: &'a F) -> Self {
        let mone = Fp2Element {
            re: base.mone(),
            im: base.zero(),
        };

        Self { base, mone }
    }

    pub fn base_field(&self) -> &F {
        self.base
    }

    pub fn i(&self) -> Fp2Element<W, F> {
        Fp2Element {
            re: self.base.zero(),
            im: self.base.one(),
        }
    }
}

impl<const W: usize, F: SupportsQuadraticExtension<W>> core_algebra::BareField
    for Fp2Field<'_, W, F>
{
    type E = Fp2Element<W, F>;
}

impl<const W: usize, F: SupportsQuadraticExtension<W>> core_algebra::AlgebraicField
    for Fp2Field<'_, W, F>
{
    fn zero(&self) -> Self::E {
        Fp2Element {
            re: self.base.zero(),
            im: self.base.zero(),
        }
    }

    fn one(&self) -> Self::E {
        Fp2Element {
            re: self.base.one(),
            im: self.base.zero(),
        }
    }

    fn add(&self, e1: &mut Self::E, e2: &Self::E) {
        self.base.add(&mut e1.re, &e2.re);
        self.base.add(&mut e1.im, &e2.im);
    }

    fn sub(&self, e1: &mut Self::E, e2: &Self::E) {
        self.base.sub(&mut e1.re, &e2.re);
        self.base.sub(&mut e1.im, &e2.im);
    }

    fn mul(&self, e1: &mut Self::E, e2: &Self::E) {
        let mut a01 = e1.re.clone();
        self.base.add(&mut a01, &e1.im);
        let mut b01 = e2.re.clone();
        self.base.add(&mut b01, &e2.im);

        let mut p1 = e1.im.clone();
        self.base.mul(&mut p1, &e2.im);

        self.base.mul(&mut e1.re, &e2.re);
        self.base.mul(&mut a01, &b01);
        self.base.sub(&mut a01, &e1.re);
        self.base.sub(&mut a01, &p1);

        self.base.sub(&mut e1.re, &p1);
        e1.im = a01;
    }

    fn invert(&self, e: &Self::E) -> Self::E {
        // (a + bi)^-1 = a/(a^2 + b^2) - b/(a^2 + b^2)i
        let a2 = self.base.mulf(&e.re, &e.re);
        let b2 = self.base.mulf(&e.im, &e.im);
        let denom = self.base.addf(&a2, &b2);
        let denom_inv = self.base.invert(&denom);

        Fp2Element {
            re: self.base.mulf(&e.re, &denom_inv),
            im: self.base.neg(&self.base.mulf(&e.im, &denom_inv)),
        }
    }

    fn mone(&self) -> Self::E {
        self.mone.clone()
    }
}

#[derive(PartialEq, Eq)]
pub struct Fp2Accum<const W: usize, F: SupportsQuadraticExtension<W>>(pub Fp2Element<W, F>);

impl<const W: usize, F: SupportsQuadraticExtension<W>> Clone for Fp2Accum<W, F> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<const W: usize, F: SupportsQuadraticExtension<W>> std::fmt::Debug for Fp2Accum<W, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fp2Accum").field("acc", &self.0).finish()
    }
}

impl<const W: usize, F: SupportsQuadraticExtension<W>> RuntimeField<W> for Fp2Field<'_, W, F> {
    type Accum = Fp2Accum<W, F>;

    fn zero_accum(&self) -> Self::Accum {
        Fp2Accum(self.zero())
    }

    fn mac(&self, acc: &mut Self::Accum, x: &Self::E, y: &Self::E) {
        let mut p = x.clone();
        self.mul(&mut p, y);
        self.add(&mut acc.0, &p);
    }

    fn add_accum(&self, a: &mut Self::Accum, b: &Self::Accum) {
        a.0 = self.addf(&a.0, &b.0);
    }

    fn accum_reduce(&self, acc: &Self::Accum) -> Self::E {
        acc.0.clone()
    }
}

impl<const W: usize, F: SupportsQuadraticExtension<W> + crate::field::SupportsSampling<W>>
    crate::field::SupportsSampling<W> for Fp2Field<'_, W, F>
{
    fn sample<R: FnMut(usize) -> Vec<u8>>(&self, mut rng: R) -> Self::E {
        let mut rng_ref = &mut rng;
        let re = self.base.sample(&mut rng_ref);
        let im = self.base.sample(&mut rng_ref);
        Fp2Element { re, im }
    }
}

impl<const W: usize, F: SupportsQuadraticExtension<W> + core_algebra::SupportsU64Conversions>
    core_algebra::SupportsU64Conversions for Fp2Field<'_, W, F>
{
    fn u64_to_element(&self, n: u64) -> Self::E {
        Fp2Element {
            re: self.base.u64_to_element(n),
            im: self.base.zero(),
        }
    }
}
