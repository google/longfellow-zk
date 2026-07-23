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

use crate::field::{
    AlgebraicField, FieldElement, RuntimeField, RuntimeSerializableField,
    SupportsQuadraticExtension,
};

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

#[derive(Clone, Debug)]
pub struct Fp2Field<'a, const W: usize, const W2: usize, F: SupportsQuadraticExtension<W>> {
    base: &'a F,
    basis: Vec<Fp2Element<W, F>>,
    mone: Fp2Element<W, F>,
}

impl<'a, const W: usize, const W2: usize, F: SupportsQuadraticExtension<W>> Fp2Field<'a, W, W2, F> {
    pub fn new(base: &'a F) -> Self {
        let d = base.pseudo_dimension();
        let mut basis = Vec::with_capacity(d);
        for i in 0..d {
            basis.push(Fp2Element {
                re: base.pseudo_basis(i),
                im: base.zero(),
            });
        }
        let mone = Fp2Element {
            re: base.mone(),
            im: base.zero(),
        };

        Self { base, basis, mone }
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

impl<const W: usize, const W2: usize, F: SupportsQuadraticExtension<W>> core_algebra::BareField
    for Fp2Field<'_, W, W2, F>
{
    type E = Fp2Element<W, F>;
}

impl<const W: usize, const W2: usize, F: SupportsQuadraticExtension<W>> core_algebra::AlgebraicField
    for Fp2Field<'_, W, W2, F>
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

impl<const W: usize, const W2: usize, F: SupportsQuadraticExtension<W>> RuntimeField<W2>
    for Fp2Field<'_, W, W2, F>
{
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

    fn pseudo_basis(&self, i: usize) -> Self::E {
        assert!(i < self.base.pseudo_dimension(), "i < dimension");
        self.basis[i].clone()
    }

    fn pseudo_dimension(&self) -> usize {
        self.base.pseudo_dimension()
    }

    fn pseudo_basis_unsafe(&self, i: usize) -> Self::E {
        Fp2Element {
            re: self.base.pseudo_basis_unsafe(i),
            im: self.base.zero(),
        }
    }
}

impl<
        const W: usize,
        const W2: usize,
        F: SupportsQuadraticExtension<W> + crate::field::SupportsSampling<W>,
    > crate::field::SupportsSampling<W2> for Fp2Field<'_, W, W2, F>
{
    fn sample<R: FnMut(usize) -> Vec<u8>>(&self, mut rng: R) -> Self::E {
        let mut rng_ref = &mut rng;
        let re = self.base.sample(&mut rng_ref);
        let im = self.base.sample(&mut rng_ref);
        Fp2Element { re, im }
    }
}

impl<const W: usize, const W2: usize, F: SupportsQuadraticExtension<W>>
    core_algebra::SerializableField for Fp2Field<'_, W, W2, F>
{
    fn name(&self) -> String {
        format!("{}^2", self.base.name())
    }

    fn id(&self) -> usize {
        self.base.id() + 100
    }

    fn is_binary(&self) -> bool {
        self.base.is_binary()
    }

    fn serialized_size_bytes(&self) -> usize {
        W2 * 8
    }

    fn to_bytes_into(&self, e: &Self::E, dst: &mut [u8]) {
        let len = self.base.serialized_size_bytes();
        assert_eq!(
            dst.len(),
            2 * len,
            "destination slice length mismatch: {} != {}",
            dst.len(),
            2 * len
        );
        self.base.to_bytes_into(&e.re, &mut dst[0..len]);
        self.base.to_bytes_into(&e.im, &mut dst[len..2 * len]);
    }

    fn bytes_to_element(&self, bytes: &[u8]) -> Result<Self::E, String> {
        if bytes.len() != W2 * 8 {
            return Err("Invalid size".to_string());
        }
        let mut limbs = [0u64; W2];
        for i in 0..W2 {
            let chunk: &[u8; 8] = (&bytes[i * 8..(i + 1) * 8]).try_into().unwrap();
            limbs[i] = u64::from_le_bytes(*chunk);
        }
        self.words64_to_element(&limbs)
    }

    fn serialized_mone(&self) -> Vec<u8> {
        let mone = self.mone();
        self.to_bytes(&mone)
    }
}

impl<const W: usize, const W2: usize, F: SupportsQuadraticExtension<W>>
    crate::field::RuntimeSerializableField<W2> for Fp2Field<'_, W, W2, F>
{
    fn to_words64(&self, e: &Self::E) -> [u64; W2] {
        let re_words = self.base.to_words64(&e.re);
        let im_words = self.base.to_words64(&e.im);
        let mut words = [0u64; W2];
        for i in 0..W {
            if i < W2 {
                words[i] = re_words[i];
            }
            if W + i < W2 {
                words[W + i] = im_words[i];
            }
        }
        words
    }

    fn words64_to_element(&self, words: &[u64; W2]) -> Result<Self::E, String> {
        let mut re_words = [0u64; W];
        let mut im_words = [0u64; W];
        for i in 0..W {
            if i < W2 {
                re_words[i] = words[i];
            }
            if W + i < W2 {
                im_words[i] = words[W + i];
            }
        }
        let re = self.base.words64_to_element(&re_words)?;
        let im = self.base.words64_to_element(&im_words)?;
        Ok(Fp2Element { re, im })
    }
}

impl<
        const W: usize,
        const W2: usize,
        F: SupportsQuadraticExtension<W> + core_algebra::SupportsNatConversions<W>,
    > core_algebra::SupportsNatConversions<W2> for Fp2Field<'_, W, W2, F>
{
    type N = crate::RuntimeNat<W2>;

    fn nat_to_element(&self, n: &Self::N) -> Self::E {
        let mut limbs = [0u64; W];
        limbs.copy_from_slice(&n.limbs()[..W]);
        let base_nat = F::N::from_limbs(&limbs);
        Fp2Element {
            re: self.base.nat_to_element(&base_nat),
            im: self.base.zero(),
        }
    }

    fn to_nat(&self, e: &Self::E) -> Self::N {
        let base_nat = self.base.to_nat(&e.re);
        let mut limbs = [0u64; W2];
        let base_limbs = base_nat.to_limbs();
        limbs[..W].copy_from_slice(&base_limbs[..W]);
        crate::RuntimeNat::from_limbs(limbs)
    }
}

impl<
        const W: usize,
        const W2: usize,
        F: SupportsQuadraticExtension<W> + core_algebra::SupportsU64Conversions,
    > core_algebra::SupportsU64Conversions for Fp2Field<'_, W, W2, F>
{
    fn u64_to_element(&self, n: u64) -> Self::E {
        Fp2Element {
            re: self.base.u64_to_element(n),
            im: self.base.zero(),
        }
    }
}
