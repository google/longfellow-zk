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

use std::{
    fmt::{self, Debug, Formatter},
    hash::{Hash, Hasher},
    marker::PhantomData,
};

use core_algebra::{
    AlgebraicField, BareField, HasLookupPoints, SerializableField, SupportsNatConversions,
    SupportsU64Conversions,
};

use crate::{
    field::{FieldElement, RuntimeField, RuntimeSerializableField, SupportsSampling},
    limb::{accum, accum_modular, lt, maybe_minus_m, maybe_plus_m, mul_accum, sub_limb},
    poly::InterpolationField,
    Limb, RuntimeNat,
};

/// A trait defining the arithmetic strategy for a prime field of limb width `L`.
pub trait MontgomeryStrategy<const L: usize>:
    Clone + Debug + PartialEq + Eq + Send + Sync + 'static
{
    #[inline(always)]
    fn add(a: &mut [Limb; L], b: &[Limb; L], negm: &[Limb; L]) {
        accum_modular(a, b, negm);
    }

    #[inline(always)]
    fn sub(a: &mut [Limb; L], b: &[Limb; L], modulo: &[Limb; L]) {
        let ah = sub_limb(a, b);
        maybe_plus_m(a, ah, modulo);
    }

    fn montgomery_mul(
        a: &mut [Limb; L],
        b: &[Limb; L],
        modulo: &[Limb; L],
        negm: &[Limb; L],
        m_prime: Limb,
    );
}

/// The generic interleaved Montgomery multiplication strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct GenericStrategy;

impl<const L: usize> MontgomeryStrategy<L> for GenericStrategy {
    #[inline(always)]
    fn montgomery_mul(
        a: &mut [Limb; L],
        b: &[Limb; L],
        modulo: &[Limb; L],
        negm: &[Limb; L],
        m_prime: Limb,
    ) {
        *a = montgomery_mul(a, b, modulo, negm, m_prime);
    }
}

/// A generic finite field element represented in Montgomery form ($x \cdot R \pmod M$).
pub struct FpGenericElement<const L: usize, Tag>(pub [Limb; L], pub PhantomData<Tag>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FpGenericAccum<const A: usize>(pub [Limb; A]);

impl<const A: usize> Default for FpGenericAccum<A> {
    fn default() -> Self {
        Self([0 as Limb; A])
    }
}

impl<const L: usize, Tag> Clone for FpGenericElement<L, Tag> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<const L: usize, Tag> Copy for FpGenericElement<L, Tag> {}

impl<const L: usize, Tag> Debug for FpGenericElement<L, Tag> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "FpGenericElement({:?})", self.0)
    }
}

impl<const L: usize, Tag> PartialEq for FpGenericElement<L, Tag> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<const L: usize, Tag> Eq for FpGenericElement<L, Tag> {}

impl<const L: usize, Tag> Hash for FpGenericElement<L, Tag> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<const L: usize, Tag> FieldElement for FpGenericElement<L, Tag> {}

/// A prime finite field implementation parameterized by word width `W`, limb width `L`, and a
/// branding `Tag`. Elements are stored and manipulated in Montgomery form with $R = 2^{64W} \pmod
/// M$.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FpGenericField<
    const W: usize,
    const L: usize,
    const ACCUM_L: usize,
    Tag = (),
    S: MontgomeryStrategy<L> = GenericStrategy,
> {
    modulo: [Limb; L],
    neg_modulo: [Limb; L],
    id: usize,
    name: String,
    m_prime: Limb,
    r2: [Limb; L],
    r: [Limb; L],
    accum_scale: FpGenericElement<L, Tag>,
    raw_half: FpGenericElement<L, Tag>,
    _marker: PhantomData<(Tag, S)>,
}

impl<const W: usize, const L: usize, const ACCUM_L: usize, Tag, S: MontgomeryStrategy<L>>
    FpGenericField<W, L, ACCUM_L, Tag, S>
{
    #[must_use]
    pub fn new_generic(modulo_words: [u64; W], id: usize, name: &str) -> Self {
        let modulo = crate::words64_to_limbs(&modulo_words);
        let mut neg_modulo = [0 as Limb; L];
        crate::limb::sub_limb(&mut neg_modulo, &modulo);
        let m_prime = compute_m_prime(modulo[0]);
        let r2 = compute_r2(&neg_modulo);
        let r = compute_r(&neg_modulo);
        let mut accum_scale = FpGenericElement(r2, PhantomData);
        for _ in 0..((ACCUM_L - 2 * L) * crate::LIMB_BITS) {
            let mut res = accum_scale.0;
            accum_modular(&mut res, &accum_scale.0, &neg_modulo);
            accum_scale.0 = res;
        }

        let mut raw_half_limbs = crate::limb::shr_1(&modulo);
        crate::limb::propagate_carry(&mut raw_half_limbs, 0, true);
        let raw_half = FpGenericElement(raw_half_limbs, PhantomData);

        Self {
            modulo,
            neg_modulo,
            id,
            name: name.to_string(),
            m_prime,
            r2,
            r,
            accum_scale,
            raw_half,
            _marker: PhantomData,
        }
    }

    fn to_montgomery(&self, standard: &[Limb; L]) -> FpGenericElement<L, Tag> {
        let mut res_limbs = *standard;
        S::montgomery_mul(
            &mut res_limbs,
            &self.r2,
            &self.modulo,
            &self.neg_modulo,
            self.m_prime,
        );
        FpGenericElement(res_limbs, PhantomData)
    }

    fn to_standard(&self, mont: &FpGenericElement<L, Tag>) -> [Limb; L] {
        let mut res_limbs = mont.0;
        let mut one_limbs = [0 as Limb; L];
        one_limbs[0] = 1;
        S::montgomery_mul(
            &mut res_limbs,
            &one_limbs,
            &self.modulo,
            &self.neg_modulo,
            self.m_prime,
        );
        res_limbs
    }

    fn of_scalar(&self, n: u64) -> FpGenericElement<L, Tag> {
        let mut standard = [0 as Limb; L];
        let n_limbs = crate::u64_to_limbs(n);
        for i in 0..crate::LIMBS_PER_U64 {
            if i < L {
                standard[i] = n_limbs[i];
            }
        }
        self.to_montgomery(&standard)
    }

    fn byhalf(&self, a: &mut FpGenericElement<L, Tag>) {
        let lsb = a.0[0] & 1;
        let mut carry = 0;
        for i in (0..L).rev() {
            let new_carry = a.0[i] << (crate::LIMB_BITS - 1);
            a.0[i] = (a.0[i] >> 1) | carry;
            carry = new_carry;
        }
        if lsb != 0 {
            S::add(&mut a.0, &self.raw_half.0, &self.neg_modulo);
        }
    }
}

// ============================================================================
// Arithmetic & Modular Reduction Helpers
// ============================================================================

/// Computes $m' = -m_0^{-1} \pmod{2^{32 or 64}}$ using Newton-Raphson iteration.
fn compute_m_prime(m0: Limb) -> Limb {
    let mut inv = m0;
    for _ in 0..6 {
        inv = inv.wrapping_mul((2 as Limb).wrapping_sub(m0.wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}

/// Computes $R^2 = (2^{64W})^2 \pmod M$.
fn compute_r2<const L: usize>(negm: &[Limb; L]) -> [Limb; L] {
    let mut x = [0 as Limb; L];
    x[0] = 1;
    for _ in 0..(2 * crate::LIMB_BITS * L) {
        let mut next_x = x;
        accum_modular(&mut next_x, &x, negm);
        x = next_x;
    }
    x
}

/// Computes $R = 2^{64W} \pmod M$.
fn compute_r<const L: usize>(negm: &[Limb; L]) -> [Limb; L] {
    let mut x = [0 as Limb; L];
    x[0] = 1;
    for _ in 0..(crate::LIMB_BITS * L) {
        let mut next_x = x;
        accum_modular(&mut next_x, &x, negm);
        x = next_x;
    }
    x
}

/// Interleaved Montgomery multiplication: $a \cdot b \cdot R^{-1} \pmod M$.
fn montgomery_mul<const L: usize>(
    a: &[Limb; L],
    b: &[Limb; L],
    modulo: &[Limb; L],
    negm: &[Limb; L],
    m_prime: Limb,
) -> [Limb; L] {
    assert!(L <= 16, "montgomery_mul: limb count exceeds static buffer");
    // Static accumulator buffer: we accumulate up to L steps of (a[i]*b + q*M).
    // The product has up to 2*L <= 32 limbs (since L <= 16).
    // We allocate 33 limbs (2*L + 1 for L=16) so that the final carry out of mul_accum or
    // reduction_step can be safely stored at index 2*L without out-of-bounds panics or dynamic
    // allocation.
    let mut t = [0 as Limb; 33];
    if L > 0 {
        let window0 = &mut t[0..L + 2];
        crate::limb::mul_accum_zero(window0, 0, a[0], b);
        reduction_step(window0, 0, modulo, m_prime);
        for i in 1..L {
            t[i + L + 1] = 0;
            let window_step = &mut t[i..i + L + 2];
            crate::limb::mul_accum(window_step, 0, a[i], b);
            reduction_step(window_step, 0, modulo, m_prime);
        }
    }
    let mut res = [0 as Limb; L];
    res.copy_from_slice(&t[L..2 * L]);
    maybe_minus_m(&mut res, t[2 * L], negm);
    res
}

/// Performs one Montgomery reduction step at index `i` on accumulator `t`.
fn reduction_step<const L: usize>(t: &mut [Limb], i: usize, modulo: &[Limb; L], m_prime: Limb) {
    let q = t[i].wrapping_mul(m_prime);
    mul_accum(t, i, q, modulo);
}

// ============================================================================
// Core Algebra & BareField Trait Implementations
// ============================================================================

impl<const W: usize, const L: usize, const ACCUM_L: usize, Tag, S: MontgomeryStrategy<L>> BareField
    for FpGenericField<W, L, ACCUM_L, Tag, S>
{
    type E = FpGenericElement<L, Tag>;
}

// ============================================================================
// AlgebraicField Implementation
// ============================================================================

impl<const W: usize, const L: usize, const ACCUM_L: usize, Tag, S: MontgomeryStrategy<L>>
    AlgebraicField for FpGenericField<W, L, ACCUM_L, Tag, S>
{
    #[inline(always)]
    fn zero(&self) -> Self::E {
        FpGenericElement([0 as Limb; L], PhantomData)
    }

    #[inline(always)]
    fn one(&self) -> Self::E {
        FpGenericElement(self.r, PhantomData)
    }

    #[inline(always)]
    fn add(&self, a: &mut Self::E, b: &Self::E) {
        S::add(&mut a.0, &b.0, &self.neg_modulo);
    }

    #[inline(always)]
    fn sub(&self, a: &mut Self::E, b: &Self::E) {
        S::sub(&mut a.0, &b.0, &self.modulo);
    }

    #[inline(always)]
    fn mul(&self, a: &mut Self::E, b: &Self::E) {
        S::montgomery_mul(&mut a.0, &b.0, &self.modulo, &self.neg_modulo, self.m_prime);
    }

    fn invert(&self, a: &Self::E) -> Self::E {
        let mut a_limbs = self.to_standard(a);
        let mut b_limbs = self.modulo;
        let mut u = self.one();
        let mut v = self.zero();

        let zero_limbs = [0 as Limb; L];
        while a_limbs != zero_limbs {
            if (a_limbs[0] & 1) == 0 {
                let mut carry = 0;
                for i in (0..L).rev() {
                    let new_carry = a_limbs[i] << (crate::LIMB_BITS - 1);
                    a_limbs[i] = (a_limbs[i] >> 1) | carry;
                    carry = new_carry;
                }
                self.byhalf(&mut u);
            } else {
                if crate::limb::lt(&a_limbs, &b_limbs) {
                    std::mem::swap(&mut a_limbs, &mut b_limbs);
                    std::mem::swap(&mut u, &mut v);
                }
                let mut borrow = false;
                for i in 0..L {
                    let (diff, b_out) = a_limbs[i].borrowing_sub(b_limbs[i], borrow);
                    a_limbs[i] = diff;
                    borrow = b_out;
                }
                let mut carry = 0;
                for i in (0..L).rev() {
                    let new_carry = a_limbs[i] << (crate::LIMB_BITS - 1);
                    a_limbs[i] = (a_limbs[i] >> 1) | carry;
                    carry = new_carry;
                }
                self.sub(&mut u, &v);
                self.byhalf(&mut u);
            }
        }
        v
    }
}

impl<const W: usize, const L: usize, const ACCUM_L: usize, Tag, S: MontgomeryStrategy<L>>
    SerializableField for FpGenericField<W, L, ACCUM_L, Tag, S>
{
    fn name(&self) -> String {
        self.name.clone()
    }

    fn id(&self) -> usize {
        self.id
    }

    fn is_binary(&self) -> bool {
        false
    }

    fn serialized_size_bytes(&self) -> usize {
        W * 8
    }

    #[inline]
    fn to_bytes_into(&self, e: &Self::E, dst: &mut [u8]) {
        assert_eq!(
            dst.len(),
            self.serialized_size_bytes(),
            "destination slice length mismatch: {} != {}",
            dst.len(),
            self.serialized_size_bytes()
        );
        let standard = self.to_standard(e);
        let bytes = dst;
        const LIMB_BYTES: usize = crate::LIMB_BITS / 8;
        let len = bytes.len();
        for (i, limb) in standard.iter().enumerate() {
            let limb_bytes = limb.to_le_bytes();
            let start = i * LIMB_BYTES;
            let end = start + LIMB_BYTES;
            if end <= len {
                bytes[start..end].copy_from_slice(&limb_bytes);
            } else if start < len {
                bytes[start..].copy_from_slice(&limb_bytes[..len - start]);
            }
        }
    }

    fn bytes_to_element(&self, bytes: &[u8]) -> Result<Self::E, String> {
        if bytes.len() != self.serialized_size_bytes() {
            return Err("Invalid size".to_string());
        }
        const LIMB_BYTES: usize = crate::LIMB_BITS / 8;
        let mut limbs = [0 as Limb; L];
        for (i, limb) in limbs.iter_mut().enumerate().take(L) {
            let start = i * LIMB_BYTES;
            let end = start + LIMB_BYTES;
            if end <= bytes.len() {
                let mut limb_bytes = [0u8; LIMB_BYTES];
                limb_bytes.copy_from_slice(&bytes[start..end]);
                *limb = Limb::from_le_bytes(limb_bytes);
            }
        }
        if !lt(&limbs, &self.modulo) {
            return Err("Out of bounds".to_string());
        }
        Ok(self.to_montgomery(&limbs))
    }

    fn serialized_mone(&self) -> Vec<u8> {
        self.to_bytes(&self.mone())
    }
}

// ============================================================================
// Runtime & Conversions Trait Implementations
// ============================================================================

impl<const W: usize, const L: usize, const ACCUM_L: usize, Tag, S: MontgomeryStrategy<L>>
    RuntimeSerializableField<W> for FpGenericField<W, L, ACCUM_L, Tag, S>
{
    fn to_words64(&self, e: &Self::E) -> [u64; W] {
        let limbs = self.to_standard(e);
        crate::limbs_to_words64(&limbs)
    }

    fn words64_to_element(&self, words: &[u64; W]) -> Result<Self::E, String> {
        let limbs = crate::words64_to_limbs(words);
        if !lt(&limbs, &self.modulo) {
            return Err("Out of bounds".to_string());
        }
        Ok(self.to_montgomery(&limbs))
    }
}

impl<const W: usize, const L: usize, const ACCUM_L: usize, Tag, S: MontgomeryStrategy<L>>
    SupportsNatConversions<W> for FpGenericField<W, L, ACCUM_L, Tag, S>
{
    type N = RuntimeNat<W>;

    fn nat_to_element(&self, n: &Self::N) -> Self::E {
        self.words64_to_element(n.limbs()).unwrap()
    }

    fn to_nat(&self, e: &Self::E) -> Self::N {
        RuntimeNat::from_limbs(self.to_words64(e))
    }
}

impl<const W: usize, const L: usize, const ACCUM_L: usize, Tag, S: MontgomeryStrategy<L>>
    RuntimeField<W> for FpGenericField<W, L, ACCUM_L, Tag, S>
{
    type Accum = FpGenericAccum<ACCUM_L>;

    #[inline(always)]
    fn fma(&self, e1: &mut Self::E, a: &Self::E, b: &Self::E) {
        let mut prod = *a;
        self.mul(&mut prod, b);
        self.add(e1, &prod);
    }

    #[inline(always)]
    fn fms(&self, e1: &mut Self::E, a: &Self::E, b: &Self::E) {
        let mut prod = *a;
        self.mul(&mut prod, b);
        self.sub(&mut prod, e1);
        *e1 = prod;
    }

    #[inline(always)]
    fn fnma(&self, e1: &mut Self::E, a: &Self::E, b: &Self::E) {
        let mut prod = *a;
        self.mul(&mut prod, b);
        self.add(&mut prod, e1);
        *e1 = self.neg(&prod);
    }

    #[inline(always)]
    fn fnms(&self, e1: &mut Self::E, a: &Self::E, b: &Self::E) {
        let mut prod = *a;
        self.mul(&mut prod, b);
        self.sub(e1, &prod);
    }

    #[inline(always)]
    fn zero_accum(&self) -> Self::Accum {
        Self::Accum::default()
    }

    #[inline(always)]
    fn mac(&self, acc: &mut Self::Accum, x: &Self::E, y: &Self::E) {
        for i in 0..L {
            let window = &mut acc.0[i..i + L + 2];
            mul_accum(window, 0, x.0[i], &y.0);
        }
    }

    #[inline(always)]
    fn add_accum(&self, a: &mut Self::Accum, b: &Self::Accum) {
        accum(&mut a.0, 0, &b.0);
    }

    fn accum_reduce(&self, acc: &Self::Accum) -> Self::E {
        // Ideally this array would be sized as [0 as Limb; ACCUM_L + L + 1], which is the exact
        // maximum number of limbs needed during Montgomery reduction steps. However, stable Rust
        // forbids const arithmetic involving generic parameters in array type definitions.
        // We hardcode 64 as an upper bound covering all 32-bit and 64-bit targets up to W = 8.
        assert!(
            ACCUM_L + L < 64,
            "Scratch array size 64 is too small for ACCUM_L + L + 1 = {}",
            ACCUM_L + L + 1
        );
        let mut a = [0 as Limb; 64];
        assert!(ACCUM_L > 2 * L, "Accumulator size must be at least 2W+1");
        for i in 0..ACCUM_L {
            let window = &mut a[i..i + L + 2];
            accum(window, 0, &[acc.0[i]]);
            reduction_step(window, 0, &self.modulo, self.m_prime);
        }
        let mut res = [0 as Limb; L];
        res.copy_from_slice(&a[ACCUM_L..ACCUM_L + L]);
        maybe_minus_m(&mut res, a[ACCUM_L + L], &self.neg_modulo);
        self.mulf(&FpGenericElement(res, PhantomData), &self.accum_scale)
    }

    fn pseudo_basis(&self, i: usize) -> Self::E {
        assert!(i < W * 64);
        let mut standard = [0 as Limb; L];
        let limb_idx = i / crate::LIMB_BITS;
        let bit_idx = i % crate::LIMB_BITS;
        if limb_idx < L {
            standard[limb_idx] = (1 as Limb) << bit_idx;
        }
        self.to_montgomery(&standard)
    }

    fn pseudo_dimension(&self) -> usize {
        W * 64
    }

    fn pseudo_basis_unsafe(&self, i: usize) -> Self::E {
        self.pseudo_basis(i)
    }
}

impl<const W: usize, const L: usize, const ACCUM_L: usize, Tag, S: MontgomeryStrategy<L>>
    HasLookupPoints for FpGenericField<W, L, ACCUM_L, Tag, S>
{
    fn lookup_point(&self, _n: usize, i: usize) -> Self::E {
        let mut two_i = self.u64_to_element((2 * i) as u64);
        let n_minus_1 = self.u64_to_element((_n - 1) as u64);
        self.sub(&mut two_i, &n_minus_1);
        two_i
    }
}

impl<const W: usize, const L: usize, const ACCUM_L: usize, Tag, S: MontgomeryStrategy<L>>
    SupportsU64Conversions for FpGenericField<W, L, ACCUM_L, Tag, S>
{
    fn u64_to_element(&self, n: u64) -> Self::E {
        self.of_scalar(n)
    }
}

impl<const W: usize, const L: usize, const ACCUM_L: usize, Tag, S: MontgomeryStrategy<L>>
    SupportsSampling<W> for FpGenericField<W, L, ACCUM_L, Tag, S>
{
    fn sample<R: FnMut(usize) -> Vec<u8>>(&self, mut rng: R) -> Self::E {
        loop {
            let buf = rng(W * 8);
            let mut words = [0u64; W];
            for (i, chunk) in buf.chunks_exact(8).enumerate() {
                if i < W {
                    words[i] = u64::from_le_bytes(chunk.try_into().unwrap());
                }
            }
            let res = crate::words64_to_limbs(&words);
            if lt(&res, &self.modulo) {
                return self.to_montgomery(&res);
            }
        }
    }
}

impl<const W: usize, const L: usize, const ACCUM_L: usize, Tag, S: MontgomeryStrategy<L>>
    InterpolationField<W> for FpGenericField<W, L, ACCUM_L, Tag, S>
{
    fn poly_evaluation_point(&self, i: usize) -> Self::E {
        self.u64_to_element(i as u64)
    }

    fn newton_denominator(&self, _k: usize, i: usize) -> Self::E {
        let val = self.u64_to_element(i as u64);
        self.invert(&val)
    }
}
