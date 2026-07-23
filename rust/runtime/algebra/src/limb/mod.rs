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

#[cfg(all(target_pointer_width = "64", not(feature = "force-32bit-limbs")))]
mod limb_64;
#[cfg(all(target_pointer_width = "64", not(feature = "force-32bit-limbs")))]
pub use limb_64::*;

#[cfg(any(target_pointer_width = "32", feature = "force-32bit-limbs"))]
mod limb_32;
#[cfg(any(target_pointer_width = "32", feature = "force-32bit-limbs"))]
pub use limb_32::*;

/// a += b, propagating carry. Returns carry bit.
/// Both arrays must have the same size N.
#[inline(always)]
pub fn add_limb<const N: usize>(a: &mut [Limb; N], b: &[Limb; N]) -> Limb {
    let mut carry = false;
    for i in 0..N {
        let (sum, c) = a[i].carrying_add(b[i], carry);
        a[i] = sum;
        carry = c;
    }
    Limb::from(carry)
}

/// a -= b, propagating borrow. Returns borrow bit.
/// Both arrays must have the same size N.
#[inline(always)]
pub fn sub_limb<const N: usize>(a: &mut [Limb; N], b: &[Limb; N]) -> Limb {
    let mut borrow = false;
    for i in 0..N {
        let (diff, bor) = a[i].borrowing_sub(b[i], borrow);
        a[i] = diff;
        borrow = bor;
    }
    Limb::from(borrow)
}

/// Right-shift multi-limb array `a` by 1 bit.
#[inline(always)]
#[must_use]
pub fn shr_1<const N: usize>(a: &[Limb; N]) -> [Limb; N] {
    let mut res = [0 as Limb; N];
    let mut carry = 0;
    for i in (0..N).rev() {
        let new_carry = a[i] << (crate::LIMB_BITS - 1);
        res[i] = (a[i] >> 1) | carry;
        carry = new_carry;
    }
    res
}

/// Propagate carry through slice `a` starting from index `start`.
/// Unconditional (no branch/break) to allow loop unrolling and avoid pipeline stalls.
#[inline(always)]
pub fn propagate_carry(a: &mut [Limb], start: usize, mut carry: bool) {
    let zero = crate::arch::zero_but_you_dont_know_it();
    for limb in &mut a[start..] {
        let (sum, c) = limb.carrying_add(zero, carry);
        *limb = sum;
        carry = c;
    }
}

/// In-place addition of b to slice a at offset `start`, propagating carry.
/// a has dynamic slice length, b has size NB. Reuses `add_limb`.
#[inline(always)]
pub fn accum<const NB: usize>(a: &mut [Limb], start: usize, b: &[Limb; NB]) {
    assert!(a.len() >= start + NB);
    let dest: &mut [Limb; NB] = (&mut a[start..start + NB]).try_into().unwrap();
    let carry = add_limb(dest, b);
    propagate_carry(a, start + NB, carry != 0);
}

#[inline(always)]
#[must_use]
pub fn is_zero_slice<const N: usize>(a: &[Limb; N]) -> bool {
    a.iter().all(|&x| x == 0)
}

#[inline(always)]
#[must_use]
pub fn is_one_slice<const N: usize>(a: &[Limb; N]) -> bool {
    a[0] == 1 && a.iter().skip(1).all(|&x| x == 0)
}

#[inline(always)]
#[must_use]
pub fn mulhl<const N: usize>(x: Limb, y: &[Limb; N]) -> ([Limb; N], [Limb; N]) {
    let mut l = [0 as Limb; N];
    let mut h = [0 as Limb; N];
    for i in 0..N {
        let (low, high) = mulhl_one(x, y[i]);
        l[i] = low;
        h[i] = high;
    }
    (l, h)
}

/// In-place accumulation of the product `x * y` into slice `a` at offset `start`.
/// Reuses mulhl and accum.
#[inline(always)]
pub fn mul_accum<const NB: usize>(a: &mut [Limb], start: usize, x: Limb, y: &[Limb; NB]) {
    let (l, h) = mulhl(x, y);
    accum(a, start, &l);
    accum(a, start + 1, &h);
}

/// In-place accumulation of the product `x * y` into slice `a` at offset `start`,
/// assuming `a[start..start + NB]` is initially zero.
#[inline(always)]
pub fn mul_accum_zero<const NB: usize>(a: &mut [Limb], start: usize, x: Limb, y: &[Limb; NB]) {
    let (l, h) = mulhl(x, y);
    a[start..start + NB].copy_from_slice(&l);
    accum(a, start + 1, &h);
}

#[inline(always)]
#[must_use]
pub fn lt<const N: usize>(a: &[Limb; N], b: &[Limb; N]) -> bool {
    for i in (0..N).rev() {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false
}

/// Subtract modulo from `A` if carry out occurred (`AH != 0`) or if
/// `A >= M` (using `NEGM = R - M`, where R = 2^W).
/// Let R = 2^W
///     X = AH:A = AH * R + A
///     X1 = AH1:A1 = AH1 * R + A1 = A + (R - M)    (note A not X)
///
/// Assume M < R /\ X < 2M
///
/// Lemmas:
///   L1: AH = 1 => X = R + A < 2*M => A < 2*M - R = M - (R - M) < M.
///   L2: AH1 = 1 => X1 = A + (R - M) >= R => A >= M.
///
/// Case (AH, AH1):
///   (0, 0) => X1 < R
///          => X + R - M < R
///          => X < M
///          => return X
///   (0, 1) => A >= M by L2
///          => return A - M
///   (1, 0) => X = R + A >= R > M
///          => return A + (R - M) = X - M
///   (1, 1) => A < M (by L1) /\ A >= M (by L2)
///          => unreachable
#[inline(always)]
pub fn maybe_minus_m<const N: usize>(a: &mut [Limb; N], ah: Limb, negm: &[Limb; N]) {
    let mut a1 = *negm;
    let ah1 = add_limb(&mut a1, a);
    crate::arch::cmovne(a, ah, ah1, &a1);
}

/// Add modulo to a if borrow occurred in subtraction.
#[inline(always)]
pub fn maybe_plus_m<const N: usize>(a: &mut [Limb; N], ah: Limb, modulo: &[Limb; N]) {
    let mut a1 = *a;
    let _ = add_limb(&mut a1, modulo);
    crate::arch::cmovnz(a, ah, &a1);
}
pub use crate::arch::cmovnz as cmovzn;

/// Abstract the pattern of adding b to a and reducing modulo (accum + `maybe_minus_m`).
#[inline(always)]
pub fn accum_modular<const N: usize>(a: &mut [Limb; N], b: &[Limb; N], negm: &[Limb; N]) {
    let carry = add_limb(a, b);
    maybe_minus_m(a, carry, negm);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maybe_minus_m_all_cases() {
        // Modulo M = 100 for N = 4 limbs
        // negm = 2^256 - 100
        let negm = [Limb::MAX - 99, Limb::MAX, Limb::MAX, Limb::MAX];

        // Case 1: ah = 0, ah1 = 0 (A < M, no reduction needed)
        let mut a1 = [50, 0, 0, 0];
        let ah1 = 0;
        maybe_minus_m(&mut a1, ah1, &negm);
        assert_eq!(
            a1,
            [50, 0, 0, 0],
            "Case 1 failed: ah=0, ah1=0 should keep a unchanged"
        );

        // Case 2: ah = 0, ah1 = 1 (A >= M and A < 2^256, reduction needed)
        let mut a2 = [120, 0, 0, 0];
        let ah2 = 0;
        maybe_minus_m(&mut a2, ah2, &negm);
        assert_eq!(
            a2,
            [20, 0, 0, 0],
            "Case 2 failed: ah=0, ah1=1 should subtract M"
        );

        // Case 3: ah = 1, ah1 = 0 (A >= 2^256, top carry set, reduction needed)
        // A = 2^256 + 30. Lower 4 limbs are [30, 0, 0, 0], top carry ah = 1.
        // A - M = (2^256 + 30) - 100 = 2^256 - 70.
        // Lower 4 limbs of 2^256 - 70 are [Limb::MAX - 69, Limb::MAX, Limb::MAX, Limb::MAX].
        let mut a3 = [30, 0, 0, 0];
        let ah3 = 1;
        maybe_minus_m(&mut a3, ah3, &negm);
        let expected_case3 = [Limb::MAX - 69, Limb::MAX, Limb::MAX, Limb::MAX];
        assert_eq!(
            a3, expected_case3,
            "Case 3 failed: ah=1, ah1=0 should subtract M from (2^256 + a)"
        );
    }

    #[test]
    fn test_shr_1() {
        let a: [Limb; 2] = [0b10, 0b1]; // 2^64 + 2
        let shifted = shr_1(&a);
        assert_eq!(shifted, [(1u64 << (LIMB_BITS - 1)) | 1, 0]);
    }
}
