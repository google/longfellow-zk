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

use core_algebra::{AlgebraicField, SerializableField, SupportsU64Conversions};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use runtime_algebra::{
    fp_generic::{FpGenericElement, FpGenericField, MontgomeryStrategy},
    RuntimeField,
};

fn to_biguint_field<
    const N: usize,
    const L: usize,
    const ACCUM_L: usize,
    S: MontgomeryStrategy<L>,
>(
    field: &FpGenericField<N, L, ACCUM_L, (), S>,
    e: &FpGenericElement<L, ()>,
) -> BigUint {
    let bytes = field.to_bytes(e);
    BigUint::from_bytes_le(&bytes)
}

fn from_biguint_field<
    const N: usize,
    const L: usize,
    const ACCUM_L: usize,
    S: MontgomeryStrategy<L>,
>(
    field: &FpGenericField<N, L, ACCUM_L, (), S>,
    b: &BigUint,
) -> FpGenericElement<L, ()> {
    let mut bytes = b.to_bytes_le();
    bytes.resize(N * 8, 0);
    field.bytes_to_element(&bytes).unwrap()
}

fn test_generic_ops_helper<const N: usize, const L: usize, const ACCUM_L: usize>(
    modulo_words: [u64; N],
    a_val: u64,
    b_val: u64,
) {
    let modulo = BigUint::from_bytes_le(&vec_of_limbs(&modulo_words));
    println!("Testing N = {N}, modulo = {modulo}");
    let field = FpGenericField::<N, L, ACCUM_L, ()>::new_generic(modulo_words);

    let a_bi = BigUint::from(a_val) % &modulo;
    let b_bi = BigUint::from(b_val) % &modulo;

    let a = from_biguint_field(&field, &a_bi);
    let b = from_biguint_field(&field, &b_bi);

    let a_bytes = field.to_bytes(&a);
    assert_eq!(a_bytes.len(), field.serialized_size_bytes());

    let sum = field.addf(&a, &b);
    let diff = field.subf(&a, &b);
    let prod = field.mulf(&a, &b);

    let expected_sum = (&a_bi + &b_bi) % &modulo;
    let expected_diff = if a_bi >= b_bi {
        (&a_bi - &b_bi) % &modulo
    } else {
        (&modulo + &a_bi - &b_bi) % &modulo
    };
    let expected_prod = (&a_bi * &b_bi) % &modulo;

    assert_eq!(
        to_biguint_field(&field, &sum),
        expected_sum,
        "Sum mismatch for N = {N}"
    );
    assert_eq!(
        to_biguint_field(&field, &diff),
        expected_diff,
        "Diff mismatch for N = {N}"
    );
    assert_eq!(
        to_biguint_field(&field, &prod),
        expected_prod,
        "Prod mismatch for N = {N}"
    );

    let mut acc = field.zero_accum();
    field.mac(&mut acc, &a, &b);
    field.mac(&mut acc, &b, &a);
    let accum_res = field.accum_reduce(&acc);
    let expected_accum_res = field.addf(&prod, &prod);
    assert_eq!(
        accum_res, expected_accum_res,
        "MAC / accum_reduce mismatch for N = {N}"
    );

    if !a_bi.is_zero() {
        let inv = field.invert(&a);

        let inv_bi = num_bigint::BigInt::from(a_bi.clone());
        let mod_bi = num_bigint::BigInt::from(modulo.clone());
        fn egcd(
            a: &num_bigint::BigInt,
            b: &num_bigint::BigInt,
        ) -> (num_bigint::BigInt, num_bigint::BigInt, num_bigint::BigInt) {
            use num_traits::Zero;
            if a.is_zero() {
                (
                    b.clone(),
                    num_bigint::BigInt::zero(),
                    num_bigint::BigInt::one(),
                )
            } else {
                let (g, x, y) = egcd(&(b % a), a);
                (g, y - (b / a) * &x, x)
            }
        }
        let (g, x, _) = egcd(&inv_bi, &mod_bi);
        assert!(g.is_one());
        let expected_inv = ((x % &mod_bi + &mod_bi) % &mod_bi).to_biguint().unwrap();

        assert_eq!(
            to_biguint_field(&field, &inv),
            expected_inv,
            "Inverse mismatch for N = {N}"
        );

        let identity = field.mulf(&a, &inv);
        assert_eq!(
            identity,
            field.one(),
            "Multiplicative identity mismatch for N = {N}"
        );
    }
}

fn vec_of_limbs(limbs: &[u64]) -> Vec<u8> {
    let mut bytes = vec![0u8; limbs.len() * 8];
    for i in 0..limbs.len() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limbs[i].to_le_bytes());
    }
    bytes
}

#[test]
fn test_all_generics() {
    // N = 1
    test_generic_ops_helper::<
        1,
        { runtime_algebra::LIMBS_PER_U64 },
        { 2 * runtime_algebra::LIMBS_PER_U64 + 1 },
    >([0xffffffffffffffc5], 0x123456789abcdef0, 0xabcdef1234567890);

    // N = 2
    test_generic_ops_helper::<
        2,
        { 2 * runtime_algebra::LIMBS_PER_U64 },
        { 2 * 2 * runtime_algebra::LIMBS_PER_U64 + 1 },
    >(
        [0xffffffffffffff61, 0xffffffffffffffff],
        0x123456789abcdef0,
        0xabcdef1234567890,
    );

    // N = 3
    test_generic_ops_helper::<
        3,
        { 3 * runtime_algebra::LIMBS_PER_U64 },
        { 2 * 3 * runtime_algebra::LIMBS_PER_U64 + 1 },
    >(
        [0xffffffffffffff13, 0xffffffffffffffff, 0xffffffffffffffff],
        0x123456789abcdef0,
        0xabcdef1234567890,
    );

    // N = 4
    test_generic_ops_helper::<
        4,
        { 4 * runtime_algebra::LIMBS_PER_U64 },
        { 2 * 4 * runtime_algebra::LIMBS_PER_U64 + 1 },
    >(
        [
            0xffffffffffffff43,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
        ],
        0x123456789abcdef0,
        0xabcdef1234567890,
    );

    // N = 5
    test_generic_ops_helper::<
        5,
        { 5 * runtime_algebra::LIMBS_PER_U64 },
        { 2 * 5 * runtime_algebra::LIMBS_PER_U64 + 1 },
    >(
        [
            0xffffffffffffff3b,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
        ],
        0x123456789abcdef0,
        0xabcdef1234567890,
    );

    // N = 6
    test_generic_ops_helper::<
        6,
        { 6 * runtime_algebra::LIMBS_PER_U64 },
        { 2 * 6 * runtime_algebra::LIMBS_PER_U64 + 1 },
    >(
        [
            0xfffffffffffffec3,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
        ],
        0x123456789abcdef0,
        0xabcdef1234567890,
    );
}

#[test]
fn test_accum_reduce_scaling_bug() {
    // This test specifically verifies that `accum_reduce` properly scales accumulated
    // products back down to standard Montgomery representation. On 32-bit platforms
    // (where LIMBS_PER_U64 = 2), an earlier bug in `accum_scale` calculation caused
    // `accum_reduce` results to be off by a factor of 2^32.
    let modulo_words = [
        0xffffffffffffffff,
        0x00000000ffffffff,
        0x0000000000000000,
        0xffffffff00000001,
    ];
    let field = FpGenericField::<
        4,
        { 4 * runtime_algebra::LIMBS_PER_U64 },
        { 9 * runtime_algebra::LIMBS_PER_U64 },
        (),
    >::new_generic(modulo_words);

    let a = field.u64_to_element(123456789);
    let b = field.u64_to_element(987654321);
    let c = field.u64_to_element(111111111);
    let d = field.u64_to_element(222222222);

    let mut acc = field.zero_accum();
    field.mac(&mut acc, &a, &b);
    field.mac(&mut acc, &c, &d);

    let res = field.accum_reduce(&acc);
    let expected = field.addf(&field.mulf(&a, &b), &field.mulf(&c, &d));

    assert_eq!(
        res, expected,
        "accum_reduce did not match mul + add! Likely accum_scale scaling bug."
    );
}

#[test]
#[should_panic(expected = "field limb count must match its serialized word width")]
fn test_rejects_mismatched_limb_count() {
    let _ = FpGenericField::<
        1,
        { runtime_algebra::LIMBS_PER_U64 + 1 },
        { 2 * (runtime_algebra::LIMBS_PER_U64 + 1) + 1 },
    >::new_generic([0xffff_ffff_ffff_ffc5]);
}

#[test]
#[should_panic(expected = "accumulator must contain at least twice the field limbs plus one")]
fn test_rejects_undersized_accumulator() {
    let _ = FpGenericField::<
        1,
        { runtime_algebra::LIMBS_PER_U64 },
        { 2 * runtime_algebra::LIMBS_PER_U64 },
    >::new_generic([0xffff_ffff_ffff_ffc5]);
}

#[test]
#[should_panic(expected = "Montgomery modulus must be odd and greater than one")]
fn test_rejects_invalid_montgomery_modulus() {
    let _ = FpGenericField::<
        1,
        { runtime_algebra::LIMBS_PER_U64 },
        { 2 * runtime_algebra::LIMBS_PER_U64 + 1 },
    >::new_generic([16]);
}
