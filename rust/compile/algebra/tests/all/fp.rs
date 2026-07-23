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

use compile_algebra::{
    field::{CompileField, SupportsNatConversions, SupportsU64Conversions},
    fp::{FpField, FpParameters},
};
use core_algebra::{AlgebraicField, SerializableField};
use num_bigint::BigUint;

struct TestFpTag;
type TestFpField = FpField<TestFpTag>;

struct TestFieldCase {
    field: TestFpField,
    modulo: BigUint,
    length_bytes: usize,
}

fn get_test_fields() -> Vec<TestFieldCase> {
    let test_cases = vec![
        (8, BigUint::parse_bytes(b"18446744073709551557", 10).unwrap()),
        (16, BigUint::parse_bytes(b"340282366920938463463374607431768211297", 10).unwrap()),
        (24, BigUint::parse_bytes(b"6277101735386680763835789423207666416102355444464034512659", 10).unwrap()),
        (32, BigUint::parse_bytes(b"115792089237316195423570985008687907853269984665640564039457584007913129639747", 10).unwrap()),
        (40, BigUint::parse_bytes(b"2135987035920910082395021706169552114602704522356652769947041607822219725780640550022962086936379", 10).unwrap()),
        (48, BigUint::parse_bytes(b"39402006196394479212279040100143613805079739270465446667948293404245721771497210611414266254884915640806627990306499", 10).unwrap()),
    ];
    test_cases
        .into_iter()
        .map(|(len_bytes, modulo)| TestFieldCase {
            field: FpField::new_field(FpParameters {
                length_bytes: len_bytes,
                modulo: compile_algebra::CompileNat::<6>::from_biguint(&modulo),
                id: len_bytes,
            }),
            modulo,
            length_bytes: len_bytes,
        })
        .collect()
}

#[test]
fn test_field_constants() {
    for case in get_test_fields() {
        let f = &case.field;
        let zero = f.zero();
        let one = f.one();

        assert!(f.is_zero(&zero));
        assert!(!f.is_zero(&one));
        assert_eq!(one, f.one());
        assert_ne!(zero, f.one());
    }
}

#[test]
fn test_arithmetic() {
    for case in get_test_fields() {
        let f = &case.field;
        let modulo = &case.modulo;

        let a = f.u64_to_element(10);
        let b = f.u64_to_element(12);

        // Addition: (10 + 12) mod p
        let sum = f.addf(&a, &b);
        let expected_sum = (BigUint::from(10u32) + BigUint::from(12u32)) % modulo;
        assert_eq!(
            sum,
            f.nat_to_element(&compile_algebra::CompileNat::<6>::from(expected_sum))
        );

        // Subtraction: (10 - 12) mod p
        let diff = f.subf(&a, &b);
        let expected_diff = if modulo > &BigUint::from(2u32) {
            modulo - BigUint::from(2u32)
        } else {
            (BigUint::from(10u32) + modulo - BigUint::from(12u32)) % modulo
        };
        assert_eq!(
            diff,
            f.nat_to_element(&compile_algebra::CompileNat::<6>::from(expected_diff))
        );

        // Multiplication: (10 * 12) mod p
        let prod = f.mulf(&a, &b);
        let expected_prod = (BigUint::from(10u32) * BigUint::from(12u32)) % modulo;
        assert_eq!(
            prod,
            f.nat_to_element(&compile_algebra::CompileNat::<6>::from(expected_prod))
        );

        // Inversion
        let inv = f.invert(&a);
        let identity = f.mulf(&a, &inv);
        assert_eq!(identity, f.one());
    }
}

#[test]
fn test_negation() {
    for case in get_test_fields() {
        let f = &case.field;
        let modulo = &case.modulo;

        let a = f.u64_to_element(5);
        let neg_a = f.neg(&a);
        let expected_neg = modulo - BigUint::from(5u32);
        assert_eq!(
            neg_a,
            f.nat_to_element(&compile_algebra::CompileNat::<6>::from(expected_neg))
        );
        assert!(f.is_zero(&f.addf(&a, &neg_a)));
    }
}

#[test]
fn test_to_from_bytes() {
    for case in get_test_fields() {
        let f = &case.field;
        let len_bytes = case.length_bytes;

        let a = f.u64_to_element(10);
        let bytes = f.to_bytes(&a);
        assert_eq!(bytes.len(), len_bytes);
        assert_eq!(bytes.len(), f.serialized_size_bytes());

        let decoded = f
            .bytes_to_element(bytes.as_slice())
            .expect("Failed to deserialize");
        assert_eq!(a, decoded);
    }
}

#[test]
fn test_large_number_creation() {
    for case in get_test_fields() {
        let f = &case.field;
        let modulo = &case.modulo;

        let a = f.nat_to_element(&compile_algebra::CompileNat::<6>::from(modulo.clone()));
        assert!(f.is_zero(&a));

        let b_val = modulo + BigUint::from(2u32);
        let b = f.nat_to_element(&compile_algebra::CompileNat::<6>::from(b_val));
        assert_eq!(b, f.u64_to_element(2));
    }
}

#[test]
fn test_fp_basis() {
    use std::collections::HashSet;

    // 1. Field of size 65537 (prime)
    let f_65537 = FpField::<TestFpTag>::new_field(FpParameters {
        length_bytes: 3,
        modulo: compile_algebra::CompileNat::<6>::from(65537u64),
        id: 2,
    });

    assert_eq!(f_65537.pseudo_dimension(), 16);

    let mut seen: HashSet<compile_algebra::CompileNat<6>> = HashSet::new();
    for mask in 0..(1 << 16) {
        let mut val = f_65537.zero();
        for i in 0..16 {
            if (mask & (1 << i)) != 0 {
                val = f_65537.addf(&val, &f_65537.pseudo_basis(i));
            }
        }
        assert!(
            seen.insert(f_65537.to_nat(&val)),
            "Duplicate linear combination found for 65537 at mask {mask}"
        );
    }
    assert_eq!(seen.len(), 65536);

    // 2. Largest prime smaller than 65536 is 65521
    let f_65521 = FpField::<TestFpTag>::new_field(FpParameters {
        length_bytes: 2,
        modulo: compile_algebra::CompileNat::<6>::from(65521u64),
        id: 3,
    });

    assert_eq!(f_65521.pseudo_dimension(), 15);

    let mut seen_large_prime: HashSet<compile_algebra::CompileNat<6>> = HashSet::new();
    for mask in 0..(1 << 15) {
        let mut val = f_65521.zero();
        for i in 0..15 {
            if (mask & (1 << i)) != 0 {
                val = f_65521.addf(&val, &f_65521.pseudo_basis(i));
            }
        }
        assert!(
            seen_large_prime.insert(f_65521.to_nat(&val)),
            "Duplicate linear combination found for 65521 at mask {mask}"
        );
    }
    assert_eq!(seen_large_prime.len(), 32768);
}

#[test]
fn test_compare_consistency() {
    use core_algebra::Comparable;
    for case in get_test_fields() {
        let field = &case.field;
        let test_values: Vec<u64> =
            vec![0, 1, 2, 3, 5, 10, 42, 100, 12345, 65535, 1000000, 123456789];
        for &x in &test_values {
            for &y in &test_values {
                let ex = field.u64_to_element(x);
                let ey = field.u64_to_element(y);
                assert_eq!(
                    field.compare(&ex, &ey),
                    x.cmp(&y),
                    "Consistency check failed for field of modulus {} at {} vs {}",
                    case.modulo,
                    x,
                    y
                );
            }
        }
    }
}
