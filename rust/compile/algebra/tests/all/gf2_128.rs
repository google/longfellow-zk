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
    field::{CompileField, SupportsU64Conversions},
    gf2_128::{Gf2_128, Gf2_128Field},
};
use core_algebra::{AlgebraicField, SerializableField};

#[test]
fn test_constants_and_equality() {
    let field = Gf2_128Field::new();
    let z = field.zero();
    let o = field.one();

    assert!(field.is_zero(&z));
    assert_eq!(o, field.one());
    assert_ne!(z, field.one());
    assert!(!field.is_zero(&o));

    assert_eq!(z, field.u64_to_element(0));
    assert_eq!(o, field.u64_to_element(1));
}

#[test]
fn test_addition_and_subtraction() {
    let field = Gf2_128Field::new();
    let a = field.u64_to_element(0x1234567890abcdef);
    let b = field.u64_to_element(0xfedcba0987654321);

    let sum = field.addf(&a, &b);
    let diff = field.subf(&a, &b);

    // In GF(2^m), addition and subtraction are both XOR
    assert_eq!(sum, diff);

    // a + a = 0
    assert!(field.is_zero(&field.addf(&a, &a)));

    // (a + b) + b = a
    assert_eq!(field.addf(&sum, &b), a);
}

#[test]
fn test_multiplication_and_inversion() {
    let field = Gf2_128Field::new();
    let a = field.u64_to_element(0x1337beef);
    let a_inv = field.invert(&a);
    let prod = field.mulf(&a, &a_inv);

    assert_eq!(prod, field.one());

    // Test precomputed generator x * xinv = 1
    let x = field.u64_to_element(2);
    let xinv = field.invert(&x);
    assert_eq!(field.mulf(&x, &xinv), field.one());

    // 1 * 1 = 1
    let one = field.one();
    assert_eq!(field.mulf(&one, &one), one);
    assert_eq!(field.invert(&one), one);
}

#[test]
fn test_serialization() {
    let field = Gf2_128Field::new();
    let a = field.u64_to_element(0xdeadbeefcafebabe);
    let bytes = field.to_bytes(&a);
    assert_eq!(bytes.len(), 16);
    assert_eq!(bytes.len(), field.serialized_size_bytes());

    let b = field.bytes_to_element(&bytes).unwrap();
    assert_eq!(a, b);
}

// Bulletproof shift-and-add reference multiplier
fn reference_mul(field: &Gf2_128Field, a: Gf2_128, b: Gf2_128) -> Gf2_128 {
    let to_u128 = |e: Gf2_128| -> u128 {
        let bytes = field.to_bytes(&e);
        u128::from_le_bytes(bytes.try_into().unwrap())
    };
    let from_u128 = |val: u128| -> Gf2_128 { field.bytes_to_element(&val.to_le_bytes()).unwrap() };

    let a_u = to_u128(a);
    let b_u = to_u128(b);
    let mut res = 0u128;
    let mut temp_a = a_u;
    for i in 0..128 {
        if ((b_u >> i) & 1) != 0 {
            res ^= temp_a;
        }
        let msb = (temp_a >> 127) & 1;
        temp_a <<= 1;
        if msb != 0 {
            temp_a ^= 0x87;
        }
    }
    from_u128(res)
}

fn assert_mul_eq(field: &Gf2_128Field, a: Gf2_128, b: Gf2_128, msg: &str) -> Gf2_128 {
    let expected = reference_mul(field, a, b);
    let actual = field.mulf(&a, &b);
    assert_eq!(actual, expected, "{msg}: field.mulf(a, b) mismatch");
    let actual_rev = field.mulf(&b, &a);
    assert_eq!(
        actual_rev, expected,
        "{msg}: field.mulf(b, a) mismatch (commutativity)"
    );
    actual
}

#[test]
fn test_powers_multiplication() {
    let field = Gf2_128Field::new();
    let gen = field.u64_to_element(2);

    let mut powers = Vec::with_capacity(100);
    let mut curr = field.one();
    for i in 0..100 {
        powers.push(curr);
        curr = assert_mul_eq(&field, curr, gen, &format!("power generation at index {i}"));
    }

    for (i, &a) in powers.iter().enumerate() {
        for (j, &b) in powers.iter().enumerate().skip(i) {
            assert_mul_eq(&field, a, b, &format!("a=x^{i}, b=x^{j}"));
        }
    }
}

#[test]
fn test_generators_and_basis() {
    let field = Gf2_128Field::new();

    // 1. Verify generators
    let gen_field = field.u64_to_element(2);
    assert_eq!(gen_field, field.u64_to_element(2)); // x
    assert_eq!(field.pseudo_basis(0), field.one());
    assert_eq!(field.pseudo_basis(1), gen_field);

    // 2. Verify basis(i) == x^i
    let mut expected_basis = field.one();
    for i in 0..128 {
        assert_eq!(field.pseudo_basis(i), expected_basis);
        expected_basis = field.mulf(&expected_basis, &gen_field);
    }
}
