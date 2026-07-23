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

use core_algebra::{AlgebraicField, SerializableField};
use num_bigint::BigUint;
use runtime_algebra::q256::{Q256Element, Q256Field};

fn to_biguint(field: &Q256Field, e: &Q256Element) -> BigUint {
    let bytes = field.to_bytes(e);
    BigUint::from_bytes_le(&bytes)
}

fn from_biguint(field: &Q256Field, b: &BigUint) -> Q256Element {
    let mut bytes = b.to_bytes_le();
    bytes.resize(32, 0);
    field.bytes_to_element(&bytes).unwrap()
}

#[test]
fn test_q256_basic_ops() {
    use num_traits::One;
    let field = Q256Field::new();
    let modulo = BigUint::parse_bytes(
        b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        16,
    )
    .unwrap();

    // 1. Test addition & subtraction
    let a_bi = BigUint::from(0x123456789abcdef0u64) * BigUint::from(0xabcdef1234567890u64);
    let b_bi = BigUint::from(0x9876543210fedcbau64) * BigUint::from(0x0fedcba987654321u64);

    let a = from_biguint(&field, &a_bi);
    let b = from_biguint(&field, &b_bi);

    let sum = field.addf(&a, &b);
    let diff = field.subf(&a, &b);

    let expected_sum = (&a_bi + &b_bi) % &modulo;
    let expected_diff = if a_bi >= b_bi {
        (&a_bi - &b_bi) % &modulo
    } else {
        (&modulo + &a_bi - &b_bi) % &modulo
    };

    assert_eq!(to_biguint(&field, &sum), expected_sum);
    assert_eq!(to_biguint(&field, &diff), expected_diff);

    // 2. Test multiplication
    let prod = field.mulf(&a, &b);
    let expected_prod = (&a_bi * &b_bi) % &modulo;
    assert_eq!(to_biguint(&field, &prod), expected_prod);

    // 3. Test modular inversion
    let inv = field.invert(&a);

    let inv_bi = num_bigint::BigInt::from(a_bi.clone());
    let mod_bi = num_bigint::BigInt::from(modulo.clone());
    fn egcd(
        a: &num_bigint::BigInt,
        b: &num_bigint::BigInt,
    ) -> (num_bigint::BigInt, num_bigint::BigInt, num_bigint::BigInt) {
        use num_traits::{One, Zero};
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

    assert_eq!(to_biguint(&field, &inv), expected_inv);

    let identity = field.mulf(&a, &inv);
    assert_eq!(identity, field.one());
}

#[test]
fn test_serialization() {
    let field = Q256Field::new();
    let one = field.one();
    let bytes = field.to_bytes(&one);
    assert_eq!(bytes.len(), field.serialized_size_bytes());
}
