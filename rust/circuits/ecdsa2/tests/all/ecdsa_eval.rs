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

use circuits_ecdsa2::{derived, evaluate_derived, evaluate_given, given, EcdsaCircuit};
use compile_algebra::{
    field::{CompileField, CompilePrimeField, SupportsNatConversions},
    p256::P256Field,
    q256::Q256Field,
    secp256r1::Secp256r1,
    Curve,
};
use compile_logic::eval::EvalLogic;
use core_algebra::Nat;

use super::test_support;

fn parse_hex<const W: usize, N: Nat<W>>(s: &str) -> N {
    let s_clean = s.strip_prefix("0x").unwrap_or(s);
    let mut bytes = [0u8; 32];
    let s_padded = format!("{s_clean:0>64}");
    for (i, byte) in bytes.iter_mut().enumerate() {
        let high = char_to_digit(s_padded.as_bytes()[2 * i]);
        let low = char_to_digit(s_padded.as_bytes()[2 * i + 1]);
        *byte = (high << 4) | low;
    }
    bytes.reverse();
    N::from_bytes_le(&bytes)
}

fn char_to_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("invalid hex character"),
    }
}

fn test_ecdsa_secp256r1_generic<
    const W: usize,
    F: CompilePrimeField
        + SupportsNatConversions<W>
        + core_algebra::HasLookupPoints
        + core_algebra::SupportsU64Conversions,
    FnR: CompileField + SupportsNatConversions<W, N = F::N>,
    C: Curve<W, F = F, N = F::N>,
>(
    curve: &C,
    f: &F,
    fn_field: &FnR,
) {
    let pkx_str = "0x88903e4e1339bde78dd5b3d7baf3efdd72eb5bf5aaaf686c8f9ff5e7c6368d9c";
    let pky_str = "0xeb8341fc38bb802138498d5f4c03733f457ebbafd0b2fe38e6f58626767f9e75";
    let e_str = "0x2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";
    let r_str = "0xc71bcbfb28bbe06299a225f057797aaf5f22669e90475de5f64176b2612671";
    let s_str = "0x42ad2f2ec7b6e91360b53427690dddfe578c10d8cf480a66a6c2410ff4f6dd40";

    let pkx_val = parse_hex::<W, F::N>(pkx_str);
    let pky_val = parse_hex::<W, F::N>(pky_str);
    let e_val = parse_hex::<W, F::N>(e_str);
    let r_val = parse_hex::<W, F::N>(r_str);
    let s_val = parse_hex::<W, F::N>(s_str);

    let pkxy_r = (f.nat_to_element(&pkx_val), f.nat_to_element(&pky_val));
    let concrete_given = given(curve, &pkxy_r, &e_val, &r_val, &s_val, f, fn_field);
    let concrete_derived = derived(curve, &pkxy_r, &e_val, &r_val, &s_val, f, fn_field);

    type L<'a, F> = EvalLogic<'a, F>;
    let logic = L::new(f);

    let circuit_given = evaluate_given(&concrete_given, &logic);
    let circuit_derived = evaluate_derived(&concrete_derived, &logic);

    let ecdsa = EcdsaCircuit::new(&logic, curve);

    let assertion = ecdsa.assert_signature(&circuit_given, &circuit_derived);
    assertion.unwrap();
}

#[test]
fn test_ecdsa_secp256r1() {
    let f = P256Field::new();
    let fn_field = Q256Field::new();
    let curve = Secp256r1::new(&f);
    test_ecdsa_secp256r1_generic::<4, _, _, _>(&curve, &f, &fn_field);
}

fn test_ecdsa_signature_tampering_generic<
    const W: usize,
    F: CompilePrimeField
        + SupportsNatConversions<W>
        + core_algebra::HasLookupPoints
        + core_algebra::SupportsU64Conversions
        + Clone
        + 'static,
    FnR: CompileField + SupportsNatConversions<W, N = F::N>,
    C: Curve<W, F = F, N = F::N>,
>(
    curve: &C,
    f: &F,
    fn_field: &FnR,
) {
    let d = C::N::from_u64(123456789u64);
    let k = C::N::from_u64(987654321u64);
    let e = C::N::from_u64(555555555u64); // Message hash

    let (concrete_given, concrete_derived) =
        test_support::sign_and_generate_given_derived::<W, _, _, _>(curve, f, fn_field, &d, &k, &e);

    type L<'a, F> = EvalLogic<'a, F>;
    let logic = L::new(f);
    let ecdsa = EcdsaCircuit::new(&logic, curve);

    let corruptors = test_support::all_ecdsa_corruptors::<W, _>(f);

    for c in corruptors {
        let mut g = concrete_given.clone();
        let mut d = concrete_derived.clone();
        (c.corrupt)(&mut g, &mut d);
        let circuit_given = evaluate_given(&g, &logic);
        let circuit_derived = evaluate_derived(&d, &logic);
        let assertion = ecdsa.assert_signature(&circuit_given, &circuit_derived);
        assertion.assert_any_failed_at(c.expected_path);
    }
}

#[test]
fn test_ecdsa_signature_tampering() {
    let f = P256Field::new();
    let fn_field = Q256Field::new();
    let curve = Secp256r1::new(&f);
    test_ecdsa_signature_tampering_generic::<4, _, _, _>(&curve, &f, &fn_field);
}

fn test_sign_and_verify_ecdsa_generic<
    const W: usize,
    F: CompilePrimeField
        + SupportsNatConversions<W>
        + core_algebra::HasLookupPoints
        + core_algebra::SupportsU64Conversions,
    FnR: CompileField + SupportsNatConversions<W, N = F::N>,
    C: Curve<W, F = F, N = F::N>,
>(
    curve: &C,
    f: &F,
    fn_field: &FnR,
) {
    type L<'a, F> = EvalLogic<'a, F>;
    let logic = L::new(f);

    // Private key and nonce
    let d = C::N::from_u64(123456789u64);
    let k = C::N::from_u64(987654321u64);
    let e = C::N::from_u64(555555555u64); // Message hash

    let (concrete_given, concrete_derived) =
        test_support::sign_and_generate_given_derived::<W, _, _, _>(curve, f, fn_field, &d, &k, &e);

    let circuit_given = evaluate_given(&concrete_given, &logic);
    let circuit_derived = evaluate_derived(&concrete_derived, &logic);

    let ecdsa = EcdsaCircuit::new(&logic, curve);
    let assertion = ecdsa.assert_signature(&circuit_given, &circuit_derived);
    assertion.unwrap();
}

#[test]
fn test_sign_and_verify_ecdsa() {
    let f = P256Field::new();
    let fn_field = Q256Field::new();
    let curve = Secp256r1::new(&f);
    test_sign_and_verify_ecdsa_generic::<4, _, _, _>(&curve, &f, &fn_field);
}
