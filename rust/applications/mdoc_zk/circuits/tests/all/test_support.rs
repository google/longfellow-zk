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

#![allow(dead_code)]
use core_algebra::{AlgebraicField, Curve, Nat, SupportsNatConversions};
use mdoc_zk_circuits::{hash::HashInput, signature::SignatureInput};

pub(crate) fn prepare_mock_signatures<
    const W: usize,
    FR: AlgebraicField + SupportsNatConversions<W> + core_algebra::HasLookupPoints,
    FnR: core_algebra::AlgebraicField + SupportsNatConversions<W, N = FR::N>,
    C: Curve<W, F = FR, N = FR::N>,
>(
    curve_r: &C,
    fr: &FR,
    fn_field: &FnR,
    mut hash_input: HashInput,
    mut signature_input: SignatureInput<FR::N>,
) -> (HashInput, SignatureInput<FR::N>) {
    let d_dpk = C::N::from_u64(987654321u64);
    let k_dpk = C::N::from_u64(123456789u64);
    let dummy_e = FR::N::from_u64(0);

    let (q_dpk, _, _) = sign_and_generate_given_input::<W, FR, FnR, C>(
        curve_r, fr, fn_field, &d_dpk, &k_dpk, &dummy_e,
    );
    let dpkx_val = fr.to_nat(&q_dpk.0);
    let dpky_val = fr.to_nat(&q_dpk.1);

    let mut dpkx_be = dpkx_val.to_bytes_le();
    dpkx_be.reverse();
    let mut dpky_be = dpky_val.to_bytes_le();
    dpky_be.reverse();

    let dpkx_cose_offset = 58 + hash_input.dev_key_info_offset;
    let dpky_cose_offset = 93 + hash_input.dev_key_info_offset;

    hash_input.cbor_mso[dpkx_cose_offset..dpkx_cose_offset + 32].copy_from_slice(&dpkx_be);
    hash_input.cbor_mso[dpky_cose_offset..dpky_cose_offset + 32].copy_from_slice(&dpky_be);

    let dpkx_compile = compile_algebra::CompileNat::<4>::from_bytes_le(&dpkx_val.to_bytes_le());
    let dpky_compile = compile_algebra::CompileNat::<4>::from_bytes_le(&dpky_val.to_bytes_le());
    hash_input.device_pk = (dpkx_compile, dpky_compile);

    signature_input.device_pk = (dpkx_val.clone(), dpky_val.clone());

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&hash_input.cbor_mso);
    let sha_result = hasher.finalize();

    hash_input.issuer_sig_e = compile_algebra::CompileNat::<4>::from_bytes_be(&sha_result);
    signature_input.issuer_sig_e = FR::N::from_bytes_be(&sha_result);
    signature_input.device_sig_e = FR::N::from_bytes_be(&sha_result);

    let d = C::N::from_u64(123456789u64);
    let k = C::N::from_u64(987654321u64);
    let (pkxy, r, s) = sign_and_generate_given_input::<W, FR, FnR, C>(
        curve_r,
        fr,
        fn_field,
        &d,
        &k,
        &signature_input.issuer_sig_e,
    );
    signature_input.issuer_pk = (fr.to_nat(&pkxy.0), fr.to_nat(&pkxy.1));
    signature_input.issuer_sig_r = r;
    signature_input.issuer_sig_s = s;

    let (_dpk_pkxy, dpk_r, dpk_s) = sign_and_generate_given_input::<W, FR, FnR, C>(
        curve_r,
        fr,
        fn_field,
        &d_dpk,
        &k_dpk,
        &signature_input.device_sig_e,
    );
    signature_input.device_sig_r = dpk_r;
    signature_input.device_sig_s = dpk_s;

    (hash_input, signature_input)
}

fn sign_and_generate_given_input<
    const W: usize,
    F: AlgebraicField + SupportsNatConversions<W> + core_algebra::HasLookupPoints,
    S: AlgebraicField + SupportsNatConversions<W, N = F::N>,
    C: Curve<W, F = F, N = F::N>,
>(
    curve: &C,
    field: &F,
    scalar_field: &S,
    d: &C::N,
    k: &C::N,
    e: &C::N,
) -> (
    (core_algebra::ElementOf<F>, core_algebra::ElementOf<F>),
    C::N,
    C::N,
) {
    let g_val = curve.g().clone();
    let g_proj = circuits_ec::concrete::projective::<F, W, C>(curve, field, &g_val);

    let q_proj = circuits_ec::concrete::scalar_mul::<F, W, C>(curve, field, 256, d, &g_proj);
    let q_normalized = circuits_ec::concrete::affine::<F>(field, &q_proj);

    let r_proj = circuits_ec::concrete::scalar_mul::<F, W, C>(curve, field, 256, k, &g_proj);
    let r_normalized = circuits_ec::concrete::affine::<F>(field, &r_proj);
    let rx = field.to_nat(&r_normalized.0);

    let rx_scalar = scalar_field.nat_to_element(&rx);
    let r = scalar_field.to_nat(&rx_scalar);

    let e_scalar = scalar_field.nat_to_element(e);
    let r_scalar = rx_scalar;
    let d_scalar = scalar_field.nat_to_element(d);
    let k_scalar = scalar_field.nat_to_element(k);
    let rd = scalar_field.mulf(&r_scalar, &d_scalar);
    let e_rd = scalar_field.addf(&e_scalar, &rd);
    let k_inv = scalar_field.invert(&k_scalar);
    let s_scalar = scalar_field.mulf(&k_inv, &e_rd);
    let s = scalar_field.to_nat(&s_scalar);

    ((q_normalized.0, q_normalized.1), r, s)
}
