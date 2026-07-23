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

use compile_algebra::CompileNat;
use core_algebra::Nat;

#[derive(Clone, Debug)]
pub struct SignatureInput<N = CompileNat<4>> {
    pub issuer_pk: (N, N),
    pub issuer_sig_e: N,
    pub issuer_sig_r: N,
    pub issuer_sig_s: N,
    pub device_pk: (N, N),
    pub device_sig_e: N,
    pub device_sig_r: N,
    pub device_sig_s: N,
}

#[derive(Clone, Debug)]
pub struct SignatureMac {
    pub mac_av: u128,
    pub mac_ap: [[u128; 2]; 3],
}

#[derive(Clone, Debug)]
pub struct ConcreteGiven<F: core_algebra::AlgebraicField, N = CompileNat<4>> {
    pub sig_input: SignatureInput<N>,
    pub mac_input: SignatureMac,
    pub mac_e: [u128; 2],
    pub mac_device_pkx: [u128; 2],
    pub mac_device_pky: [u128; 2],
    pub issuer_sig_given: circuits_ecdsa2::concrete::ConcreteGiven<F>,
    pub device_sig_given: circuits_ecdsa2::concrete::ConcreteGiven<F>,
}

#[derive(Clone, Debug)]
pub struct ConcreteDerived<F: core_algebra::AlgebraicField> {
    pub issuer_sig_derived: circuits_ecdsa2::concrete::ConcreteDerived<F>,
    pub device_sig_derived: circuits_ecdsa2::concrete::ConcreteDerived<F>,
}

pub fn signature_input_of_parsed_mdoc<const W: usize, N: Nat<W>>(
    parsed: &crate::cbor::mdoc::ParsedMdoc<N>,
    issuer_pk: (N, N),
) -> SignatureInput<N> {
    SignatureInput {
        issuer_pk,
        issuer_sig_e: parsed.issuer_sig_digest.clone(),
        issuer_sig_r: parsed.issuer_sig_r.clone(),
        issuer_sig_s: parsed.issuer_sig_s.clone(),
        device_pk: parsed.device_pk.clone(),
        device_sig_e: parsed.device_sig_digest.clone(),
        device_sig_r: parsed.device_sig_r.clone(),
        device_sig_s: parsed.device_sig_s.clone(),
    }
}

pub fn compute_mac_tags<
    const W: usize,
    F: core_algebra::AlgebraicField + core_algebra::SupportsNatConversions<W>,
>(
    sig_input: &SignatureInput<F::N>,
    mac_input: &SignatureMac,
) -> ([u128; 2], [u128; 2], [u128; 2]) {
    let to_32_bytes = |val: &F::N| -> [u8; 32] {
        let bytes = val.to_bytes_le();
        let mut padded = [0u8; 32];
        let len = bytes.len().min(32);
        padded[..len].copy_from_slice(&bytes[..len]);
        padded
    };

    let issuer_sig_e_msg = to_32_bytes(&sig_input.issuer_sig_e);
    let device_pkx_msg = to_32_bytes(&sig_input.device_pk.0);
    let device_pky_msg = to_32_bytes(&sig_input.device_pk.1);

    let mac_e = circuits_mac::concrete::compute_tag(
        &issuer_sig_e_msg,
        mac_input.mac_av,
        &mac_input.mac_ap[0],
    );
    let mac_device_pkx = circuits_mac::concrete::compute_tag(
        &device_pkx_msg,
        mac_input.mac_av,
        &mac_input.mac_ap[1],
    );
    let mac_device_pky = circuits_mac::concrete::compute_tag(
        &device_pky_msg,
        mac_input.mac_av,
        &mac_input.mac_ap[2],
    );

    (mac_e, mac_device_pkx, mac_device_pky)
}

pub fn given<
    const W: usize,
    F: core_algebra::AlgebraicField
        + core_algebra::SupportsNatConversions<W>
        + core_algebra::HasLookupPoints,
    Fn: core_algebra::AlgebraicField + core_algebra::SupportsNatConversions<W, N = F::N>,
    C: core_algebra::Curve<W, F = F, N = F::N>,
>(
    sig_input: SignatureInput<F::N>,
    mac_input: SignatureMac,
    f: &F,
    fn_field: &Fn,
    curve: &C,
) -> ConcreteGiven<F, F::N> {
    let (mac_e, mac_device_pkx, mac_device_pky) = {
        let nat_to_32bytes = |n: &F::N| -> [u8; 32] {
            let bytes = n.to_bytes_le();
            assert!(bytes.len() <= 32);
            let mut padded = [0u8; 32];
            padded[..bytes.len()].copy_from_slice(&bytes);
            padded
        };

        let mac_e = circuits_mac::concrete::compute_tag(
            &nat_to_32bytes(&sig_input.issuer_sig_e),
            mac_input.mac_av,
            &mac_input.mac_ap[0],
        );
        let mac_device_pkx = circuits_mac::concrete::compute_tag(
            &nat_to_32bytes(&sig_input.device_pk.0),
            mac_input.mac_av,
            &mac_input.mac_ap[1],
        );
        let mac_device_pky = circuits_mac::concrete::compute_tag(
            &nat_to_32bytes(&sig_input.device_pk.1),
            mac_input.mac_av,
            &mac_input.mac_ap[2],
        );

        (mac_e, mac_device_pkx, mac_device_pky)
    };

    let issuer_pkxy = (
        f.nat_to_element(&sig_input.issuer_pk.0),
        f.nat_to_element(&sig_input.issuer_pk.1),
    );
    let issuer_sig_given = circuits_ecdsa2::concrete::given(
        curve,
        &issuer_pkxy,
        &sig_input.issuer_sig_e,
        &sig_input.issuer_sig_r,
        &sig_input.issuer_sig_s,
        f,
        fn_field,
    );

    let device_pkxy = (
        f.nat_to_element(&sig_input.device_pk.0),
        f.nat_to_element(&sig_input.device_pk.1),
    );
    let device_sig_given = circuits_ecdsa2::concrete::given(
        curve,
        &device_pkxy,
        &sig_input.device_sig_e,
        &sig_input.device_sig_r,
        &sig_input.device_sig_s,
        f,
        fn_field,
    );

    ConcreteGiven {
        sig_input,
        mac_input,
        mac_e,
        mac_device_pkx,
        mac_device_pky,
        issuer_sig_given,
        device_sig_given,
    }
}

pub fn derived<
    const W: usize,
    F: core_algebra::AlgebraicField
        + core_algebra::SupportsNatConversions<W>
        + core_algebra::HasLookupPoints,
    Fn: core_algebra::AlgebraicField + core_algebra::SupportsNatConversions<W, N = F::N>,
    C: core_algebra::Curve<W, F = F, N = F::N>,
>(
    f: &F,
    fn_field: &Fn,
    curve: &C,
    input: &ConcreteGiven<F, F::N>,
) -> Result<ConcreteDerived<F>, String> {
    let issuer_pkxy = (
        f.nat_to_element(&input.sig_input.issuer_pk.0),
        f.nat_to_element(&input.sig_input.issuer_pk.1),
    );
    let issuer_sig_derived = circuits_ecdsa2::concrete::derived(
        curve,
        &issuer_pkxy,
        &input.sig_input.issuer_sig_e,
        &input.sig_input.issuer_sig_r,
        &input.sig_input.issuer_sig_s,
        f,
        fn_field,
    );

    let device_pkxy = (
        f.nat_to_element(&input.sig_input.device_pk.0),
        f.nat_to_element(&input.sig_input.device_pk.1),
    );
    let device_sig_derived = circuits_ecdsa2::concrete::derived(
        curve,
        &device_pkxy,
        &input.sig_input.device_sig_e,
        &input.sig_input.device_sig_r,
        &input.sig_input.device_sig_s,
        f,
        fn_field,
    );

    Ok(ConcreteDerived {
        issuer_sig_derived,
        device_sig_derived,
    })
}

impl<FR: core_algebra::AlgebraicField> ConcreteDerived<FR> {
    #[cfg(feature = "testonly")]
    pub fn push_derived(&self, mut push: impl FnMut(FR::E)) {
        let push_ecdsa = |d: &circuits_ecdsa2::concrete::ConcreteDerived<FR>,
                          p: &mut dyn FnMut(FR::E)| {
            p(d.pkxinv.clone());
            p(d.rxinv.clone());
            p(d.nmsinv.clone());
            p(d.yinv.clone());
            p(d.slicing.g_pk.0.clone());
            p(d.slicing.g_pk.1.clone());
            p(d.slicing.g_r.0.clone());
            p(d.slicing.g_r.1.clone());
            p(d.slicing.pk_r.0.clone());
            p(d.slicing.pk_r.1.clone());
            p(d.slicing.g_pk_r.0.clone());
            p(d.slicing.g_pk_r.1.clone());
            for pt in &d.slicing.round {
                p(pt.0.clone());
                p(pt.1.clone());
                p(pt.2.clone());
            }
        };
        push_ecdsa(&self.issuer_sig_derived, &mut push);
        push_ecdsa(&self.device_sig_derived, &mut push);
    }
}
