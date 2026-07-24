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

use core_algebra::{AlgebraicField, Nat, SupportsNatConversions};
use mdoc_zk_circuits::signature::concrete::ConcreteGiven;

pub struct MdocSignatureCorruptor<F>
where
    F: AlgebraicField + SupportsNatConversions<4>,
{
    pub name: String,
    pub expected_path: String,
    pub corrupt_input: Option<
        Box<
            dyn Fn(
                &mut mdoc_zk_circuits::signature::SignatureInput<
                    <F as SupportsNatConversions<4>>::N,
                >,
            ),
        >,
    >,
    pub corrupt_given:
        Option<Box<dyn Fn(&mut ConcreteGiven<F, <F as SupportsNatConversions<4>>::N>, &F)>>,
}

pub fn all_mdoc_signature_corruptors<F>() -> Vec<MdocSignatureCorruptor<F>>
where
    F: AlgebraicField + SupportsNatConversions<4> + 'static,
    F::N: 'static,
{
    vec![
        MdocSignatureCorruptor {
            name: "corrupt_issuer_sig_e".into(),
            expected_path: "signature/ecdsa/e_eq".into(),
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, f| {
                g.sig_input.issuer_sig_e =
                    <F as SupportsNatConversions<4>>::N::from_u64(0xdeadbeef);
                g.issuer_sig_given.e = f.reduce_nat(&g.sig_input.issuer_sig_e);
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_issuer_pkx".into(),
            expected_path: "signature/ecdsa/slice_x".into(),
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, f| {
                g.sig_input.issuer_pk.0 = <F as SupportsNatConversions<4>>::N::from_u64(0xdeadbeef);
                g.issuer_sig_given.pkxy.0 = f.reduce_nat(&g.sig_input.issuer_pk.0);
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_issuer_pky".into(),
            expected_path: "signature/ecdsa/slice_x".into(),
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, f| {
                g.sig_input.issuer_pk.1 = <F as SupportsNatConversions<4>>::N::from_u64(0xdeadbeef);
                g.issuer_sig_given.pkxy.1 = f.reduce_nat(&g.sig_input.issuer_pk.1);
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_issuer_sig_r".into(),
            expected_path: "signature/ecdsa/ax_zero".into(),
            corrupt_input: Some(Box::new(|sig| {
                sig.issuer_sig_r = <F as SupportsNatConversions<4>>::N::from_u64(0xdeadbeef);
            })),
            corrupt_given: None,
        },
        MdocSignatureCorruptor {
            name: "corrupt_issuer_sig_s".into(),
            expected_path: "signature/ecdsa/ax_zero".into(),
            corrupt_input: Some(Box::new(|sig| {
                sig.issuer_sig_s = <F as SupportsNatConversions<4>>::N::from_u64(0xdeadbeef);
            })),
            corrupt_given: None,
        },
        MdocSignatureCorruptor {
            name: "corrupt_device_sig_e".into(),
            expected_path: "signature/ecdsa/e_eq".into(),
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, f| {
                g.sig_input.device_sig_e =
                    <F as SupportsNatConversions<4>>::N::from_u64(0xdeadbeef);
                g.device_sig_given.e = f.reduce_nat(&g.sig_input.device_sig_e);
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_device_pkx".into(),
            expected_path: "signature/ecdsa/slice_x".into(),
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, f| {
                g.sig_input.device_pk.0 = <F as SupportsNatConversions<4>>::N::from_u64(0xdeadbeef);
                g.device_sig_given.pkxy.0 = f.reduce_nat(&g.sig_input.device_pk.0);
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_device_pky".into(),
            expected_path: "signature/ecdsa/slice_x".into(),
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, f| {
                g.sig_input.device_pk.1 = <F as SupportsNatConversions<4>>::N::from_u64(0xdeadbeef);
                g.device_sig_given.pkxy.1 = f.reduce_nat(&g.sig_input.device_pk.1);
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_device_sig_r".into(),
            expected_path: "signature/ecdsa/ax_zero".into(),
            corrupt_input: Some(Box::new(|sig| {
                sig.device_sig_r = <F as SupportsNatConversions<4>>::N::from_u64(0xdeadbeef);
            })),
            corrupt_given: None,
        },
        MdocSignatureCorruptor {
            name: "corrupt_device_sig_s".into(),
            expected_path: "signature/ecdsa/ax_zero".into(),
            corrupt_input: Some(Box::new(|sig| {
                sig.device_sig_s = <F as SupportsNatConversions<4>>::N::from_u64(0xdeadbeef);
            })),
            corrupt_given: None,
        },
        MdocSignatureCorruptor {
            name: "corrupt_mac_e".into(),
            expected_path: "signature/assert_mac/msg0_eq/msg0_eq.0/chunk_eq".into(),
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, _| {
                g.mac_e[0] ^= 1;
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_mac_device_pkx".into(),
            expected_path: "signature/assert_mac/msg0_eq/msg0_eq.0/chunk_eq".into(),
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, _| {
                g.mac_device_pkx[0] ^= 1;
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_mac_device_pky".into(),
            expected_path: "signature/assert_mac/msg0_eq/msg0_eq.0/chunk_eq".into(),
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, _| {
                g.mac_device_pky[0] ^= 1;
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_mac_av".into(),
            expected_path: "signature/assert_mac/msg0_eq/msg0_eq.0/chunk_eq".into(),
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, _| {
                g.mac_input.mac_av ^= 1;
            })),
        },
    ]
}
