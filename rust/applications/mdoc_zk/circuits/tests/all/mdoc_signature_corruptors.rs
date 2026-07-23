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

use compile_algebra::{p256::P256Field, CompileNat};
use core_algebra::{Nat, SupportsNatConversions};
use mdoc_zk_circuits::signature::concrete::ConcreteGiven;

pub struct MdocSignatureCorruptor {
    pub name: &'static str,
    pub expected_path: &'static str,
    pub corrupt_input:
        Option<Box<dyn Fn(&mut mdoc_zk_circuits::signature::SignatureInput<CompileNat<4>>)>>,
    pub corrupt_given:
        Option<Box<dyn Fn(&mut ConcreteGiven<P256Field, CompileNat<4>>, &P256Field)>>,
}

pub fn all_mdoc_signature_corruptors() -> Vec<MdocSignatureCorruptor> {
    vec![
        MdocSignatureCorruptor {
            name: "corrupt_issuer_sig_e",
            expected_path: "signature",
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, f| {
                g.sig_input.issuer_sig_e = CompileNat::<4>::from_u64(0xdeadbeef);
                g.issuer_sig_given.e = f.nat_to_element(&g.sig_input.issuer_sig_e);
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_issuer_pkx",
            expected_path: "signature",
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, f| {
                g.sig_input.issuer_pk.0 = CompileNat::<4>::from_u64(0xdeadbeef);
                g.issuer_sig_given.pkxy.0 = f.nat_to_element(&g.sig_input.issuer_pk.0);
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_issuer_pky",
            expected_path: "signature",
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, f| {
                g.sig_input.issuer_pk.1 = CompileNat::<4>::from_u64(0xdeadbeef);
                g.issuer_sig_given.pkxy.1 = f.nat_to_element(&g.sig_input.issuer_pk.1);
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_issuer_sig_r",
            expected_path: "signature",
            corrupt_input: Some(Box::new(|sig| {
                sig.issuer_sig_r = CompileNat::<4>::from_u64(0xdeadbeef);
            })),
            corrupt_given: None,
        },
        MdocSignatureCorruptor {
            name: "corrupt_issuer_sig_s",
            expected_path: "signature",
            corrupt_input: Some(Box::new(|sig| {
                sig.issuer_sig_s = CompileNat::<4>::from_u64(0xdeadbeef);
            })),
            corrupt_given: None,
        },
        MdocSignatureCorruptor {
            name: "corrupt_device_sig_e",
            expected_path: "signature",
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, f| {
                g.sig_input.device_sig_e = CompileNat::<4>::from_u64(0xdeadbeef);
                g.device_sig_given.e = f.nat_to_element(&g.sig_input.device_sig_e);
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_device_pkx",
            expected_path: "signature",
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, f| {
                g.sig_input.device_pk.0 = CompileNat::<4>::from_u64(0xdeadbeef);
                g.device_sig_given.pkxy.0 = f.nat_to_element(&g.sig_input.device_pk.0);
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_device_pky",
            expected_path: "signature",
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, f| {
                g.sig_input.device_pk.1 = CompileNat::<4>::from_u64(0xdeadbeef);
                g.device_sig_given.pkxy.1 = f.nat_to_element(&g.sig_input.device_pk.1);
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_device_sig_r",
            expected_path: "signature",
            corrupt_input: Some(Box::new(|sig| {
                sig.device_sig_r = CompileNat::<4>::from_u64(0xdeadbeef);
            })),
            corrupt_given: None,
        },
        MdocSignatureCorruptor {
            name: "corrupt_device_sig_s",
            expected_path: "signature",
            corrupt_input: Some(Box::new(|sig| {
                sig.device_sig_s = CompileNat::<4>::from_u64(0xdeadbeef);
            })),
            corrupt_given: None,
        },
        MdocSignatureCorruptor {
            name: "corrupt_mac_e",
            expected_path: "assert_mac",
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, _| {
                g.mac_e[0] ^= 1;
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_mac_device_pkx",
            expected_path: "assert_mac",
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, _| {
                g.mac_device_pkx[0] ^= 1;
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_mac_device_pky",
            expected_path: "assert_mac",
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, _| {
                g.mac_device_pky[0] ^= 1;
            })),
        },
        MdocSignatureCorruptor {
            name: "corrupt_mac_av",
            expected_path: "assert_mac",
            corrupt_input: None,
            corrupt_given: Some(Box::new(|g, _| {
                g.mac_input.mac_av ^= 1;
            })),
        },
    ]
}
