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

pub(crate) mod builder;
pub(crate) mod legacy;
pub(crate) mod modern;

use core_algebra::Nat;
use legacy::{push_legacy_input_hash, push_legacy_input_sig};
use mdoc_zk_circuits::cbor::mdoc::ParsedMdoc;
use modern::{push_modern_input_hash, push_modern_input_sig};
use runtime_algebra::{
    gf2_128::{Gf2_128, Gf2_128Field},
    p256::{P256Element, P256Field},
    secp256r1::Secp256r1,
};

use crate::{attribute::RequestedAttribute, error::MdocProverErrorCode};

pub fn push_witness_hash<N: Nat<4>>(
    version: usize,
    gf2: &Gf2_128Field,
    attrs: &[RequestedAttribute],
    parsed: &ParsedMdoc<N>,
    mac_ap: &[[u128; 2]; 3],
) -> Result<Vec<Gf2_128>, MdocProverErrorCode> {
    if version >= 8 {
        modern::push_witness_hash(gf2, attrs, parsed, mac_ap)
    } else {
        legacy::push_witness_hash(gf2, version, attrs, parsed, mac_ap)
    }
}

pub fn push_witness_sig(
    version: usize,
    p256: &P256Field,
    q256: &runtime_algebra::Q256Field,
    secp256r1: &Secp256r1<P256Field>,
    issuer_pk: &(P256Element, P256Element),
    parsed: &ParsedMdoc<runtime_algebra::RuntimeNat<4>>,
    mac_ap: &[[u128; 2]; 3],
) -> Result<Vec<P256Element>, MdocProverErrorCode> {
    if version >= 8 {
        modern::push_witness_sig(p256, q256, secp256r1, issuer_pk, parsed, mac_ap)
            .map_err(|_| MdocProverErrorCode::GeneralFailure)
    } else {
        Ok(legacy::push_witness_sig(
            p256, q256, secp256r1, issuer_pk, parsed, mac_ap,
        ))
    }
}

#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn push_input_hash(
    version: usize,
    gf2: &Gf2_128Field,
    attrs: &[RequestedAttribute],
    now_bytes: &[u8],
    macs: &[u128; 6],
    av: u128,
    suppress_doc_type_check: bool,
    expected_doc_type: &[u8],
) -> Vec<Gf2_128> {
    if version >= 8 {
        push_modern_input_hash(
            gf2,
            attrs,
            now_bytes,
            macs,
            av,
            suppress_doc_type_check,
            expected_doc_type,
        )
    } else {
        push_legacy_input_hash(gf2, version, attrs, now_bytes, macs, av)
    }
}

pub fn push_input_sig<N: Nat<4>>(
    version: usize,
    p256: &P256Field,
    issuer_pk: &(P256Element, P256Element),
    device_sig_digest: &N,
    macs: &[u128; 6],
    av: u128,
) -> Vec<P256Element> {
    if version >= 8 {
        push_modern_input_sig(p256, issuer_pk.0, issuer_pk.1, device_sig_digest, macs, av)
    } else {
        push_legacy_input_sig(p256, issuer_pk.0, issuer_pk.1, device_sig_digest, macs, av)
    }
}
