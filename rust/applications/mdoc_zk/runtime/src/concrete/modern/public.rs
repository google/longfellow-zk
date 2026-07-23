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

use core_algebra::{AlgebraicField, Nat, SupportsU64Conversions};
use runtime_algebra::{
    gf2_128::{Gf2_128, Gf2_128Field},
    p256::{P256Element, P256Field},
};

use crate::{
    attribute::RequestedAttribute, concrete::builder::AssignmentBuilder, config::K_ATTR_LEN_BITS,
};

fn push_modern_input_attrs(
    builder: &mut AssignmentBuilder<'_, Gf2_128Field>,
    attrs: &[RequestedAttribute],
) {
    for la in attrs {
        let cbor_id = mdoc_zk_circuits::cbor::encode_cbor_string(&la.id);
        for i in 0..32 {
            builder.push_v8(*cbor_id.get(i).unwrap_or(&0));
        }
        builder.push_bits_len(cbor_id.len() as u64, K_ATTR_LEN_BITS);

        for i in 0..64 {
            builder.push_v8(*la.cbor_value.get(i).unwrap_or(&0));
        }
        builder.push_bits_len(la.cbor_value.len() as u64, K_ATTR_LEN_BITS);
    }
}

pub fn push_modern_input_hash(
    gf2: &Gf2_128Field,
    attrs: &[RequestedAttribute],
    now_bytes: &[u8],
    macs: &[u128; 6],
    av: u128,
    suppress_doc_type_check: bool,
    expected_doc_type: &[u8],
) -> Vec<Gf2_128> {
    let mut builder = AssignmentBuilder::new(gf2);
    builder.push_elt(&gf2.one());
    for i in 0..20 {
        builder.push_v8(*now_bytes.get(i).unwrap_or(&0));
    }

    push_modern_input_attrs(&mut builder, attrs);

    for &m in macs {
        builder.push_u128(m);
    }
    builder.push_u128(av);

    let suppress_val = if suppress_doc_type_check {
        gf2.one()
    } else {
        gf2.zero()
    };
    builder.push_elt(&suppress_val);
    for i in 0..32 {
        builder.push_v8(*expected_doc_type.get(i).unwrap_or(&0));
    }
    builder.push_bits_len(expected_doc_type.len() as u64, K_ATTR_LEN_BITS);

    builder.into_inner()
}

pub fn push_modern_input_sig<N: Nat<4>>(
    p256: &P256Field,
    pk_x_elt: P256Element,
    pk_y_elt: P256Element,
    device_sig_e: &N,
    macs: &[u128; 6],
    av: u128,
) -> Vec<P256Element> {
    let mut builder = AssignmentBuilder::new(p256);
    builder.push_elt(&p256.u64_to_element(1));
    builder.push_elt(&pk_x_elt);
    builder.push_elt(&pk_y_elt);

    builder.push_nat_256_bits(device_sig_e);

    for &m in macs {
        builder.push_plucked_128(m);
    }
    builder.push_plucked_128(av);
    builder.into_inner()
}
