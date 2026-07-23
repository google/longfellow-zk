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

use crate::{attribute::RequestedAttribute, concrete::builder::AssignmentBuilder};

fn push_legacy_input_attrs(
    builder: &mut AssignmentBuilder<'_, Gf2_128Field>,
    version: usize,
    attrs: &[RequestedAttribute],
) {
    let zero = builder.field.zero();
    for la in attrs {
        if version >= 7 {
            let mut vbuf = Vec::with_capacity(3 + la.id.len());
            mdoc_zk_circuits::cbor::encode_cbor_string_into(&la.id, &mut vbuf);

            builder.push_raw_bytes(&vbuf);
            builder.push_pad(zero, (32 - vbuf.len()) * 8);

            let val_slice = &la.cbor_value;
            builder.push_raw_bytes(val_slice);
            builder.push_pad(zero, (64 - val_slice.len()) * 8);

            builder.push_bits_len((1 + 17 + 1 + la.id.len()) as u64, 8);
            builder.push_bits_len((la.cbor_value.len() + 12 + 1) as u64, 8);
        } else {
            let mut vbuf = Vec::new();
            mdoc_zk_circuits::cbor::encode_cbor_string_into(&la.id, &mut vbuf);
            mdoc_zk_circuits::cbor::encode_cbor_string_into(b"elementValue", &mut vbuf);
            vbuf.extend_from_slice(&la.cbor_value);

            let len = vbuf.len();
            builder.push_raw_bytes(&vbuf);
            builder.push_pad(zero, (96 - len) * 8);
            builder.push_bits_len(len as u64, 8);
        }
    }
}

pub fn push_legacy_input_hash(
    gf2: &Gf2_128Field,
    version: usize,
    attrs: &[RequestedAttribute],
    now_bytes: &[u8],
    macs: &[u128; 6],
    av: u128,
) -> Vec<Gf2_128> {
    let mut builder = AssignmentBuilder::new(gf2);
    builder.push_elt(&gf2.one());
    push_legacy_input_attrs(&mut builder, version, attrs);

    builder.push_raw_bytes(now_bytes);
    builder.push_pad(Gf2_128::from(2u128), (20 - now_bytes.len()) * 8);

    for &m in macs {
        builder.push_u128(m);
    }
    builder.push_u128(av);
    builder.into_inner()
}

pub fn push_legacy_input_sig<N: Nat<4>>(
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

    builder.push_nat_elt(device_sig_e);

    for &m in macs {
        builder.push_bits_len(m as u64, 64);
        builder.push_bits_len((m >> 64) as u64, 64);
    }
    builder.push_bits_len(av as u64, 64);
    builder.push_bits_len((av >> 64) as u64, 64);

    builder.into_inner()
}
