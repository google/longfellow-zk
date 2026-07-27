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

use core_algebra::{AlgebraicField, Nat, SupportsNatConversions, SupportsU64Conversions};
use mdoc_zk_circuits::cbor::mdoc::ParsedMdoc;
use runtime_algebra::{
    field::RuntimeSerializableField,
    gf2_128::{Gf2_128, Gf2_128Field},
    p256::{P256Element, P256Field},
    secp256r1::Secp256r1,
};

use crate::{
    attribute::RequestedAttribute, concrete::builder::AssignmentBuilder, error::MdocProverErrorCode,
};

fn max_shablocks(version: usize) -> usize {
    if version <= 6 {
        35
    } else {
        40
    }
}

fn push_legacy_sha_witness(
    builder: &mut AssignmentBuilder<Gf2_128Field>,
    sha: &circuits_sha256::concrete::ConcreteDerived,
) {
    for val in sha.legacy_elements() {
        builder.push_v32_legacy(val);
    }
}

fn val_header_len(cbor_value: &[u8]) -> usize {
    if cbor_value.is_empty() {
        return 0;
    }
    match cbor_value[0] {
        0xD9 => {
            let inner_header_len =
                if cbor_value.len() > 3 && (cbor_value[3] == 0x78 || cbor_value[3] == 0x58) {
                    2
                } else {
                    1
                };
            3 + inner_header_len
        }
        0x60..=0x77 | 0x40..=0x57 => 1,
        0x78 | 0x58 => 2,
        0x79 | 0x59 => 3,
        _ => 0,
    }
}

pub fn push_witness_hash<N: Nat<4>>(
    gf2: &Gf2_128Field,
    version: usize,
    req_attrs: &[RequestedAttribute],
    parsed: &ParsedMdoc<N>,
    mac_ap: &[[u128; 2]; 3],
) -> Result<Vec<Gf2_128>, MdocProverErrorCode> {
    let mut builder = AssignmentBuilder::new(gf2);

    for nat in [
        &parsed.issuer_sig_digest,
        &parsed.device_pk.0,
        &parsed.device_pk.1,
    ] {
        let bytes = nat.to_bytes_le();
        builder.push_raw_bytes(&bytes);
    }

    let max_mso_blocks = max_shablocks(version);
    let mso_sha_in = circuits_sha256msg::concrete::given(
        &parsed.cbor_mso,
        &circuits_sha256::constants::INITIAL,
        max_mso_blocks,
    )
    .unwrap();
    let mso_sha_witness = circuits_sha256msg::concrete::derived(&mso_sha_in, max_mso_blocks);
    let signed_bytes = &mso_sha_in.padded_preimage;
    let nblocks = mso_sha_in.nblocks;

    builder.push_bits_len(nblocks as u64, 8);
    builder.push_raw_bytes(&signed_bytes[18..max_mso_blocks * 64]);
    for sha in &mso_sha_witness.sha_derived {
        push_legacy_sha_witness(&mut builder, sha);
    }

    builder.push_bits_len(parsed.valid_from_offset_in_mso as u64, 12);
    builder.push_bits_len(parsed.valid_until_offset_in_mso as u64, 12);
    builder.push_bits_len(parsed.device_key_info_offset_in_mso as u64, 12);
    builder.push_bits_len(parsed.value_digests_offset_in_mso as u64, 12);

    push_witness_attrs(gf2, version, req_attrs, parsed, &mut builder)?;
    for pair in mac_ap {
        builder.push_u128(pair[0]);
        builder.push_u128(pair[1]);
    }

    Ok(builder.into_inner())
}

fn push_witness_attrs<N: Nat<4>>(
    _gf2: &Gf2_128Field,
    version: usize,
    req_attrs: &[RequestedAttribute],
    parsed: &ParsedMdoc<N>,
    builder: &mut AssignmentBuilder<Gf2_128Field>,
) -> Result<(), MdocProverErrorCode> {
    for la in req_attrs {
        let pa = parsed
            .get_attribute(&la.id)
            .ok_or(MdocProverErrorCode::AttributeNotFound)?;
        if pa.cbor_issuer_signed_item.len() >= 256 {
            return Err(MdocProverErrorCode::AttributeTooLong);
        }

        let attr_sha_in = circuits_sha256msg::concrete::given(
            &pa.cbor_issuer_signed_item,
            &circuits_sha256::constants::INITIAL,
            2,
        )
        .unwrap();
        let attr_sha_witness = circuits_sha256msg::concrete::derived(&attr_sha_in, 2);
        builder.push_raw_bytes(&attr_sha_in.padded_preimage);
        push_legacy_sha_witness(builder, &attr_sha_witness.sha_derived[0]);
        push_legacy_sha_witness(builder, &attr_sha_witness.sha_derived[1]);

        builder.push_bits_len(pa.mso_digest_offset_in_preimage as u64, 12);

        let loc = &pa.field_locator;
        let slot_ei = (loc.permutation >> 4) & 3;
        let slot_ev = (loc.permutation >> 6) & 3;

        let id_len = la.id.len();
        let val_header_len = val_header_len(&la.cbor_value);
        let val_len = la.cbor_value.len() - val_header_len;

        let (ei_pos, ei_len, ev_pos, ev_len) = if version < 7 {
            (
                loc.slot_position[slot_ei] + 18,
                id_len + val_len + 13,
                loc.slot_position[slot_ev] + 1,
                val_len,
            )
        } else {
            (
                loc.slot_position[slot_ei],
                loc.length[slot_ei],
                loc.slot_position[slot_ev],
                loc.length[slot_ev],
            )
        };

        builder.push_bits_len(ei_pos as u64, 12);
        builder.push_bits_len(ei_len as u64, 12);

        builder.push_bits_len(ev_pos as u64, 12);
        builder.push_bits_len(ev_len as u64, 12);

        if version >= 7 {
            builder.push_bits_len(loc.slot_position[1] as u64, 12);
            builder.push_bits_len(loc.slot_position[2] as u64, 12);
            builder.push_bits_len(loc.slot_position[3] as u64, 12);
            builder.push_bits_len(loc.length[0] as u64, 12);
            builder.push_bits_len(loc.length[1] as u64, 12);
            builder.push_bits_len(loc.length[2] as u64, 12);
            builder.push_bits_len(loc.length[3] as u64, 12);
            builder.push_bits_len(loc.permutation as u64, 8);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_legacy_verify_witness_3(
    builder: &mut AssignmentBuilder<P256Field>,
    q256: &runtime_algebra::Q256Field,
    secp256r1: &Secp256r1<P256Field>,
    pk_x: &P256Element,
    pk_y: &P256Element,
    e: &runtime_algebra::RuntimeNat<4>,
    r: &runtime_algebra::RuntimeNat<4>,
    s: &runtime_algebra::RuntimeNat<4>,
) {
    let p256 = builder.field;
    let ecdsa_given =
        circuits_ecdsa2::concrete::given(secp256r1, &(*pk_x, *pk_y), e, r, s, p256, q256);
    let ecdsa_derived =
        circuits_ecdsa2::concrete::derived(secp256r1, &(*pk_x, *pk_y), e, r, s, p256, q256);

    builder.push_elt(&ecdsa_given.rxy.0);
    builder.push_elt(&ecdsa_given.rxy.1);
    builder.push_elt(&ecdsa_derived.rxinv);
    builder.push_elt(&ecdsa_derived.nmsinv);
    builder.push_elt(&ecdsa_derived.pkxinv);

    builder.push_elt(&ecdsa_derived.slicing.g_pk.0);
    builder.push_elt(&ecdsa_derived.slicing.g_pk.1);
    builder.push_elt(&ecdsa_derived.slicing.g_r.0);
    builder.push_elt(&ecdsa_derived.slicing.g_r.1);
    builder.push_elt(&ecdsa_derived.slicing.pk_r.0);
    builder.push_elt(&ecdsa_derived.slicing.pk_r.1);
    builder.push_elt(&ecdsa_derived.slicing.g_pk_r.0);
    builder.push_elt(&ecdsa_derived.slicing.g_pk_r.1);

    let s_elt = q256.words64_to_element(&s.to_limbs()).unwrap();
    let tms_elt = q256.neg(&s_elt);
    let nms = runtime_algebra::RuntimeNat::<4>::from_limbs(&q256.to_words64(&tms_elt));

    for i in 0..256 {
        let bit_idx = 255 - i;
        let e_bit = usize::from(e.bit(bit_idx));
        let r_bit = usize::from(r.bit(bit_idx));
        let nms_bit = usize::from(nms.bit(bit_idx));
        let b_i = e_bit + 2 * r_bit + 4 * nms_bit;

        let bi_u64 = 2 * b_i as u64;
        let bi_val = if bi_u64 >= 7 {
            p256.u64_to_element(bi_u64 - 7)
        } else {
            p256.neg(&p256.u64_to_element(7 - bi_u64))
        };
        builder.push_elt(&bi_val);

        if i < 255 {
            let pt = &ecdsa_derived.slicing.round[255 - i];
            builder.push_elt(&pt.0);
            builder.push_elt(&pt.1);
            builder.push_elt(&pt.2);
        }
    }
}

pub fn push_witness_sig(
    p256: &P256Field,
    q256: &runtime_algebra::Q256Field,
    secp256r1: &Secp256r1<P256Field>,
    issuer_pk: &(P256Element, P256Element),
    parsed: &ParsedMdoc<runtime_algebra::RuntimeNat<4>>,
    mac_ap: &[[u128; 2]; 3],
) -> Vec<P256Element> {
    let mut builder = AssignmentBuilder::new(p256);

    let issuer_sig_e_elt = p256.reduce_nat(&parsed.issuer_sig_digest);
    let device_pk_elt = (
        p256.reduce_nat(&parsed.device_pk.0),
        p256.reduce_nat(&parsed.device_pk.1),
    );

    builder.push_elt(&issuer_sig_e_elt);
    builder.push_elt(&device_pk_elt.0);
    builder.push_elt(&device_pk_elt.1);

    push_legacy_verify_witness_3(
        &mut builder,
        q256,
        secp256r1,
        &issuer_pk.0,
        &issuer_pk.1,
        &parsed.issuer_sig_digest,
        &parsed.issuer_sig_r,
        &parsed.issuer_sig_s,
    );
    push_legacy_verify_witness_3(
        &mut builder,
        q256,
        secp256r1,
        &device_pk_elt.0,
        &device_pk_elt.1,
        &parsed.device_sig_digest,
        &parsed.device_sig_r,
        &parsed.device_sig_s,
    );

    for (i, nat) in [
        &parsed.issuer_sig_digest,
        &parsed.device_pk.0,
        &parsed.device_pk.1,
    ]
    .iter()
    .enumerate()
    {
        builder.push_plucked_128_legacy(mac_ap[i][0]);
        builder.push_plucked_128_legacy(mac_ap[i][1]);

        let limbs = nat.to_limbs();
        let x0 = u128::from(limbs[1]) << 64 | u128::from(limbs[0]);
        let x1 = u128::from(limbs[3]) << 64 | u128::from(limbs[2]);
        builder.push_plucked_128_legacy(x0);
        builder.push_plucked_128_legacy(x1);
    }

    builder.into_inner()
}
