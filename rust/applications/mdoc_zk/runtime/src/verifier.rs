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

use core_algebra::Nat;
use runtime_algebra::{
    gf2_128::Gf2_128Field, lch14_reed_solomon::Lch14InterpolatorFactory, p256::P256Field,
    reed_solomon::FftInterpolatorFactory, SupportsFFT,
};
use runtime_random::{transcript::Transcript, RandomEngine};
use runtime_zk::ZkVerifier;

use crate::{
    push_input_hash, push_input_sig,
    utils::{circuit_supports, parse_pk_coordinate, same_namespace},
    MdocProof, MdocProofGeometry, MdocVerifierErrorCode, RequestedAttribute, ZkSpecStruct,
};

#[allow(clippy::too_many_arguments)]
pub fn run_mdoc_verifier(
    zk_spec: &ZkSpecStruct,
    circuits_compressed: &[u8],
    pkx: &str,
    pky: &str,
    transcript: &[u8],
    attrs: &[RequestedAttribute],
    now: &str,
    doc_type: &str,
    proof_bytes: &[u8],
) -> Result<(), MdocVerifierErrorCode> {
    run_mdoc_verifier_inner(
        zk_spec,
        circuits_compressed,
        pkx,
        pky,
        transcript,
        attrs,
        now,
        doc_type,
        proof_bytes,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn run_mdoc_verifier_inner(
    zk_spec: &ZkSpecStruct,
    circuits_compressed: &[u8],
    pkx: &str,
    pky: &str,
    transcript: &[u8],
    attrs: &[RequestedAttribute],
    now: &str,
    doc_type: &str,
    proof_bytes: &[u8],
) -> Result<(), MdocVerifierErrorCode> {
    let version = zk_spec.version;
    let (config_hash, config_sig) = crate::ligero_configs(zk_spec);
    if !crate::is_supported_version(version) {
        return Err(MdocVerifierErrorCode::InvalidZkSpecVersion);
    }
    if !same_namespace(attrs) {
        return Err(MdocVerifierErrorCode::AttributeNumberMismatch);
    }
    if version >= 8 {
        for a in attrs {
            if !circuit_supports(&a.cbor_value) {
                return Err(MdocVerifierErrorCode::UnsupportedAttribute);
            }
        }
    } else {
        // For prior versions (version < 8), doc_type and namespace checks are not supported by the
        // circuit to save constraints. Instead, the external verifier computes the ISO
        // 18013-5 standard DeviceAuthentication / COSE_Sign1 transcript hash (which
        // incorporates `doc_type` and the session transcript) and feeds the resulting
        // digest (`e2_val`) as a public input into the signature verification circuit. In
        // current circuits (version >= 8), doc_type and namespaces are supported by the
        // circuit directly as public inputs: in addition to checking the transcript
        // hash, the circuit asserts that the doc_type is the one stored in the document.
    }

    let p256 = P256Field::new();
    let p256_2 = runtime_algebra::fp2::Fp2Field::new(&p256);
    let omega = p256_2.omega();
    let omega_order = p256_2.omega_order();
    let make_interpolator_sig = FftInterpolatorFactory::new(&p256, &p256_2, omega, omega_order);

    let gf2 = Gf2_128Field::new();
    let sf_hash =
        runtime_algebra::subfield::BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let make_interpolator_hash = Lch14InterpolatorFactory::new(&gf2, &sf_hash);

    let (c_sig, c_hash) = crate::proto::decompress_circuits(circuits_compressed, &p256, &gf2)
        .map_err(|_| MdocVerifierErrorCode::CircuitParsingFailure)?;

    let verifier_hash = ZkVerifier::<2, _>::new(c_hash, config_hash);
    let geom_hash = verifier_hash.geometry(&runtime_zk::common::ZkContext {
        f: &gf2,
        make_interpolator: &make_interpolator_hash,
    });

    let verifier_sig = ZkVerifier::<4, _>::new(c_sig, config_sig);
    let geom_sig = verifier_sig.geometry(&runtime_zk::common::ZkContext {
        f: &p256,
        make_interpolator: &make_interpolator_sig,
    });

    let geom = MdocProofGeometry {
        geom_hash,
        geom_sig,
    };

    let sf_sig = runtime_algebra::p256::P256Subfield::new(&p256);
    let (remaining, proof) = MdocProof::read(proof_bytes, &geom, &gf2, &sf_hash, &p256, &sf_sig)
        .map_err(|_| MdocVerifierErrorCode::HashParsingFailure)?;

    if !remaining.is_empty() {
        return Err(MdocVerifierErrorCode::GeneralFailure);
    }

    let mut tp = Transcript::new(transcript);

    verifier_hash.recv_commitment(
        &proof.proof_hash,
        &mut tp,
        &runtime_zk::common::ZkContext {
            f: &gf2,
            make_interpolator: &make_interpolator_hash,
        },
    );
    verifier_sig.recv_commitment(
        &proof.proof_sig,
        &mut tp,
        &runtime_zk::common::ZkContext {
            f: &p256,
            make_interpolator: &make_interpolator_sig,
        },
    );

    let av_buf = tp.bytes(16);
    let av_val = u128::from_le_bytes(av_buf.try_into().unwrap());

    let pub_inputs_hash = push_input_hash(
        version,
        &gf2,
        attrs,
        now.as_bytes(),
        &proof.macs,
        av_val,
        false,
        doc_type.as_bytes(),
    );

    if pub_inputs_hash.len() != verifier_hash.circuit.raw.npublic_input {
        return Err(MdocVerifierErrorCode::AttributeNumberMismatch);
    }

    verifier_hash
        .verify(
            pub_inputs_hash,
            &proof.proof_hash,
            &mut tp,
            &runtime_zk::common::ZkContext {
                f: &gf2,
                make_interpolator: &make_interpolator_hash,
            },
        )
        .map_err(|_| MdocVerifierErrorCode::GeneralFailure)?;

    let pk_x_elt =
        parse_pk_coordinate(pkx, &p256).map_err(|_| MdocVerifierErrorCode::InvalidInput)?;
    let pk_y_elt =
        parse_pk_coordinate(pky, &p256).map_err(|_| MdocVerifierErrorCode::InvalidInput)?;

    let digest = mdoc_zk_circuits::cbor::mdoc::compute_transcript_hash(transcript, doc_type);
    let e2_val = runtime_algebra::RuntimeNat::<4>::from_bytes_be(&digest);

    let pub_inputs_sig = push_input_sig(
        version,
        &p256,
        &(pk_x_elt, pk_y_elt),
        &e2_val,
        &proof.macs,
        av_val,
    );

    if pub_inputs_sig.len() != verifier_sig.circuit.raw.npublic_input {
        return Err(MdocVerifierErrorCode::AttributeNumberMismatch);
    }

    verifier_sig
        .verify(
            pub_inputs_sig,
            &proof.proof_sig,
            &mut tp,
            &runtime_zk::common::ZkContext {
                f: &p256,
                make_interpolator: &make_interpolator_sig,
            },
        )
        .map_err(|_| MdocVerifierErrorCode::GeneralFailure)?;

    Ok(())
}
