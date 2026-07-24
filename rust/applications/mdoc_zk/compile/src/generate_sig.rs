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

use compile_algebra::p256::P256Field;
use core_algebra::SerializableField;
use core_proto::circuit::Circuit;
use mdoc_zk_circuits::{
    config::{K_NREQ, K_RATEINV, K_SIG_MAC_BIT_PLUCKER},
    signature::circuit::MdocSignature,
    MdocSigCompileField,
};
use runtime_algebra::SupportsFFT;

use crate::{allocate_sig::allocate_sig, allocator::WireAllocator};

pub fn mdoc_zk_circuits_signature<FC>(
    fc: &FC,
) -> (
    Circuit<FC>,
    core_proto::circuit::CircuitGeometry,
    compile_compiler::debug::CircuitDebugSymbols,
)
where FC: MdocSigCompileField {
    compile_compiler::compile(fc, |iologic| {
        let bv = circuits_bitvec::BitvecLogic::new(&iologic);
        let bitvec_io = circuits_bitvec::BitvecIO::new(&bv);
        let plucker =
            circuits_bit_plucker::BitPlucker::<_, { K_SIG_MAC_BIT_PLUCKER }>::new(&iologic);

        let mut allocator =
            WireAllocator::new(&iologic, &bitvec_io, compile_logic::K_FIRST_WIRE_POSITION);

        let curve = compile_algebra::secp256r1::Secp256r1::new(fc);
        let (given, derived, pub_inputs_count, subfield_boundary_val) =
            allocate_sig(&mut allocator, &plucker, &curve);

        let mdoc_sig = MdocSignature::new(&iologic, &curve);
        let assertion = mdoc_sig.assert_signatures_and_macs(&given, &derived);
        (assertion, pub_inputs_count, subfield_boundary_val)
    })
}

pub fn generate_sig_circuit(
    p256_compile: &P256Field,
) -> Result<(Circuit<P256Field>, runtime_ligero::param::LigeroConfig), String> {
    use std::fmt::Write;

    let start = std::time::Instant::now();
    let (sig_circuit_comp, stats, _symbols) = mdoc_zk_circuits_signature(p256_compile);

    let duration = start.elapsed();

    let segmented = compile_compiler::segment_circuit(p256_compile, &sig_circuit_comp);
    let (num_witness, num_quadratic_constraints) =
        runtime_proto::witness_and_constraint_count(&segmented);
    let p256 = runtime_algebra::p256::P256Field::new();
    let p256_2 = runtime_algebra::fp2::Fp2Field::new(&p256);
    let make_interpolator = runtime_algebra::reed_solomon::FftInterpolatorFactory::new(
        &p256,
        &p256_2,
        p256_2.omega(),
        p256_2.omega_order(),
    );
    let best_block_enc = runtime_ligero::optimize_geometry(
        num_witness,
        num_quadratic_constraints,
        K_RATEINV,
        K_NREQ,
        p256_compile.serialized_size_bytes(),
        p256_compile.serialized_size_bytes(),
        &make_interpolator,
    );
    let config = runtime_ligero::param::LigeroConfig {
        rateinv: K_RATEINV,
        nreq: K_NREQ,
        block_enc: best_block_enc,
    };

    let mut hex_id = String::with_capacity(64);
    for b in sig_circuit_comp.id {
        let _ = write!(&mut hex_id, "{b:02x}");
    }

    println!("[Compiler] Signature Circuit");
    println!("  Hash (ID): 0x{hex_id}");
    println!(
        "  Geometry: nin={}, npubin={}, nout={}, W={}, T={}, L={}, assertions={}",
        stats.ninput,
        stats.npublic_input,
        stats.noutput,
        stats.nwires,
        stats.nterms,
        stats.nlayers,
        stats.nassertions
    );
    println!("  Compile time: {duration:?}");
    println!(
        "  Ligero params: rateinv={}, nreq={}, block_enc={}",
        config.rateinv, config.nreq, config.block_enc
    );

    Ok((segmented, config))
}
