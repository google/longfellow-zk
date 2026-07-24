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

use compile_algebra::gf2_128::Gf2_128Field;
use core_algebra::SerializableField;
use core_proto::circuit::Circuit;
use mdoc_zk_circuits::{
    config::{
        K_HASH_V256_BIT_PLUCKER, K_HASH_V8_BIT_PLUCKER, K_NREQ, K_RATEINV, K_SHA_BIT_PLUCKER,
    },
    hash::circuit::MdocHash,
    MdocHashCompileField,
};

use crate::{allocate_hash::allocate_hash, allocator::WireAllocator};

pub fn mdoc_zk_circuits_hash<FC>(
    fc: &FC,
    num_attrs: usize,
) -> (
    Circuit<FC>,
    core_proto::circuit::CircuitGeometry,
    compile_compiler::debug::CircuitDebugSymbols,
)
where
    FC: MdocHashCompileField,
{
    compile_compiler::compile(fc, |iologic| {
        let bv = circuits_bitvec::BitvecLogic::new(&iologic);
        let bitvec_io = circuits_bitvec::BitvecIO::new(&bv);
        let plucker_v8 =
            circuits_bit_plucker::BitPlucker::<_, { K_HASH_V8_BIT_PLUCKER }>::new(&iologic);
        let plucker_v256 =
            circuits_bit_plucker::BitPlucker::<_, { K_HASH_V256_BIT_PLUCKER }>::new(&iologic);
        let plucker_sha =
            circuits_bit_plucker::BitPlucker::<_, { K_SHA_BIT_PLUCKER }>::new(&iologic);

        let mut allocator =
            WireAllocator::new(&iologic, &bitvec_io, compile_logic::K_FIRST_WIRE_POSITION);

        let (given, derived, pub_inputs_count, subfield_boundary_val) = allocate_hash(
            &mut allocator,
            num_attrs,
            &plucker_v8,
            &plucker_v256,
            &plucker_sha,
        );

        let mdoc = MdocHash::new(&iologic, num_attrs);
        let assertion = mdoc.assert_valid_presentation_and_macs(&given, &derived);
        (assertion, pub_inputs_count, subfield_boundary_val)
    })
}

pub fn generate_hash_circuit(
    f128_compile: &Gf2_128Field,
    num_attrs: usize,
) -> Result<(Circuit<Gf2_128Field>, runtime_ligero::param::LigeroConfig), String> {
    use std::fmt::Write;

    let start = std::time::Instant::now();
    let (hash_circuit_comp, stats, _symbols) = mdoc_zk_circuits_hash(f128_compile, num_attrs);

    let duration = start.elapsed();

    let segmented = compile_compiler::segment_circuit(f128_compile, &hash_circuit_comp);
    let mut hex_id = String::with_capacity(64);
    for b in hash_circuit_comp.id {
        let _ = write!(&mut hex_id, "{b:02x}");
    }

    println!("[Compiler] Hash Circuit (nattrs={num_attrs})");
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

    let (num_witness, num_quadratic_constraints) =
        runtime_proto::witness_and_constraint_count(&segmented);
    let gf2 = runtime_algebra::gf2_128::Gf2_128Field::new();
    let sf_hash =
        runtime_algebra::subfield::BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let make_interpolator =
        runtime_algebra::lch14_reed_solomon::Lch14InterpolatorFactory::new(&gf2, &sf_hash);
    let best_block_enc = runtime_ligero::optimize_geometry(
        num_witness,
        num_quadratic_constraints,
        K_RATEINV,
        K_NREQ,
        f128_compile.serialized_size_bytes(),
        2,
        &make_interpolator,
    );
    let config = runtime_ligero::param::LigeroConfig {
        rateinv: K_RATEINV,
        nreq: K_NREQ,
        block_enc: best_block_enc,
    };
    println!("  Compile time: {duration:?}");
    println!(
        "  Ligero params: rateinv={}, nreq={}, block_enc={}",
        config.rateinv, config.nreq, config.block_enc
    );
    Ok((segmented, config))
}
