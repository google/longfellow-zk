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

pub mod allocate_hash;
pub mod allocate_sig;
pub mod allocator;
pub mod generate_hash;
pub mod generate_sig;

pub use allocate_hash::*;
pub use allocate_sig::*;
pub use allocator::*;
use compile_algebra::{gf2_128::Gf2_128Field, p256::P256Field};
use compile_compiler::CompilerArena;
pub use generate_hash::*;
pub use generate_sig::*;

pub fn compile_circuits(
    num_attrs: usize,
) -> Result<
    (
        Vec<u8>,
        runtime_ligero::param::LigeroConfig,
        runtime_ligero::param::LigeroConfig,
    ),
    String,
> {
    let f128_compile = Gf2_128Field::new();
    let p256_compile = P256Field::new();
    let arena_128 = CompilerArena::new();
    let arena_256 = CompilerArena::new();
    let (seg_sig, config_sig) = generate_sig_circuit(&arena_256, &p256_compile)?;
    let (seg_hash, config_hash) = generate_hash_circuit(&arena_128, &f128_compile, num_attrs)?;

    let writer_sig =
        core_proto::writer::CircuitWriter::new(&p256_compile, core_proto::FieldID::P256);
    let sig_bytes = writer_sig.to_bytes_lfc2(&seg_sig);

    let writer_hash =
        core_proto::writer::CircuitWriter::new(&f128_compile, core_proto::FieldID::Gf2_128);
    let hash_bytes = writer_hash.to_bytes_lfc2(&seg_hash);

    let mut builder = core_proto::archive::CircuitArchiveBuilder::new();
    builder.set_circuit_version(mdoc_zk_circuits::CURRENT_VERSION as u32);
    builder.add_entry("sig", seg_sig.id, sig_bytes);
    builder.add_entry("hash", seg_hash.id, hash_bytes);

    let archive = builder.build();
    Ok((archive.to_bytes(), config_sig, config_hash))
}

pub use compile_circuits as generate_circuits;

pub fn compile_all_circuits() -> Vec<
    Result<
        (
            Vec<u8>,
            runtime_ligero::param::LigeroConfig,
            runtime_ligero::param::LigeroConfig,
        ),
        String,
    >,
> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::scope(|s| {
        for num_attrs in 1..=4 {
            let tx = tx.clone();
            s.spawn(move || {
                let res = compile_circuits(num_attrs);
                tx.send((num_attrs, res)).unwrap();
            });
        }
    });
    drop(tx);

    let mut results = vec![Err(String::new()); 4];
    for (num_attrs, res) in rx {
        results[num_attrs - 1] = res;
    }
    results
}

pub use compile_all_circuits as generate_all_circuits;
