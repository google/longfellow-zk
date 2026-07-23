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

use core_proto::writer::CircuitWriter;
use mdoc_zk_runtime::proto::decompress_circuits;

fn main() {
    let p256 = runtime_algebra::p256::P256Field::new();
    let gf2 = runtime_algebra::gf2_128::Gf2_128Field::new();
    let circuits_dir = format!("{}/../artifacts/circuits", env!("CARGO_MANIFEST_DIR"));

    for hash in mdoc_zk_artifacts::all_circuit_hashes() {
        let path_unversioned = format!("{circuits_dir}/{hash}");
        let bytes_in = std::fs::read(&path_unversioned).unwrap_or_else(|_| {
            let path_lfa1 = format!("{circuits_dir}/{hash}.lfa1");
            std::fs::read(&path_lfa1)
                .unwrap_or_else(|e| panic!("Failed to read circuit archive file {path_lfa1}: {e}"))
        });

        let (c_sig, c_hash) = decompress_circuits(&bytes_in, &p256, &gf2).expect("decompress");

        let old_sig_deltas = count_unique_deltas(&c_sig.raw.layers);
        let old_hash_deltas = count_unique_deltas(&c_hash.raw.layers);

        let writer_sig = CircuitWriter::new(&p256, core_proto::FieldID::P256);
        let sig_lfc1_bytes = writer_sig.to_bytes_lfc1(&c_sig);
        let compressed_sig = compile_compiler::segment_circuit(&p256, &c_sig);
        let sig_lfc2_bytes = writer_sig.to_bytes_lfc2(&compressed_sig);

        let writer_hash = CircuitWriter::new(&gf2, core_proto::FieldID::Gf2_128);
        let hash_lfc1_bytes = writer_hash.to_bytes_lfc1(&c_hash);
        let compressed_hash = compile_compiler::segment_circuit(&gf2, &c_hash);
        let hash_lfc2_bytes = writer_hash.to_bytes_lfc2(&compressed_hash);

        let new_sig_deltas = count_unique_deltas(&compressed_sig.raw.layers);
        let new_hash_deltas = count_unique_deltas(&compressed_hash.raw.layers);

        let mut builder1 = core_proto::archive::CircuitArchiveBuilder::new();
        builder1.set_created_at("");
        builder1.set_author("");
        builder1.set_generator_tool("");
        builder1.set_description("");
        builder1.add_entry("sig", c_sig.id, sig_lfc1_bytes.clone());
        builder1.add_entry("hash", c_hash.id, hash_lfc1_bytes.clone());
        let archive1 = builder1.build();
        let uncompressed_lfa1 = archive1.to_bytes_lfa1();
        let bytes_lfa1 = zstd::encode_all(
            &uncompressed_lfa1[..],
            mdoc_zk_circuits::config::K_ZSTD_LEVEL,
        )
        .expect("compress lfa1");
        std::fs::write(format!("{circuits_dir}/{hash}.lfa1"), &bytes_lfa1).expect("write .lfa1");

        let version = mdoc_zk_runtime::zk_spec::find_zk_spec_by_hex("longfellow-libzk-v1", hash)
            .map(|s| s.version as u32)
            .unwrap_or(0);

        let mut builder2 = core_proto::archive::CircuitArchiveBuilder::new();
        builder2.set_circuit_version(version);
        builder2.set_created_at("2026-07-15T00:00:00Z");
        builder2.set_author("Google LLC");
        builder2.set_generator_tool("rzkl-compiler v0.1.0");
        builder2.set_description("mdoc ZK Circuit Archive");
        builder2.add_entry("sig", compressed_sig.id, sig_lfc2_bytes.clone());
        builder2.add_entry("hash", compressed_hash.id, hash_lfc2_bytes.clone());
        let archive2 = builder2.build();
        let uncompressed_lfa2 = archive2.to_bytes_lfa2();
        let bytes_lfa2 = zstd::encode_all(
            &uncompressed_lfa2[..],
            mdoc_zk_circuits::config::K_ZSTD_LEVEL,
        )
        .expect("compress lfa2");
        std::fs::write(format!("{circuits_dir}/{hash}.lfa2"), &bytes_lfa2).expect("write .lfa2");

        println!(
            "Circuit archive {}: lfa1 (no zstd)={} bytes, zstd={} bytes | lfa2 (no zstd)={} bytes, zstd={} bytes (sig deltas: {} -> {}, hash deltas: {} -> {})",
            hash,
            uncompressed_lfa1.len(),
            bytes_lfa1.len(),
            uncompressed_lfa2.len(),
            bytes_lfa2.len(),
            old_sig_deltas,
            new_sig_deltas,
            old_hash_deltas,
            new_hash_deltas
        );
    }
}

fn count_unique_deltas<F: core_proto::SerializableField>(layers: &[core_proto::Layer<F>]) -> usize {
    let mut unique = std::collections::HashSet::new();
    for l in layers {
        l.for_each_delta(|&d| {
            unique.insert(d);
        });
    }
    unique.len()
}
