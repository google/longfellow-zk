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

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::Ordering,
};

use compile_algebra::CompileNat;
use core_algebra::Nat;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mdoc_zk_circuits::parse_test_data;
use mdoc_zk_runtime::{
    decompress_circuits, req_attr, run_mdoc_prover_inner, run_mdoc_verifier_inner,
    RequestedAttribute,
};
use runtime_algebra::{
    fp2::Fp2Field,
    lch14_reed_solomon::Lch14InterpolatorFactory,
    mem::{ALLOCATED, PEAK},
    reed_solomon::FftInterpolatorFactory,
    SupportsFFT,
};

struct TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let size = layout.size();
            let prev = ALLOCATED.fetch_add(size, Ordering::SeqCst);
            let current = prev + size;
            loop {
                let current_peak = PEAK.load(Ordering::SeqCst);
                if current <= current_peak {
                    break;
                }
                if PEAK
                    .compare_exchange_weak(
                        current_peak,
                        current,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    )
                    .is_ok()
                {
                    break;
                }
            }
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        ALLOCATED.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static ALLOC: TrackingAllocator = TrackingAllocator;

fn reset_peak() {
    let current = ALLOCATED.load(Ordering::SeqCst);
    PEAK.store(current, Ordering::SeqCst);
}

fn get_peak_allocated() -> usize {
    PEAK.load(Ordering::SeqCst)
}

fn get_current_allocated() -> usize {
    ALLOCATED.load(Ordering::SeqCst)
}

fn hex_id(id: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for byte in id {
        write!(&mut s, "{byte:02x}").unwrap();
    }
    s
}

fn bench_mdoc_zk_flow(c: &mut Criterion) {
    let (issuer_pk, parsed, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);
    let req_attrs: Vec<RequestedAttribute> = parsed
        .attrs
        .iter()
        .take(1)
        .map(|a| req_attr("org.iso.18013.5.1", &a.name, &a.cbor_value))
        .collect();

    let mdoc_bytes = mdoc_zk_testcases::vectors::TEST_DATA.mdoc;
    let transcript = mdoc_zk_testcases::vectors::TEST_DATA.transcript;
    let doc_type = "org.iso.18013.5.1.mDL";

    let pubkey_x_string = format!(
        "0x{}",
        num_bigint::BigUint::from_bytes_le(&issuer_pk.0.to_bytes_le()).to_str_radix(16)
    );
    let pubkey_y_formatted = format!(
        "0x{}",
        num_bigint::BigUint::from_bytes_le(&issuer_pk.1.to_bytes_le()).to_str_radix(16)
    );

    let provided = mdoc_zk_runtime::provider::materialize(7, req_attrs.len()).unwrap();
    let spec = &provided.spec;
    let hash_hex = spec.combined_hash_hex();
    let circuits_v1 = mdoc_zk_artifacts::load_circuit_v1(&hash_hex);
    let (config_hash, config_sig) = mdoc_zk_runtime::ligero_configs(spec);

    let gf2_runtime = runtime_algebra::gf2_128::Gf2_128RuntimeField::new();
    let p256_runtime = runtime_algebra::p256::P256Field::new();
    let subfield =
        runtime_algebra::subfield::BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let make_interpolator_hash = Lch14InterpolatorFactory::new(&gf2_runtime, &subfield);
    let p256_2 = Fp2Field::new(&p256_runtime);
    let omega = p256_2.omega();
    let omega_order = p256_2.omega_order();
    let make_interpolator_sig =
        FftInterpolatorFactory::new(&p256_runtime, &p256_2, omega, omega_order);

    {
        let (c_sig, c_hash) =
            decompress_circuits(&circuits_v1, &p256_runtime, &gf2_runtime).unwrap();

        println!("--------------------------------------------------");
        println!("Circuit Stats (v7 Official Circuit):");
        let mut decompressed = Vec::new();
        zstd::stream::copy_decode(std::io::Cursor::new(&circuits_v1), &mut decompressed)
            .expect("decompress");
        println!(
            "  Circuit Sizes: zstd-{}={} bytes, segmented (no zstd)={} bytes",
            mdoc_zk_circuits::config::K_ZSTD_LEVEL,
            circuits_v1.len(),
            decompressed.len()
        );
        println!("  Sig Circuit ID:  {}", hex_id(&c_sig.id));
        println!("  Hash Circuit ID: {}", hex_id(&c_hash.id));
        println!("  Overall Spec Hash: {}", hash_hex);
        println!(
            "  Hash Circuit: inputs={}, pub_inputs={}, outputs={}, layers={}, wires={}, terms={}",
            c_hash.raw.ninput,
            c_hash.raw.npublic_input,
            c_hash.raw.noutput,
            c_hash.raw.layers.len(),
            c_hash
                .raw
                .layers
                .iter()
                .map(core_proto::layer::Layer::nw)
                .sum::<usize>()
                - c_hash.raw.ninput
                + c_hash.raw.noutput,
            c_hash
                .raw
                .layers
                .iter()
                .map(core_proto::layer::Layer::num_terms)
                .sum::<usize>()
        );
        let (count_w_hash, total_q_hash) = runtime_proto::witness_and_constraint_count(&c_hash);
        let param_hash = runtime_ligero::param::LigeroParam::try_new(
            count_w_hash,
            total_q_hash,
            config_hash,
            &make_interpolator_hash,
        )
        .unwrap();
        println!(
            "  Hash Ligero:  block={}, dblock={}, block_enc={}, nrow={}, mc_pathlen={}",
            param_hash.block,
            param_hash.dblock,
            param_hash.block_enc,
            param_hash.geom.nrow,
            param_hash.geom.mc_pathlen
        );
        println!(
            "  Sig Circuit:  inputs={}, pub_inputs={}, outputs={}, layers={}, wires={}, terms={}",
            c_sig.raw.ninput,
            c_sig.raw.npublic_input,
            c_sig.raw.noutput,
            c_sig.raw.layers.len(),
            c_sig
                .raw
                .layers
                .iter()
                .map(core_proto::layer::Layer::nw)
                .sum::<usize>()
                - c_sig.raw.ninput
                + c_sig.raw.noutput,
            c_sig
                .raw
                .layers
                .iter()
                .map(core_proto::layer::Layer::num_terms)
                .sum::<usize>()
        );
        let (count_w_sig, total_q_sig) = runtime_proto::witness_and_constraint_count(&c_sig);
        let param_sig = runtime_ligero::param::LigeroParam::try_new(
            count_w_sig,
            total_q_sig,
            config_sig,
            &make_interpolator_sig,
        )
        .unwrap();
        println!(
            "  Sig Ligero:   block={}, dblock={}, block_enc={}, nrow={}, mc_pathlen={}",
            param_sig.block,
            param_sig.dblock,
            param_sig.block_enc,
            param_sig.geom.nrow,
            param_sig.geom.mc_pathlen
        );
    }
    println!(
        "Compressed circuits (concatenated) size: {} bytes",
        circuits_v1.len()
    );

    // Dry-run prover once to get proof size and heap memory stats
    let baseline = get_current_allocated();
    reset_peak();

    let mut rng_v1 = runtime_random::DeterministicRng::new(42);
    let zkproof_v1 = run_mdoc_prover_inner(
        spec,
        &circuits_v1,
        mdoc_bytes,
        &pubkey_x_string,
        &pubkey_y_formatted,
        transcript,
        &req_attrs,
        now,
        doc_type,
        &mut rng_v1,
    )
    .unwrap();

    let mut baseline_heap = 0;
    let mut baseline_peak_heap = 0;

    let heap = get_current_allocated();
    if heap > baseline {
        baseline_heap = heap - baseline;
    }

    let peak = get_peak_allocated();
    if peak > baseline {
        baseline_peak_heap = peak - baseline;
    }

    let baseline_ver = get_current_allocated();
    reset_peak();
    run_mdoc_verifier_inner(
        spec,
        &circuits_v1,
        &pubkey_x_string,
        &pubkey_y_formatted,
        transcript,
        &req_attrs,
        now,
        doc_type,
        &zkproof_v1,
    )
    .unwrap();
    let mut baseline_heap_ver = 0;
    let mut baseline_peak_heap_ver = 0;
    let heap_ver = get_current_allocated();
    if heap_ver > baseline_ver {
        baseline_heap_ver = heap_ver - baseline_ver;
    }
    let peak_ver = get_peak_allocated();
    if peak_ver > baseline_ver {
        baseline_peak_heap_ver = peak_ver - baseline_ver;
    }

    println!("--------------------------------------------------");
    println!("Baseline Circuit Memory Stats (v1 Serialization Format):");
    println!("  Proof Size: {} bytes", zkproof_v1.len());
    println!("  Prover Net Heap Memory: {baseline_heap} bytes");
    println!("  Prover Peak Heap Memory: {baseline_peak_heap} bytes");
    println!("  Verifier Net Heap Memory: {baseline_heap_ver} bytes");
    println!("  Verifier Peak Heap Memory: {baseline_peak_heap_ver} bytes");
    println!("--------------------------------------------------");

    let circuits_v2 = mdoc_zk_artifacts::load_circuit_v2(&hash_hex);

    let baseline_v2 = get_current_allocated();
    reset_peak();
    let mut rng_v2 = runtime_random::DeterministicRng::new(42);
    let zkproof_v2 = run_mdoc_prover_inner(
        spec,
        &circuits_v2,
        mdoc_bytes,
        &pubkey_x_string,
        &pubkey_y_formatted,
        transcript,
        &req_attrs,
        now,
        doc_type,
        &mut rng_v2,
    )
    .unwrap();
    let mut baseline_heap_v2 = 0;
    let mut baseline_peak_heap_v2 = 0;
    let heap_v2 = get_current_allocated();
    if heap_v2 > baseline_v2 {
        baseline_heap_v2 = heap_v2 - baseline_v2;
    }
    let peak_v2 = get_peak_allocated();
    if peak_v2 > baseline_v2 {
        baseline_peak_heap_v2 = peak_v2 - baseline_v2;
    }

    let baseline_ver_v2 = get_current_allocated();
    reset_peak();
    run_mdoc_verifier_inner(
        spec,
        &circuits_v2,
        &pubkey_x_string,
        &pubkey_y_formatted,
        transcript,
        &req_attrs,
        now,
        doc_type,
        &zkproof_v2,
    )
    .unwrap();
    let mut baseline_heap_ver_v2 = 0;
    let mut baseline_peak_heap_ver_v2 = 0;
    let heap_ver_v2 = get_current_allocated();
    if heap_ver_v2 > baseline_ver_v2 {
        baseline_heap_ver_v2 = heap_ver_v2 - baseline_ver_v2;
    }
    let peak_ver_v2 = get_peak_allocated();
    if peak_ver_v2 > baseline_ver_v2 {
        baseline_peak_heap_ver_v2 = peak_ver_v2 - baseline_ver_v2;
    }

    println!("--------------------------------------------------");
    println!("Baseline Circuit Memory Stats (v2 Serialization Format):");
    println!("  Proof Size: {} bytes", zkproof_v2.len());
    println!("  Prover Net Heap Memory: {baseline_heap_v2} bytes");
    println!("  Prover Peak Heap Memory: {baseline_peak_heap_v2} bytes");
    println!("  Verifier Net Heap Memory: {baseline_heap_ver_v2} bytes");
    println!("  Verifier Peak Heap Memory: {baseline_peak_heap_ver_v2} bytes");
    println!("--------------------------------------------------");

    let mut group = c.benchmark_group("integration_v7");
    group.sample_size(10);
    group.bench_function("prove_mdoc_flow_v7_v1", |b| {
        b.iter(|| {
            let mut rng = runtime_random::DeterministicRng::new(42);
            let zkproof = run_mdoc_prover_inner(
                black_box(spec),
                black_box(&circuits_v1),
                black_box(mdoc_bytes),
                black_box(&pubkey_x_string),
                black_box(&pubkey_y_formatted),
                black_box(transcript),
                black_box(&req_attrs),
                black_box(now),
                black_box(doc_type),
                &mut rng,
            )
            .unwrap();
            black_box(zkproof);
        });
    });
    group.bench_function("verify_mdoc_flow_v7_v1", |b| {
        b.iter(|| {
            let verify_res = run_mdoc_verifier_inner(
                black_box(spec),
                black_box(&circuits_v1),
                black_box(&pubkey_x_string),
                black_box(&pubkey_y_formatted),
                black_box(transcript),
                black_box(&req_attrs),
                black_box(now),
                black_box(doc_type),
                black_box(&zkproof_v1),
            );
            assert!(verify_res.is_ok());
        });
    });
    group.bench_function("prove_mdoc_flow_v7_v2", |b| {
        b.iter(|| {
            let mut rng = runtime_random::DeterministicRng::new(42);
            let zkproof = run_mdoc_prover_inner(
                black_box(spec),
                black_box(&circuits_v2),
                black_box(mdoc_bytes),
                black_box(&pubkey_x_string),
                black_box(&pubkey_y_formatted),
                black_box(transcript),
                black_box(&req_attrs),
                black_box(now),
                black_box(doc_type),
                &mut rng,
            )
            .unwrap();
            black_box(zkproof);
        });
    });
    group.bench_function("verify_mdoc_flow_v7_v2", |b| {
        b.iter(|| {
            let verify_res = run_mdoc_verifier_inner(
                black_box(spec),
                black_box(&circuits_v2),
                black_box(&pubkey_x_string),
                black_box(&pubkey_y_formatted),
                black_box(transcript),
                black_box(&req_attrs),
                black_box(now),
                black_box(doc_type),
                black_box(&zkproof_v2),
            );
            assert!(verify_res.is_ok());
        });
    });
    group.finish();
    print_memory_stats();
}

fn print_memory_stats() {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        println!("Process OS Memory Stats (Peak/HWM):");
        for line in status.lines() {
            if line.starts_with("VmPeak:") || line.starts_with("VmHWM:") {
                println!("  {line}");
            }
        }
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(std::time::Duration::from_millis(100))
        .warm_up_time(std::time::Duration::from_millis(100))
        .sample_size(10);
    targets = bench_mdoc_zk_flow
);
criterion_main!(benches);
