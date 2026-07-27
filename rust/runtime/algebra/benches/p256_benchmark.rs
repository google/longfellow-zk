// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core_algebra::{AlgebraicField, SupportsU64Conversions};
use criterion::{criterion_group, criterion_main, Criterion};
use runtime_algebra::{
    fp_generic::MontgomeryStrategy,
    limb::Limb,
    p256::{P256Field, P256Strategy},
};

#[no_mangle]
pub extern "C" fn inspect_p256_montgomery_mul(
    a: &mut [Limb; 4 * runtime_algebra::LIMBS_PER_U64],
    b: &[Limb; 4 * runtime_algebra::LIMBS_PER_U64],
    modulo: &[Limb; 4 * runtime_algebra::LIMBS_PER_U64],
    negm: &[Limb; 4 * runtime_algebra::LIMBS_PER_U64],
    m_prime: Limb,
) {
    P256Strategy::montgomery_mul(a, b, modulo, negm, m_prime);
}

fn bench_p256(c: &mut Criterion) {
    let p256 = P256Field::new();

    let mut group = c.benchmark_group("P-256");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    group.sample_size(10);

    let a = p256.u64_to_element(1234567890u64);
    let b = p256.u64_to_element(9876543210u64);

    group.bench_function("add", |bench| {
        bench.iter(|| p256.addf(criterion::black_box(&a), criterion::black_box(&b)));
    });
    group.bench_function("mul", |bench| {
        bench.iter(|| p256.mulf(criterion::black_box(&a), criterion::black_box(&b)));
    });
    group.bench_function("invert", |bench| {
        bench.iter(|| p256.invert(criterion::black_box(&a)));
    });
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(std::time::Duration::from_millis(100))
        .warm_up_time(std::time::Duration::from_millis(100))
        .sample_size(10);
    targets = bench_p256
);
criterion_main!(benches);
