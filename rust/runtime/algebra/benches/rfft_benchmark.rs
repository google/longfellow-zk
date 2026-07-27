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
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use runtime_algebra::{fp2::Fp2Field, p256::P256Field, SupportsFFT};

fn bench_rfft(c: &mut Criterion) {
    let p256 = P256Field::new();
    let fp2: Fp2Field<'_, 4, _> = Fp2Field::new(&p256);

    let mut group = c.benchmark_group("RFFT Forward");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    group.sample_size(10);
    let omega = fp2.omega();
    let omega_order = fp2.omega_order();

    for n in [256, 1024, 8192, 65536] {
        let mut ar = vec![p256.zero(); n];
        for (i, ar_val) in ar.iter_mut().enumerate().take(n) {
            *ar_val = p256.u64_to_element((i * 12345 + 6789) as u64);
        }
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |bench, _| {
            bench.iter(|| {
                let mut ar_mut = ar.clone();
                runtime_algebra::rfft::r2hc(&mut ar_mut, &omega, omega_order, &fp2);
                ar_mut
            });
        });
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(std::time::Duration::from_millis(100))
        .warm_up_time(std::time::Duration::from_millis(100))
        .sample_size(10);
    targets = bench_rfft
);
criterion_main!(benches);
