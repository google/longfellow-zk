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

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use runtime_algebra::{gf2_128::Gf2_128RuntimeField, lch14::Lch14, AlgebraicField};

fn bench_lch14(c: &mut Criterion) {
    let gf2 = Gf2_128RuntimeField::new();

    let mut group = c.benchmark_group("LCH14 FFT");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    group.sample_size(10);

    let subfield =
        runtime_algebra::subfield::BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let fft = Lch14::new(&gf2, &subfield);

    for l in [8, 12, 16] {
        let n = 1 << l;
        let b = vec![gf2.one(); n];
        let mut b_fft = b.clone();
        group.bench_with_input(BenchmarkId::new("FFT", l), &l, |bench, _| {
            bench.iter(|| {
                fft.fft(l, 0, &mut b_fft);
            });
        });

        let mut b_ifft = b.clone();
        group.bench_with_input(BenchmarkId::new("IFFT", l), &l, |bench, _| {
            bench.iter(|| {
                fft.ifft(l, 0, &mut b_ifft);
            });
        });

        let mut b_bi = b.clone();
        group.bench_with_input(BenchmarkId::new("BidirectionalFFT", l), &l, |bench, _| {
            bench.iter(|| {
                fft.bidirectional_fft(l, n - 1, &mut b_bi);
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
    targets = bench_lch14
);
criterion_main!(benches);
