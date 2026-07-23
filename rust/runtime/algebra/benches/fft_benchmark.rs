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

use core_algebra::{AlgebraicField, SerializableField, SupportsU64Conversions};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use num_bigint::BigUint;
use runtime_algebra::{
    fft::fftf,
    fp2::{Fp2Element, Fp2Field},
    p256::P256Field,
};

fn bench_fft(c: &mut Criterion) {
    let p256 = P256Field::new();
    let fp2: Fp2Field<'_, 4, 8, _> = Fp2Field::new(&p256);

    let mut group = c.benchmark_group("FFT Forward");
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));
    group.sample_size(10);

    let re = BigUint::parse_bytes(
        b"112649224146410281873500457609690258373018840430489408729223714171582664680802",
        10,
    )
    .unwrap();
    let im = BigUint::parse_bytes(
        b"84087994358540907695740461427818660560182168997182378749313018254450460212908",
        10,
    )
    .unwrap();
    let from_nat_subfield = |f: &P256Field, n: &BigUint| {
        let mut bytes = n.to_bytes_le();
        bytes.resize(f.serialized_size_bytes(), 0);
        f.bytes_to_element(&bytes).unwrap()
    };
    let omega = Fp2Element {
        re: from_nat_subfield(&p256, &re),
        im: from_nat_subfield(&p256, &im),
    };
    let omega_order = 1usize << 31;

    for n in [256, 1024, 8192, 65536] {
        let mut ar = vec![fp2.zero(); n];
        for (i, ar_val) in ar.iter_mut().enumerate().take(n) {
            *ar_val = fp2.u64_to_element((i * 12345 + 6789) as u64);
        }

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |bench, _| {
            bench.iter(|| {
                let mut ar_mut = ar.clone();
                fftf(&mut ar_mut, &omega, omega_order as u64, &fp2);
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
    targets = bench_fft
);
criterion_main!(benches);
