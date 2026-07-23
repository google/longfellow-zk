use criterion::{black_box, criterion_group, criterion_main, Criterion};
use runtime_algebra::{
    field::SupportsU64Conversions, gf2_128::Gf2_128RuntimeField, p256::P256Field, ElementOf,
};
use runtime_sumcheck::dense::bind;

fn bench_dense_bind_p256(c: &mut Criterion) {
    let f = P256Field::new();
    let size = 1 << 18; // 262,144 elements
    let v_init: Vec<ElementOf<P256Field>> = (0..size).map(|i| f.u64_to_element(i as u64)).collect();
    let r = f.u64_to_element(123456789);

    c.bench_function("dense_bind_p256_2e18", |b| {
        b.iter_with_setup(
            || v_init.clone(),
            |mut v| {
                bind(&mut v, &r, &f);
                black_box(v)
            },
        );
    });
}

fn bench_dense_bind_gf2_128(c: &mut Criterion) {
    let f = Gf2_128RuntimeField::new();
    let size = 1 << 18; // 262,144 elements
    use core_algebra::SupportsU128Conversions;
    let v_init: Vec<ElementOf<Gf2_128RuntimeField>> =
        (0..size).map(|i| f.u128_to_element(i as u128)).collect();
    let r = f.u128_to_element(0x123456789abcdef0);

    c.bench_function("dense_bind_gf2_128_2e18", |b| {
        b.iter_with_setup(
            || v_init.clone(),
            |mut v| {
                bind(&mut v, &r, &f);
                black_box(v)
            },
        );
    });
}

criterion_group!(benches, bench_dense_bind_p256, bench_dense_bind_gf2_128);
criterion_main!(benches);
