use util::morton::{cmp, even, uneven};

#[test]
fn test_even_uneven_roundtrip() {
    for val in 0..10000u64 {
        let ev = even(val);
        let unev = uneven(ev);
        assert_eq!(unev, val & 0x5555_5555_5555_5555);
    }
}

#[test]
fn test_morton_cmp() {
    // Test cases comparing against coordinate-wise interleaved bits.
    let check_cmp = |x0: usize, x1: usize, y0: usize, y1: usize| -> std::cmp::Ordering {
        let encode = |h0: usize, h1: usize| -> u128 {
            let mut code = 0u128;
            for i in 0..64 {
                code |= (((h0 >> i) & 1) as u128) << (2 * i);
                code |= (((h1 >> i) & 1) as u128) << (2 * i + 1);
            }
            code
        };
        encode(x0, x1).cmp(&encode(y0, y1))
    };

    // 1. Exhaustive small grid check
    for x0 in 0..30 {
        for x1 in 0..30 {
            for y0 in 0..30 {
                for y1 in 0..30 {
                    assert_eq!(cmp(x0, x1, y0, y1), check_cmp(x0, x1, y0, y1));
                }
            }
        }
    }

    // 2. Large random fuzzing check (1,000,000 iterations)
    let mut rng_state = 0x1234_5678_9abc_deff_u64;
    let mut next_rand = || {
        rng_state = rng_state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        rng_state
    };

    for _ in 0..1_000_000 {
        let x0 = next_rand() as usize;
        let x1 = next_rand() as usize;
        let y0 = next_rand() as usize;
        let y1 = next_rand() as usize;
        assert_eq!(cmp(x0, x1, y0, y1), check_cmp(x0, x1, y0, y1));
    }
}
