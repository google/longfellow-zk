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

use runtime_algebra::{
    convolution::{choose_padding, Convolver, FFTConvolution, FFTExtConvolution},
    field::RuntimeField,
    fp2::{Fp2Element, Fp2Field},
    p256::P256Field,
    AlgebraicField,
};

fn get_test_field_and_omega(
    p256: &P256Field,
) -> (Fp2Field<'_, 4, 8, P256Field>, Fp2Element<4, P256Field>, u64) {
    let f: Fp2Field<'_, 4, 8, _> = Fp2Field::new(p256);
    let re_bytes = [
        98, 37, 36, 75, 50, 101, 90, 152, 76, 74, 42, 56, 59, 86, 201, 159, 55, 227, 144, 121, 198,
        133, 252, 92, 102, 245, 132, 189, 142, 51, 13, 249,
    ];
    let im_bytes = [
        172, 62, 164, 96, 79, 23, 244, 219, 198, 50, 210, 116, 100, 138, 115, 132, 64, 227, 6, 1,
        226, 194, 79, 160, 77, 204, 151, 188, 66, 30, 232, 185,
    ];
    use core_algebra::SerializableField;
    let omega = Fp2Element {
        re: p256.bytes_to_element(&re_bytes).unwrap(),
        im: p256.bytes_to_element(&im_bytes).unwrap(),
    };
    (f, omega, 1 << 31)
}

struct SimplePrg {
    state: u64,
}

impl SimplePrg {
    fn new() -> Self {
        Self { state: 42 }
    }
    fn next<const W: usize, F: RuntimeField<W> + core_algebra::SupportsU64Conversions>(
        &mut self,
        f: &F,
    ) -> F::E {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        f.u64_to_element(self.state)
    }
}

#[test]
fn test_convolution_fft() {
    let p256 = P256Field::new();
    let (f, omega, omega_order) = get_test_field_and_omega(&p256);

    let n = 15;
    let m = 20;

    let mut prg = SimplePrg::new();
    let mut x = Vec::with_capacity(n);
    let mut y = Vec::with_capacity(m);
    for _ in 0..n {
        x.push(prg.next(&f));
    }
    for _ in 0..m {
        y.push(prg.next(&f));
    }

    // Slow reference convolution
    let mut expected = vec![f.zero(); m];
    for k in 0..m {
        let mut s = f.zero();
        for i in 0..n {
            if k >= i && (k - i) < m {
                let term = f.mulf(&x[i], &y[k - i]);
                s = f.addf(&s, &term);
            }
        }
        expected[k] = s;
    }

    // FFTConvolution
    let padding = choose_padding(n + m - 1);
    let mut y_padded = vec![f.zero(); padding];
    y_padded[..m].clone_from_slice(&y);

    let convolver = FFTConvolution::<8, _>::new(n, padding, &omega, omega_order, &y_padded, &f);
    let mut got = vec![f.zero(); padding];
    convolver.convolution(&x, &mut got);

    assert_eq!(&got[..m], &expected[..m]);
}

#[test]
fn test_convolution_ext() {
    let p256 = P256Field::new();
    let fp2: Fp2Field<'_, 4, 8, _> = Fp2Field::new(&p256);

    let re_bytes = [
        98, 37, 36, 75, 50, 101, 90, 152, 76, 74, 42, 56, 59, 86, 201, 159, 55, 227, 144, 121, 198,
        133, 252, 92, 102, 245, 132, 189, 142, 51, 13, 249,
    ];
    let im_bytes = [
        172, 62, 164, 96, 79, 23, 244, 219, 198, 50, 210, 116, 100, 138, 115, 132, 64, 227, 6, 1,
        226, 194, 79, 160, 77, 204, 151, 188, 66, 30, 232, 185,
    ];

    use core_algebra::SerializableField;
    let omega = Fp2Element {
        re: p256.bytes_to_element(&re_bytes).unwrap(),
        im: p256.bytes_to_element(&im_bytes).unwrap(),
    };
    let omega_order = 1u64 << 31;

    let n = 15;
    let m = 20;

    let mut prg = SimplePrg::new();
    let mut x = Vec::with_capacity(n);
    let mut y = Vec::with_capacity(m);
    for _ in 0..n {
        x.push(prg.next(&p256));
    }
    for _ in 0..m {
        y.push(prg.next(&p256));
    }

    // Slow reference convolution
    let mut expected = vec![p256.zero(); m];
    for k in 0..m {
        let mut s = p256.zero();
        for i in 0..n {
            if k >= i && (k - i) < m {
                let term = p256.mulf(&x[i], &y[k - i]);
                s = p256.addf(&s, &term);
            }
        }
        expected[k] = s;
    }

    // FFTExtConvolution
    let padding = choose_padding(n + m - 1);
    let mut y_padded = vec![p256.zero(); padding];
    y_padded[..m].clone_from_slice(&y);

    let convolver =
        FFTExtConvolution::<4, 8, _>::new(n, padding, &omega, omega_order, &y_padded, &p256, &fp2);
    let mut got = vec![p256.zero(); padding];
    convolver.convolution(&x, &mut got);

    assert_eq!(&got[..m], &expected[..m]);
}
