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

use runtime_algebra::{blas::*, field::SupportsU64Conversions, p256::P256Field};

#[test]
fn test_blas_subroutines() {
    let f = P256Field::new();

    let a = f.u64_to_element(2);
    let x = vec![
        f.u64_to_element(1),
        f.u64_to_element(2),
        f.u64_to_element(3),
        f.u64_to_element(4),
    ];
    let mut y = vec![
        f.u64_to_element(10),
        f.u64_to_element(20),
        f.u64_to_element(30),
        f.u64_to_element(40),
    ];

    // Test dot product: 1*10 + 2*20 + 3*30 + 4*40 = 300
    let d = dot(&x, &y, &f);
    assert_eq!(d, f.u64_to_element(300));

    // Test dot1: 1 + 2 + 3 + 4 = 10
    let d1 = dot1(&x, &f);
    assert_eq!(d1, f.u64_to_element(10));

    // Test axpy: y = a*x + y
    axpy(&mut y, &a, &x, &f);
    assert_eq!(y[0], f.u64_to_element(12));
    assert_eq!(y[1], f.u64_to_element(24));
    assert_eq!(y[2], f.u64_to_element(36));
    assert_eq!(y[3], f.u64_to_element(48));

    // Test scale: y = a * y
    scale(&mut y, &a, &f);
    assert_eq!(y[0], f.u64_to_element(24));

    // Test equal / equal0
    assert!(equal(&y, &y));
    assert!(!equal0(&y, &f));

    // Test clear
    clear(&mut y, &f);
    assert!(equal0(&y, &f));
}
