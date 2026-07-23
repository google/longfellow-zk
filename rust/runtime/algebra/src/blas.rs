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

use crate::field::RuntimeField;

/// SUM_{i} x[i] * y[i]
pub fn dot<const W: usize, F: RuntimeField<W>>(x: &[F::E], y: &[F::E], f: &F) -> F::E {
    assert_eq!(x.len(), y.len(), "dot: slice size mismatch");
    if x.is_empty() {
        return f.zero();
    }

    let mut r = f.zero();
    for (xi, yi) in x.iter().zip(y) {
        f.fma(&mut r, xi, yi);
    }
    r
}

/// SUM_{i} x[i]
pub fn dot1<const W: usize, F: RuntimeField<W>>(x: &[F::E], f: &F) -> F::E {
    if x.is_empty() {
        return f.zero();
    }

    let mut r = f.zero();
    for xi in x {
        f.add(&mut r, xi);
    }
    r
}

/// y = a * y
pub fn scale<const W: usize, F: RuntimeField<W>>(y: &mut [F::E], a: &F::E, f: &F) {
    for yi in y {
        f.mul(yi, a);
    }
}

/// y = a * x + y
pub fn axpy<const W: usize, F: RuntimeField<W>>(y: &mut [F::E], a: &F::E, x: &[F::E], f: &F) {
    assert_eq!(y.len(), x.len(), "axpy: slice size mismatch");
    for (yi, xi) in y.iter_mut().zip(x) {
        f.fma(yi, a, xi);
    }
}

/// y[i] += a[i] * x[i]
pub fn vaxpy<const W: usize, F: RuntimeField<W>>(y: &mut [F::E], a: &[F::E], x: &[F::E], f: &F) {
    assert_eq!(y.len(), a.len(), "vaxpy: slice size mismatch");
    assert_eq!(y.len(), x.len(), "vaxpy: slice size mismatch");

    for (yi, (ai, xi)) in y.iter_mut().zip(a.iter().zip(x)) {
        f.fma(yi, ai, xi);
    }
}

/// y[i] -= a[i] * x[i]
pub fn vymax<const W: usize, F: RuntimeField<W>>(y: &mut [F::E], a: &[F::E], x: &[F::E], f: &F) {
    assert_eq!(y.len(), a.len(), "vymax: slice size mismatch");
    assert_eq!(y.len(), x.len(), "vymax: slice size mismatch");

    for (yi, (ai, xi)) in y.iter_mut().zip(a.iter().zip(x)) {
        f.fnms(yi, ai, xi);
    }
}

/// Checks element-wise equality of two slices
pub fn equal<T: PartialEq>(x: &[T], y: &[T]) -> bool {
    assert_eq!(x.len(), y.len(), "equal: slice size mismatch");
    for i in 0..x.len() {
        if x[i] != y[i] {
            return false;
        }
    }
    true
}

/// Checks if all elements of a slice are zero
pub fn equal0<const W: usize, F: RuntimeField<W>>(x: &[F::E], f: &F) -> bool {
    for xi in x {
        if !f.is_zero(xi) {
            return false;
        }
    }
    true
}

/// Returns a Vec containing src[idx[i]] for all idx elements
pub fn gather<T: Clone>(idx: &[usize], src: &[T]) -> Vec<T> {
    let mut dst = Vec::with_capacity(idx.len());
    for &src_idx in idx {
        assert!(src_idx < src.len(), "src index out of bounds");
        dst.push(src[src_idx].clone());
    }
    dst
}

/// dst[i] = 0
pub fn clear<const W: usize, F: RuntimeField<W>>(dst: &mut [F::E], f: &F) {
    for dsti in dst {
        *dsti = f.zero();
    }
}

/// y[i] += x[i]
pub fn add<const W: usize, F: RuntimeField<W>>(y: &mut [F::E], x: &[F::E], f: &F) {
    assert_eq!(y.len(), x.len(), "add: slice size mismatch");
    for (yi, xi) in y.iter_mut().zip(x) {
        f.add(yi, xi);
    }
}

/// y[i] -= x[i]
pub fn sub<const W: usize, F: RuntimeField<W>>(y: &mut [F::E], x: &[F::E], f: &F) {
    assert_eq!(y.len(), x.len(), "sub: slice size mismatch");
    for (yi, xi) in y.iter_mut().zip(x) {
        f.sub(yi, xi);
    }
}

/// y[i] *= x[i]
pub fn mul<const W: usize, F: RuntimeField<W>>(y: &mut [F::E], x: &[F::E], f: &F) {
    assert_eq!(y.len(), x.len(), "mul: slice size mismatch");
    for (yi, xi) in y.iter_mut().zip(x) {
        f.mul(yi, xi);
    }
}

/// y[i] += c
pub fn add_const<const W: usize, F: RuntimeField<W>>(y: &mut [F::E], c: &F::E, f: &F) {
    for yi in y {
        f.add(yi, c);
    }
}

/// y[i] = a * y[i] + b * x[i]
pub fn axpby<const W: usize, F: RuntimeField<W>>(
    y: &mut [F::E],
    a: &F::E,
    x: &[F::E],
    b: &F::E,
    f: &F,
) {
    assert_eq!(y.len(), x.len(), "axpby: slice size mismatch");
    for (yi, xi) in y.iter_mut().zip(x) {
        let mut t = f.mulf(b, xi);
        f.fma(&mut t, a, yi);
        *yi = t;
    }
}

/// `dst.clone_from_slice(src)`
pub fn copy<T: Clone>(dst: &mut [T], src: &[T]) {
    assert_eq!(dst.len(), src.len(), "copy: slice size mismatch");
    dst.clone_from_slice(src);
}
