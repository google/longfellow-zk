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

use runtime_algebra::field::RuntimeField;

#[inline(always)]
pub fn affine_interpolation<const W: usize, F: RuntimeField<W>>(
    r: &F::E,
    f0: &F::E,
    f1: &F::E,
    f: &F,
) -> F::E {
    let diff = f.subf(f1, f0);
    let mut res = f0.clone();
    f.fma(&mut res, &diff, r);
    res
}

#[inline(always)]
pub fn affine_interpolation_z_nz<const W: usize, F: RuntimeField<W>>(
    r: &F::E,
    f1: &F::E,
    f: &F,
) -> F::E {
    f.mulf(f1, r)
}

#[inline(always)]
pub fn affine_interpolation_nz_z<const W: usize, F: RuntimeField<W>>(
    r: &F::E,
    f0: &F::E,
    f: &F,
) -> F::E {
    let p = f.mulf(f0, r);
    f.subf(f0, &p)
}

/// For a given random number r, the binding operation computes
///   v[i] = (1 - r) * v[2 * i] + r * v[2 * i + 1]
///        = v[2 * i] + r * (v[2 * i + 1] - v[2 * i])
/// This method works in-place and truncates the vector.
pub fn bind<const W: usize, F: RuntimeField<W>>(v: &mut Vec<F::E>, r: &F::E, f: &F) {
    assert!(!v.is_empty(), "vector length must be >= 1 in bind");
    let in_n = v.len();
    let half = in_n / 2;

    let ptr = v.as_mut_ptr();
    for i in 0..half {
        unsafe {
            let v0 = &*ptr.add(2 * i);
            let v1 = &*ptr.add(2 * i + 1);
            let res = affine_interpolation(r, v0, v1, f);
            *ptr.add(i) = res;
        }
    }

    if in_n % 2 != 0 {
        let vn = &v[in_n - 1];
        v[half] = affine_interpolation_nz_z(r, vn, f);
        v.truncate(half + 1);
    } else {
        v.truncate(half);
    }
}

pub fn bind_out_of_place<const W: usize, F: RuntimeField<W>>(
    v: &[F::E],
    r: &F::E,
    f: &F,
) -> Vec<F::E> {
    assert!(
        !v.is_empty(),
        "vector length must be >= 1 in bind_out_of_place"
    );
    let in_n = v.len();
    let half = in_n / 2;
    let mut out = Vec::with_capacity(in_n.div_ceil(2));
    for chunk in v[..2 * half].chunks_exact(2) {
        out.push(affine_interpolation(r, &chunk[0], &chunk[1], f));
    }
    if in_n % 2 != 0 {
        out.push(affine_interpolation_nz_z(r, &v[in_n - 1], f));
    }
    out
}

pub fn bind_all<const W: usize, F: RuntimeField<W>>(
    logv: usize,
    v: &mut Vec<F::E>,
    r: &[F::E],
    f: &F,
) {
    assert!(!v.is_empty(), "vector length must be >= 1 in bind_all");
    assert!(crate::sane_logw(logv), "logv must be sane");
    assert!(
        v.len() as u64 <= (1u64 << logv),
        "size of wires {} exceeds 2^logw {}",
        v.len(),
        1u64 << logv
    );
    for ri in r.iter().take(logv) {
        bind(v, ri, f);
    }
}

/// Normalizes a dense wire vector by ensuring it contains at least one element.
///
/// In dense sumcheck, wire vectors are conceptually padded with zeros up to a power of 2.
/// If a wire vector is completely empty (size 0), this function pads it with a single `0` element
/// (size 1). This simplifies implementation across the sumcheck prover and verifier by avoiding
/// empty vector edge cases in downstream folding and binding operations (`bind` / `bind_all`).
#[inline]
pub fn normalize<const W: usize, F: RuntimeField<W>>(v: Vec<F::E>, f: &F) -> Vec<F::E> {
    if v.is_empty() {
        vec![f.zero()]
    } else {
        v
    }
}

/// Extracts the single scalar field element from a fully bound wire vector.
///
/// After folding a wire vector across all rounds of sumcheck, its length must be exactly 1.
/// This function asserts that `v.len() == 1` and returns that final evaluated scalar claim.
#[inline]
pub fn as_scalar<const W: usize, F: RuntimeField<W>>(v: &[F::E]) -> F::E {
    assert_eq!(v.len(), 1, "vector length must be 1");
    v[0].clone()
}
