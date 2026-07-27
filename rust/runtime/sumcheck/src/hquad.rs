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

use runtime_algebra::RuntimeField;

use crate::dense::{affine_interpolation, affine_interpolation_nz_z, affine_interpolation_z_nz};

/// two "hand" variables
#[derive(Clone, Copy)]
pub struct HCorner {
    pub h: [u32; 2],
}

/// Representation of the quad after `bind_g`, in which case g = 0
/// and we don't need to store it.
///
/// Ideally we would write
///   struct hcorner {
///     `quad_corner_t` h[2];
///     Elt v;
///   };
/// However, Elt may be 128-bit aligned, causing holes in the struct.
/// Thus we store an array of H and an array of V.
pub struct HQuad<const W: usize, F: RuntimeField<W>> {
    pub hc: Vec<HCorner>,
    pub vc: Vec<F::E>,
}

impl<const W: usize, F: RuntimeField<W> + core_algebra::SerializableField> HQuad<W, F> {
    #[allow(clippy::too_many_arguments)]
    pub fn bind_g(
        layer: &core_proto::circuit::Layer<F>,
        constants: &[F::E],
        logv: usize,
        nv: usize,
        g0: &[F::E],
        g1: &[F::E],
        alpha: &F::E,
        beta: &F::E,
        f: &F,
    ) -> Self {
        let cap = layer.nterms_after_bind_g();
        let mut hc: Vec<HCorner> = Vec::with_capacity(cap);
        let mut vc: Vec<F::E> = Vec::with_capacity(cap);
        assert!(crate::sane_logw(logv), "logv must be sane");
        let dot = crate::eq::eq2(logv, nv, g0, g1, alpha, f);
        let mut prev_h0 = !0u32;
        let mut prev_h1 = !0u32;
        layer.for_each_term(
            constants,
            #[inline(always)]
            |term| {
                let dot_val = dot
                    .get(term.g as usize)
                    .expect("term.g out of bounds for dot");
                let vcc = if f.is_zero(&term.k) {
                    f.mulf(beta, dot_val)
                } else {
                    f.mulf(&term.k, dot_val)
                };
                if term.h0 == prev_h0 && term.h1 == prev_h1 {
                    if let Some(last) = vc.last_mut() {
                        f.add(last, &vcc);
                    }
                } else {
                    hc.push(HCorner {
                        h: [term.h0, term.h1],
                    });
                    vc.push(vcc);
                    prev_h0 = term.h0;
                    prev_h1 = term.h1;
                }
            },
        );
        Self { hc, vc }
    }

    pub fn bind_h(&mut self, r: &F::E, hand: usize, f: &F) {
        let n = self.hc.len();
        assert_eq!(self.vc.len(), n, "hc and vc must have equal length");
        let ohand = 1 - hand;
        let mut rd = 0;
        let mut wr = 0;
        let hc_slice = &mut self.hc[..n];
        let vc_slice = &mut self.vc[..n];

        while rd < n {
            let hc_rd = &hc_slice[rd];
            let mut hcc = HCorner { h: [0, 0] };
            hcc.h[hand] = hc_rd.h[hand] >> 1;
            hcc.h[ohand] = hc_rd.h[ohand];

            let vcc;
            let rd1 = rd + 1;
            if rd1 < n
                && hc_rd.h[ohand] == hc_slice[rd1].h[ohand]
                && (hc_rd.h[hand] >> 1) == (hc_slice[rd1].h[hand] >> 1)
                && hc_slice[rd1].h[hand] == hc_rd.h[hand] + 1
            {
                // we have two corners.
                vcc = affine_interpolation(r, &vc_slice[rd], &vc_slice[rd1], f);
                rd += 2;
            } else {
                // we have one corner and the other one is zero.
                if (hc_rd.h[hand] & 1) == 0 {
                    vcc = affine_interpolation_nz_z(r, &vc_slice[rd], f);
                } else {
                    vcc = affine_interpolation_z_nz(r, &vc_slice[rd], f);
                }
                rd = rd1;
            }

            hc_slice[wr] = hcc;
            vc_slice[wr] = vcc;
            wr += 1;
        }

        self.hc.truncate(wr);
        self.vc.truncate(wr);
    }

    #[must_use]
    pub fn scalar(&self) -> F::E {
        assert_eq!(self.hc.len(), 1, "HQuad size must be 1");
        assert_eq!(self.hc[0].h[0], 0, "HQuad index h0 must be 0");
        assert_eq!(self.hc[0].h[1], 0, "HQuad index h1 must be 0");
        assert_eq!(self.vc.len(), 1, "HQuad vc length must be 1");
        self.vc[0].clone()
    }
}
