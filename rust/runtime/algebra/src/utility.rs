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

pub(crate) struct AlgebraUtil;

impl AlgebraUtil {
    pub(crate) fn batch_inverse_arithmetic<const W: usize, F: RuntimeField<W>>(
        n: usize,
        a: &mut [F::E],
        f: &F,
    ) {
        a[0] = f.zero();

        let mut p = f.one();
        let mut bi = f.zero();
        let one = f.one();

        for item in a.iter_mut().take(n).skip(1) {
            f.add(&mut bi, &one);
            *item = p.clone();
            f.mul(&mut p, &bi);
        }

        p = f.invert(&p);

        for item in a.iter_mut().take(n).skip(1).rev() {
            f.mul(item, &p);
            f.mul(&mut p, &bi);
            f.sub(&mut bi, &one);
        }
    }
}
