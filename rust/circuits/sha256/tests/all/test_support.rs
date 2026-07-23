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

use circuits_sha256::{ConcreteDerived, ConcreteGiven};

#[allow(dead_code)]
pub struct Sha256Corruptor {
    pub name: String,
    pub expected_path: String,
    pub corrupt: Box<dyn Fn(&mut ConcreteGiven, &mut ConcreteDerived)>,
}

impl Sha256Corruptor {
    pub fn expected_compiled_path(&self) -> String {
        self.expected_path
            .replace("assert_wrapping_sum_gf2", "assert_wrapping_sum_prime")
    }
}

pub fn all_sha256_corruptors() -> Vec<Sha256Corruptor> {
    let bitflips = (0..16)
        .flat_map(|word_idx| {
            (0..32).map(move |bit_idx| Sha256Corruptor {
                name: format!("input_block[{word_idx}].bit[{bit_idx}]"),
                expected_path: format!(
                    "sha256/schedule/schedule.{word_idx}/assert_wrapping_sum_gf2"
                ),
                corrupt: Box::new(move |g, _d| {
                    g.input_block[word_idx] ^= 1 << bit_idx;
                }),
            })
        })
        .chain((0..8).flat_map(|word_idx| {
            (0..32).map(move |bit_idx| Sha256Corruptor {
                name: format!("h0[{word_idx}].bit[{bit_idx}]"),
                expected_path: format!("sha256/final/final.{word_idx}/assert_wrapping_sum_gf2"),
                corrupt: Box::new(move |g, _d| {
                    g.h0[word_idx] ^= 1 << bit_idx;
                }),
            })
        }))
        .chain((0..8).flat_map(|word_idx| {
            (0..32).map(move |bit_idx| Sha256Corruptor {
                name: format!("h1[{word_idx}].bit[{bit_idx}]"),
                expected_path: format!("sha256/final/final.{word_idx}/assert_wrapping_sum_gf2"),
                corrupt: Box::new(move |_g, d| {
                    d.h1[word_idx] ^= 1 << bit_idx;
                }),
            })
        }));

    let explicit = vec![
        Sha256Corruptor {
            name: "outw[0]".into(),
            expected_path: "sha256/schedule/schedule.16/assert_wrapping_sum_gf2".into(),
            corrupt: Box::new(|_g, d| {
                d.outw[0] ^= 1;
            }),
        },
        Sha256Corruptor {
            name: "oute[0]".into(),
            expected_path: "sha256/rounds/rounds.0/round_step/assert_wrapping_sum_gf2".into(),
            corrupt: Box::new(|_g, d| {
                d.oute[0] ^= 1;
            }),
        },
        Sha256Corruptor {
            name: "outa[0]".into(),
            expected_path: "sha256/rounds/rounds.0/round_step/assert_wrapping_sum_gf2".into(),
            corrupt: Box::new(|_g, d| {
                d.outa[0] ^= 1;
            }),
        },
    ];

    bitflips.chain(explicit).collect()
}
