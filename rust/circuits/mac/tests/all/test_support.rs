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

use circuits_mac::concrete::ConcreteGiven;

#[allow(dead_code)]
pub struct MacCorruptor {
    pub name: &'static str,
    pub expected_path: &'static str,
    pub corrupt: Box<dyn Fn(&mut ConcreteGiven)>,
}

pub fn all_mac_corruptors() -> Vec<MacCorruptor> {
    (0..32)
        .flat_map(|byte_idx| {
            (0..8).map(move |bit_idx| {
                let path = if byte_idx < 16 {
                    "assert_mac/msg0_eq"
                } else {
                    "assert_mac/msg1_eq"
                };
                MacCorruptor {
                    name: "message_bitflip",
                    expected_path: path,
                    corrupt: Box::new(move |g| {
                        g.message[byte_idx] ^= 1 << bit_idx;
                    }),
                }
            })
        })
        .chain((0..128).map(|bit_idx| MacCorruptor {
            name: "mac_av_bitflip",
            expected_path: "assert_mac",
            corrupt: Box::new(move |g| {
                g.mac_av ^= 1 << bit_idx;
            }),
        }))
        .chain((0..2).flat_map(|idx| {
            let path = if idx == 0 {
                "assert_mac/msg0_eq"
            } else {
                "assert_mac/msg1_eq"
            };
            (0..128).map(move |bit_idx| MacCorruptor {
                name: "mac_ap_bitflip",
                expected_path: path,
                corrupt: Box::new(move |g| {
                    g.mac_ap[idx] ^= 1 << bit_idx;
                }),
            })
        }))
        .chain((0..2).flat_map(|idx| {
            let path = if idx == 0 {
                "assert_mac/msg0_eq"
            } else {
                "assert_mac/msg1_eq"
            };
            (0..128).map(move |bit_idx| MacCorruptor {
                name: "tag_bitflip",
                expected_path: path,
                corrupt: Box::new(move |g| {
                    g.tag[idx] ^= 1 << bit_idx;
                }),
            })
        }))
        .collect()
}
