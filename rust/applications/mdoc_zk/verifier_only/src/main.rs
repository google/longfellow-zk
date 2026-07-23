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

use std::hint::black_box;

use mdoc_zk_runtime::{run_mdoc_verifier_inner, RequestedAttribute, CURRENT_ZK_SPECS};

fn main() {
    let spec = black_box(CURRENT_ZK_SPECS[0]);
    let circuits = black_box(&[0u8; 10][..]);
    let pkx = black_box("0x00");
    let pky = black_box("0x00");
    let transcript = black_box(&[0u8; 10][..]);
    let attrs: [RequestedAttribute; 0] = [];
    let now = black_box("2026-07-08");
    let doc_type = black_box("org.iso.18013.5.1.mDL");
    let proof = black_box(&[0u8; 10][..]);

    let _res = black_box(run_mdoc_verifier_inner(
        &spec,
        circuits,
        pkx,
        pky,
        transcript,
        black_box(&attrs[..]),
        now,
        doc_type,
        proof,
    ));
}
