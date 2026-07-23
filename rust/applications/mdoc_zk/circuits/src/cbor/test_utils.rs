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

use core_algebra::Nat;
pub use mdoc_zk_testcases::TestDataStatic;
use num_bigint::BigUint;

use crate::cbor::mdoc::{parse_mdoc, ParsedMdoc};

#[must_use]
pub fn parse_test_data<const W: usize, N: Nat<W> + Nat<4>>(
    data: &TestDataStatic,
) -> ((N, N), ParsedMdoc<N>, &'static str) {
    let parse_hex_nat = |s: &str| -> N {
        let s_str = s.strip_prefix("0x").unwrap_or(s);
        let val = BigUint::parse_bytes(s_str.as_bytes(), 16).unwrap();
        let mut bytes = val.to_bytes_le();
        bytes.resize(W * 8, 0);
        <N as Nat<W>>::from_bytes_le(&bytes)
    };

    let issuer_pk = (parse_hex_nat(data.pkx), parse_hex_nat(data.pky));
    let parsed = parse_mdoc(data.mdoc, data.transcript, data.doc_type);
    (issuer_pk, parsed, data.now)
}
