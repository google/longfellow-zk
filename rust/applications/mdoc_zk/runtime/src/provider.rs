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

use crate::{
    error::MdocProverErrorCode,
    zk_spec::{ZkSpecStruct, CURRENT_VERSION, CURRENT_ZK_SPECS, ZK_SPECS},
};

#[derive(Clone, Debug)]
pub struct ProvidedCircuit {
    pub name: String,
    pub spec: ZkSpecStruct,
    pub archive: core_proto::archive::CircuitArchive,
    pub compressed: Vec<u8>,
}

pub fn materialize(
    version: usize,
    num_attributes: usize,
) -> Result<ProvidedCircuit, MdocProverErrorCode> {
    match version.cmp(&CURRENT_VERSION) {
        std::cmp::Ordering::Less => {
            let spec = ZK_SPECS
                .iter()
                .find(|s| s.version == version && s.num_attributes == num_attributes)
                .ok_or(MdocProverErrorCode::InvalidZkSpecVersion)?;
            let hash_hex = spec.combined_hash_hex();
            let compressed = mdoc_zk_artifacts::load_circuit_lfa2(&hash_hex);
            let zstd_decoder = zstd::stream::read::Decoder::new(&compressed[..])
                .map_err(|_| MdocProverErrorCode::CircuitParsingFailure)?;
            let mut buf_stream = std::io::BufReader::new(zstd_decoder);
            let archive = core_proto::archive::CircuitArchive::from_stream(&mut buf_stream)
                .map_err(|_| MdocProverErrorCode::CircuitParsingFailure)?;

            Ok(ProvidedCircuit {
                name: hash_hex,
                spec: *spec,
                archive,
                compressed,
            })
        }
        std::cmp::Ordering::Equal => {
            let spec = CURRENT_ZK_SPECS
                .iter()
                .find(|s| s.num_attributes == num_attributes)
                .ok_or(MdocProverErrorCode::InvalidZkSpecVersion)?;

            let (lfa_bytes, _config_sig, _config_hash) =
                mdoc_zk_compile::generate_circuits(num_attributes)
                    .map_err(|_| MdocProverErrorCode::GeneralFailure)?;

            let archive = core_proto::archive::CircuitArchive::from_bytes(&lfa_bytes)
                .map_err(|_| MdocProverErrorCode::CircuitParsingFailure)?;

            let compressed =
                zstd::encode_all(&lfa_bytes[..], mdoc_zk_circuits::config::K_ZSTD_LEVEL)
                    .map_err(|_| MdocProverErrorCode::GeneralFailure)?;

            let name = spec.combined_hash_hex();
            Ok(ProvidedCircuit {
                name,
                spec: *spec,
                archive,
                compressed,
            })
        }
        std::cmp::Ordering::Greater => Err(MdocProverErrorCode::InvalidZkSpecVersion),
    }
}

#[must_use]
pub fn all_prior_versions_and_attrs() -> Vec<(usize, usize)> {
    let mut pairs = Vec::new();
    for version in 5..CURRENT_VERSION {
        for num_attributes in 1..=4 {
            pairs.push((version, num_attributes));
        }
    }
    pairs
}
