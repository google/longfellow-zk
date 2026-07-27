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

use crate::archive::CircuitArchive;

/// Serializes a `CircuitArchive` to LFA1 format (concatenated LFC1 circuit payloads).
/// Asserts that no metadata information is lost.
pub fn to_bytes_lfa1(archive: &CircuitArchive) -> Vec<u8> {
    assert_eq!(
        archive.circuit_version, 0,
        "Cannot serialize to LFA1 format: circuit_version is non-zero ({})",
        archive.circuit_version
    );
    assert!(
        archive.created_at.is_empty(),
        "Cannot serialize to LFA1 format: created_at field is non-empty ('{}')",
        archive.created_at
    );
    assert!(
        archive.author.is_empty(),
        "Cannot serialize to LFA1 format: author field is non-empty ('{}')",
        archive.author
    );
    assert!(
        archive.generator_tool.is_empty(),
        "Cannot serialize to LFA1 format: generator_tool field is non-empty ('{}')",
        archive.generator_tool
    );
    assert!(
        archive.description.is_empty(),
        "Cannot serialize to LFA1 format: description field is non-empty ('{}')",
        archive.description
    );
    assert_eq!(
        archive.entries.len(),
        2,
        "LFA1 format requires exactly 2 circuit entries ('sig' and 'hash'), got {}",
        archive.entries.len()
    );

    let sig_entry = archive
        .get("sig")
        .expect("LFA1 format requires a 'sig' entry");
    let hash_entry = archive
        .get("hash")
        .expect("LFA1 format requires a 'hash' entry");

    let mut bytes = Vec::with_capacity(sig_entry.payload.len() + hash_entry.payload.len());
    bytes.extend_from_slice(&sig_entry.payload);
    bytes.extend_from_slice(&hash_entry.payload);
    bytes
}
