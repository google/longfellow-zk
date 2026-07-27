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

use crate::{archive::CircuitArchive, uleb::serialize_uleb128};

pub const LFA2_MAGIC: &[u8; 4] = b"LFA2";

/// Serializes a `CircuitArchive` to LFA2 format (with metadata header and circuit_version).
pub fn to_bytes_lfa2(archive: &CircuitArchive) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(LFA2_MAGIC);
    bytes.push(archive.version);
    serialize_uleb128(&mut bytes, archive.circuit_version as usize);
    bytes.extend_from_slice(&archive.combined_id);

    write_utf8_string(&mut bytes, &archive.created_at);
    write_utf8_string(&mut bytes, &archive.author);
    write_utf8_string(&mut bytes, &archive.generator_tool);
    write_utf8_string(&mut bytes, &archive.description);

    serialize_uleb128(&mut bytes, archive.entries.len());
    for entry in &archive.entries {
        write_utf8_string(&mut bytes, &entry.name);
        bytes.extend_from_slice(&entry.circuit_id);
        serialize_uleb128(&mut bytes, entry.payload.len());
    }

    for entry in &archive.entries {
        bytes.extend_from_slice(&entry.payload);
    }

    bytes
}

fn write_utf8_string(bytes: &mut Vec<u8>, s: &str) {
    let s_bytes = s.as_bytes();
    serialize_uleb128(bytes, s_bytes.len());
    bytes.extend_from_slice(s_bytes);
}
