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

use std::io::BufRead;

use crate::archive::{compute_combined_id, ArchiveEntry, CircuitArchive, LFA_VERSION};

/// Reads an LFA1 archive from a stream (concatenated "sig" and "hash" LFC1 circuits starting with
/// version/field byte 1).
pub fn from_stream_lfa1<R: BufRead>(stream: &mut R) -> Result<CircuitArchive, String> {
    let p256 = compile_algebra::p256::P256Field::new();
    let gf2 = compile_algebra::gf2_128::Gf2_128Field::new();

    let mut raw_bytes = Vec::new();
    stream
        .read_to_end(&mut raw_bytes)
        .map_err(|e| format!("Failed to read LFA1 stream: {e}"))?;

    if raw_bytes.is_empty() || raw_bytes[0] != 1 {
        return Err(format!(
            "Invalid LFA1 header: expected first byte to be 1 (LFC1), got {:?}",
            raw_bytes.first()
        ));
    }

    let cursor1 = &raw_bytes[..];
    let reader_sig = crate::reader::CircuitReader::new(&p256, crate::FieldID::P256);
    let (c_sig, remaining1) = reader_sig.from_bytes(cursor1, false)?;

    let sig_len = raw_bytes.len() - remaining1.len();
    let payload_sig = raw_bytes[..sig_len].to_vec();

    let cursor2 = remaining1;
    let reader_hash = crate::reader::CircuitReader::new(&gf2, crate::FieldID::Gf2_128);
    let (c_hash, remaining2) = reader_hash.from_bytes(cursor2, false)?;

    let hash_len = cursor2.len() - remaining2.len();
    let payload_hash = cursor2[..hash_len].to_vec();

    let entry_sig = ArchiveEntry {
        name: "sig".to_string(),
        circuit_id: c_sig.id,
        payload: payload_sig,
    };

    let entry_hash = ArchiveEntry {
        name: "hash".to_string(),
        circuit_id: c_hash.id,
        payload: payload_hash,
    };

    let entries = vec![entry_sig, entry_hash];
    let combined_id = compute_combined_id(&entries);

    Ok(CircuitArchive {
        version: LFA_VERSION,
        circuit_version: 0,
        combined_id,
        created_at: String::new(),
        author: String::new(),
        generator_tool: String::new(),
        description: String::new(),
        entries,
    })
}
