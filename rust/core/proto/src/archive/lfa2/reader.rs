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

use crate::{
    archive::{compute_combined_id, read_utf8_string, ArchiveEntry, CircuitArchive, LFA_VERSION},
    uleb::read_uleb128,
};

/// Reads the body of an LFA2 archive stream after magic bytes have been consumed.
pub fn from_stream_lfa2_body<R: BufRead>(stream: &mut R) -> Result<CircuitArchive, String> {
    let mut ver_buf = [0u8; 1];
    stream
        .read_exact(&mut ver_buf)
        .map_err(|_| "Incomplete header: missing version byte".to_string())?;
    let version = ver_buf[0];
    if version != LFA_VERSION {
        return Err(format!(
            "Unsupported archive version: expected {LFA_VERSION}, got {version}"
        ));
    }

    let circuit_version = read_uleb128(stream)? as u32;

    let mut combined_id = [0u8; 32];
    stream
        .read_exact(&mut combined_id)
        .map_err(|_| "Incomplete header: missing combined_id".to_string())?;

    let created_at = read_utf8_string(stream, 4096, "created_at")?;
    let author = read_utf8_string(stream, 4096, "author")?;
    let generator_tool = read_utf8_string(stream, 4096, "generator_tool")?;
    let description = read_utf8_string(stream, 65536, "description")?;

    let num_entries = read_uleb128(stream)?;
    if num_entries > 10_000 {
        return Err(format!("Excessive circuit count in archive: {num_entries}"));
    }

    let mut metadata = Vec::with_capacity(num_entries);
    for _ in 0..num_entries {
        let name = read_utf8_string(stream, 4096, "entry name")?;
        let mut circuit_id = [0u8; 32];
        stream
            .read_exact(&mut circuit_id)
            .map_err(|_| "Incomplete entry circuit_id".to_string())?;

        let payload_len = read_uleb128(stream)?;
        metadata.push((name, circuit_id, payload_len));
    }

    let mut entries = Vec::with_capacity(num_entries);
    for (name, circuit_id, payload_len) in metadata {
        let mut payload = vec![0u8; payload_len];
        stream
            .read_exact(&mut payload)
            .map_err(|_| format!("Incomplete payload for entry '{name}'"))?;
        entries.push(ArchiveEntry {
            name,
            circuit_id,
            payload,
        });
    }

    let expected_combined_id = compute_combined_id(&entries);
    if combined_id != expected_combined_id {
        return Err(format!(
            "Combined archive ID mismatch: expected {expected_combined_id:?}, got {combined_id:?}"
        ));
    }

    Ok(CircuitArchive {
        version,
        circuit_version,
        combined_id,
        created_at,
        author,
        generator_tool,
        description,
        entries,
    })
}
