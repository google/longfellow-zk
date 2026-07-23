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

pub mod lfa1;
pub mod lfa2;

use std::io::BufRead;

pub use lfa2::LFA2_MAGIC;
use sha2::{Digest, Sha256};

pub const LFA_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub name: String,
    pub circuit_id: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitArchive {
    pub version: u8,
    pub circuit_version: u32,
    pub combined_id: [u8; 32],
    pub created_at: String,
    pub author: String,
    pub generator_tool: String,
    pub description: String,
    pub entries: Vec<ArchiveEntry>,
}

#[derive(Clone, Debug, Default)]
pub struct CircuitArchiveBuilder {
    circuit_version: Option<u32>,
    created_at: Option<String>,
    author: Option<String>,
    generator_tool: Option<String>,
    description: Option<String>,
    entries: Vec<ArchiveEntry>,
}

impl CircuitArchiveBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_circuit_version(&mut self, circuit_version: u32) -> &mut Self {
        self.circuit_version = Some(circuit_version);
        self
    }

    pub fn set_created_at(&mut self, created_at: impl Into<String>) -> &mut Self {
        self.created_at = Some(created_at.into());
        self
    }

    pub fn set_author(&mut self, author: impl Into<String>) -> &mut Self {
        self.author = Some(author.into());
        self
    }

    pub fn set_generator_tool(&mut self, tool: impl Into<String>) -> &mut Self {
        self.generator_tool = Some(tool.into());
        self
    }

    pub fn set_description(&mut self, description: impl Into<String>) -> &mut Self {
        self.description = Some(description.into());
        self
    }

    pub fn add_entry(
        &mut self,
        name: impl Into<String>,
        circuit_id: [u8; 32],
        payload: Vec<u8>,
    ) -> &mut Self {
        self.entries.push(ArchiveEntry {
            name: name.into(),
            circuit_id,
            payload,
        });
        self
    }

    #[must_use]
    pub fn build(self) -> CircuitArchive {
        let combined_id = compute_combined_id(&self.entries);
        let circuit_version = self.circuit_version.unwrap_or(0);
        let created_at = self
            .created_at
            .unwrap_or_else(|| "2026-07-15T00:00:00Z".to_string());
        let author = self.author.unwrap_or_else(|| "Google LLC".to_string());
        let generator_tool = self
            .generator_tool
            .unwrap_or_else(|| "rzkl-compiler v0.1.0".to_string());
        let description = self.description.unwrap_or_default();

        CircuitArchive {
            version: LFA_VERSION,
            circuit_version,
            combined_id,
            created_at,
            author,
            generator_tool,
            description,
            entries: self.entries,
        }
    }
}

pub fn compute_combined_id(entries: &[ArchiveEntry]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for entry in entries {
        hasher.update(entry.circuit_id);
    }
    hasher.finalize().into()
}

impl CircuitArchive {
    #[must_use]
    pub fn builder() -> CircuitArchiveBuilder {
        CircuitArchiveBuilder::new()
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ArchiveEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Default serialization to LFA2 format.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_lfa2()
    }

    /// Serializes to LFA2 format (with metadata fields).
    #[must_use]
    pub fn to_bytes_lfa2(&self) -> Vec<u8> {
        lfa2::writer::to_bytes_lfa2(self)
    }

    /// Serializes to LFA1 format (legacy minimal format without header metadata).
    /// Asserts that no metadata information is lost.
    #[must_use]
    pub fn to_bytes_lfa1(&self) -> Vec<u8> {
        lfa1::writer::to_bytes_lfa1(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut cursor = bytes;
        Self::from_stream(&mut cursor)
    }

    pub fn from_stream<R: BufRead>(stream: &mut R) -> Result<Self, String> {
        let buf = stream
            .fill_buf()
            .map_err(|e| format!("Incomplete header: missing bytes: {e}"))?;

        if buf.starts_with(LFA2_MAGIC) {
            stream.consume(4);
            lfa2::reader::from_stream_lfa2_body(stream)
        } else if !buf.is_empty() && buf[0] == 1 {
            lfa1::reader::from_stream_lfa1(stream)
        } else {
            Err(format!(
                "Unsupported archive header: expected b\"LFA2\" magic or 0x01 (LFA1), got {:?}",
                buf.get(..4)
            ))
        }
    }
}

pub(crate) fn read_utf8_string<R: BufRead>(
    stream: &mut R,
    max_len: usize,
    field_name: &str,
) -> Result<String, String> {
    let len = crate::uleb::read_uleb128(stream)?;
    if len > max_len {
        return Err(format!(
            "Excessive {field_name} string length: {len} > {max_len}"
        ));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|_| format!("Incomplete {field_name} string"))?;
    String::from_utf8(buf).map_err(|e| format!("Invalid UTF-8 in {field_name}: {e}"))
}
