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

pub mod archive;
pub mod cache;
pub mod circuit;
pub mod layer;
pub mod reader;
pub mod uleb;
pub mod writer;

pub use archive::{ArchiveEntry, CircuitArchive, CircuitArchiveBuilder};
pub use uleb::*;

pub const BYTES_PER_SIZE_T: usize = 3;
pub const MAX_LOGW: usize = 40;

#[inline]
#[must_use]
pub fn sane_logw(logw: usize) -> bool {
    logw <= MAX_LOGW && logw < (usize::BITS as usize)
}

pub use circuit::{CircuitGeometry, FieldID};
pub use core_algebra::SerializableField;
pub use layer::{canonical_term, compare_term, Layer, Term, TermDelta};
