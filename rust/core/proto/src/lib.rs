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
