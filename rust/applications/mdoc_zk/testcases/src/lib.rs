#[derive(Clone, Debug)]
pub struct TestDataStatic {
    pub pkx: &'static str,
    pub pky: &'static str,
    pub transcript: &'static [u8],
    pub now: &'static str,
    pub doc_type: &'static str,
    pub mdoc: &'static [u8],
}

pub mod vectors;
pub use vectors::*;
