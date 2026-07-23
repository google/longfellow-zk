pub mod circuit;
pub mod proto;
pub use circuit::{AnalogDecoder, BinaryDecoder, BitDecoder, UnaryDecoder};
pub use proto::{binary_point, unary_point};
