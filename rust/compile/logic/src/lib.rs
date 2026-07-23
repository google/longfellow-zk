#[cfg(feature = "testonly")]
pub mod concrete;
#[cfg(feature = "testonly")]
pub mod eval;
pub mod logic;
#[cfg(feature = "testonly")]
pub use concrete::*;

#[cfg(feature = "testonly")]
pub use crate::eval::EvalError;
pub use crate::logic::{Eltw, Logic, LogicIO, K_FIRST_WIRE_POSITION};
