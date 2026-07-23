pub mod allocate;
pub mod circuit;
pub use allocate::allocate_given;
pub use circuit::{Given, MAC};
#[cfg(feature = "testonly")]
pub mod evaluate;
#[cfg(feature = "testonly")]
pub use evaluate::evaluate_given;
pub mod concrete;
pub use concrete::{compute_tag, given, ConcreteGiven};
