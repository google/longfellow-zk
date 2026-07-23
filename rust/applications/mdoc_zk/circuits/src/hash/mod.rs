pub mod allocate;
pub mod circuit;
pub mod concrete;
pub use mdoc_zk_proto::hash::constants;
#[cfg(feature = "testonly")]
pub mod evaluate;

pub use allocate::{allocate_derived, allocate_given};
pub use circuit::{AttrDerived, AttrGiven, Derived, Given, MdocHash};
pub use concrete::{
    compute_mac_tags, derived, given, hash_input_of_parsed_mdoc, ConcreteDerived, ConcreteGiven,
    HashInput, HashMac,
};
#[cfg(feature = "testonly")]
pub use evaluate::{evaluate_derived, evaluate_given};
