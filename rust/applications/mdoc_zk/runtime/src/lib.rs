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

pub mod attribute;
pub(crate) mod concrete;
pub mod error;
pub(crate) mod mac;
pub mod proto;
pub mod prover;
pub mod provider;
pub(crate) mod utils;
pub mod verifier;
pub mod zk_spec;

pub use attribute::RequestedAttribute;
pub use concrete::{push_input_hash, push_input_sig, push_witness_hash, push_witness_sig};
pub use error::{MdocProverErrorCode, MdocVerifierErrorCode};
pub use mac::{generate_mac_ap, push_macs};
pub use mdoc_zk_circuits as circuits;
pub use mdoc_zk_compile as generate;
pub use mdoc_zk_compile::*;
pub use mdoc_zk_proto::{config, *};
pub use proto::*;
pub use prover::*;
pub use provider::*;
pub use utils::{circuit_supports, parse_hex_nat, parse_pk_coordinate, req_attr, same_namespace};
pub use verifier::*;
pub use zk_spec::*;
