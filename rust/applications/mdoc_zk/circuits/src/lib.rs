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

pub mod cbor;
pub mod cbor_decoder;
pub mod hash;
pub mod mso_attribute;
pub mod signature;
pub mod traits;

pub use cbor::{cbor_encode::*, mdoc::*, test_utils::*};
pub use mdoc_zk_proto::*;
pub use traits::*;

pub const CURRENT_VERSION: usize = 8;
