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

use crate::RandomEngine;

/// A cryptographically secure random engine backed by the operating system's CSPRNG.
#[derive(Clone, Default, Debug)]
pub struct SecureRandomEngine;

impl SecureRandomEngine {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl RandomEngine for SecureRandomEngine {
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        getrandom::fill(&mut buf).expect("Failed to generate secure random bytes from OS CSPRNG");
        buf
    }
}
