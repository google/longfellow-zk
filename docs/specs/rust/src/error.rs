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

use std::fmt;

use crate::{
    algebra::FieldError, ligero::VerificationError, sumcheck::CircuitEvaluationError,
    zk::ZkVerificationError,
};

#[derive(Debug)]
pub enum ZkError {
    Field(FieldError),
    Ligero(VerificationError),
    ZkVerification(ZkVerificationError),
    CircuitEvaluation(CircuitEvaluationError),
    Io(std::io::Error),
    InvalidData(String),
}

impl fmt::Display for ZkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Field(e) => write!(f, "Field error: {}", e),
            Self::Ligero(e) => write!(f, "Ligero error: {}", e),
            Self::ZkVerification(e) => write!(f, "ZK verification error: {}", e),
            Self::CircuitEvaluation(e) => write!(f, "Circuit evaluation error: {}", e),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::InvalidData(msg) => write!(f, "Invalid data error: {}", msg),
        }
    }
}

impl std::error::Error for ZkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Field(e) => Some(e),
            Self::Ligero(e) => Some(e),
            Self::ZkVerification(e) => Some(e),
            Self::CircuitEvaluation(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::InvalidData(_) => None,
        }
    }
}

impl From<FieldError> for ZkError {
    fn from(e: FieldError) -> Self {
        Self::Field(e)
    }
}

impl From<VerificationError> for ZkError {
    fn from(e: VerificationError) -> Self {
        Self::Ligero(e)
    }
}

impl From<ZkVerificationError> for ZkError {
    fn from(e: ZkVerificationError) -> Self {
        Self::ZkVerification(e)
    }
}

impl From<CircuitEvaluationError> for ZkError {
    fn from(e: CircuitEvaluationError) -> Self {
        Self::CircuitEvaluation(e)
    }
}

impl From<std::io::Error> for ZkError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
