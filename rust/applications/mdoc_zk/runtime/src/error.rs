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

// Return codes for the run_mdoc_prover method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MdocProverErrorCode {
    Success = 0,
    NullInput = 1,
    InvalidInput = 2,
    CircuitParsingFailure = 3,
    HashParsingFailure = 4,
    WitnessCreationFailure = 5,
    GeneralFailure = 6,
    MemoryAllocationFailure = 7,
    InvalidZkSpecVersion = 8,
    RootDecodingFailure = 9,
    DocumentsMissing = 10,
    Document0Missing = 11,
    DocTypeMissing = 12,
    IssuerSignedMissing = 13,
    IssuerAuthMissing = 14,
    MsoMissing = 15,
    NsigMissing = 16,
    NamespacesMissing = 17,
    DeviceSignedMissing = 18,
    DeviceAuthMissing = 19,
    DeviceSignatureMissing = 20,
    DeviceKeyMissing = 21,
    MsoDecodingFailure = 22,
    ValidityInfoMissing = 23,
    DeviceKeyInfoMissing = 24,
    AttributeDecodeFailure = 25,
    AttributeEiMissing = 26,
    AttributeEvMissing = 27,
    AttributeDidMissing = 28,
    SignatureFailure = 29,
    DeviceSignatureFailure = 30,
    AttributeNotFound = 31,
    AttributeTooLong = 32,
    TaggedMsoTooBig = 33,
    VersionNotSupported = 34,
    AttributeRandomMissing = 35,
    UnsupportedAttribute = 36,
}

// Return codes for the run_mdoc_verifier method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MdocVerifierErrorCode {
    Success = 0,
    CircuitParsingFailure = 1,
    ProofTooSmall = 2,
    HashParsingFailure = 3,
    SignatureParsingFailure = 4,
    GeneralFailure = 5,
    NullInput = 6,
    InvalidInput = 7,
    ArgumentsTooSmall = 8,
    AttributeNumberMismatch = 9,
    InvalidZkSpecVersion = 10,
    UnsupportedAttribute = 11,
}
