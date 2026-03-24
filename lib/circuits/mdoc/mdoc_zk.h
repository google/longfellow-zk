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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_ZK_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_ZK_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// This package implements C interfaces that allow external programs to call
// the zk mdoc-based prover and verifier.
//
// It also contains a helper method that produces a byte representation
// of a circuit which verifies the mdoc with regards to specific properties,
// for example age_over_18. The circuit generation can be run once, and the
// result cached for subsequent use in the prover and verifier.

const size_t kLigeroRate = 4;
const size_t kLigeroNreq = 128;  // 86+ bits statistical security

const size_t kLigeroRatev7 = 7;
const size_t kLigeroNreqv7 = 132;  // ~109 bits statistical security

/* This struct allows a verifier to express which attribute and value the prover
 * must claim.  The value should be passed as the raw bytes of the CBOR value.
 */
typedef struct {
  uint8_t namespace_id[64];
  uint8_t id[32];
  uint8_t cbor_value[64];
  size_t namespace_len, id_len, cbor_value_len;
} RequestedAttribute;

// Return codes for the run_mdoc_prover method.
typedef enum {
  MDOC_PROVER_SUCCESS = 0,
  MDOC_PROVER_NULL_INPUT,
  MDOC_PROVER_INVALID_INPUT,
  MDOC_PROVER_CIRCUIT_PARSING_FAILURE,
  MDOC_PROVER_HASH_PARSING_FAILURE,
  MDOC_PROVER_WITNESS_CREATION_FAILURE,
  MDOC_PROVER_GENERAL_FAILURE,
  MDOC_PROVER_MEMORY_ALLOCATION_FAILURE,
  MDOC_PROVER_INVALID_ZK_SPEC_VERSION,
  MDOC_PROVER_ROOT_DECODING_FAILURE,
  MDOC_PROVER_DOCUMENTS_MISSING,
  MDOC_PROVER_DOCUMENT_0_MISSING,
  MDOC_PROVER_DOCTYPE_MISSING,
  MDOC_PROVER_ISSUER_SIGNED_MISSING,
  MDOC_PROVER_ISSUER_AUTH_MISSING,
  MDOC_PROVER_MSO_MISSING,
  MDOC_PROVER_NSIG_MISSING,
  MDOC_PROVER_NAMESPACES_MISSING,
  MDOC_PROVER_DEVICE_SIGNED_MISSING,
  MDOC_PROVER_DEVICE_AUTH_MISSING,
  MDOC_PROVER_DEVICE_SIGNATURE_MISSING,
  MDOC_PROVER_DEVICE_KEY_MISSING,
  MDOC_PROVER_MSO_DECODING_FAILURE,
  MDOC_PROVER_VALIDITY_INFO_MISSING,
  MDOC_PROVER_DEVICE_KEY_INFO_MISSING,
  MDOC_PROVER_ATTRIBUTE_DECODE_FAILURE,
  MDOC_PROVER_ATTRIBUTE_EI_MISSING,
  MDOC_PROVER_ATTRIBUTE_EV_MISSING,
  MDOC_PROVER_ATTRIBUTE_DID_MISSING,
  MDOC_PROVER_SIGNATURE_FAILURE,
  MDOC_PROVER_DEVICE_SIGNATURE_FAILURE,
  MDOC_PROVER_ATTRIBUTE_NOT_FOUND,
  MDOC_PROVER_ATTRIBUTE_TOO_LONG,
  MDOC_PROVER_TAGGED_MSO_TOO_BIG,
  MDOC_PROVER_VERSION_NOT_SUPPORTED,
  MDOC_PROVER_ATTRIBUTE_RANDOM_MISSING,
} MdocProverErrorCode;

// Return codes for the run_mdoc_verifier method.
typedef enum {
  MDOC_VERIFIER_SUCCESS = 0,
  MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE,
  MDOC_VERIFIER_PROOF_TOO_SMALL,
  MDOC_VERIFIER_HASH_PARSING_FAILURE,
  MDOC_VERIFIER_SIGNATURE_PARSING_FAILURE,
  MDOC_VERIFIER_GENERAL_FAILURE,
  MDOC_VERIFIER_NULL_INPUT,
  MDOC_VERIFIER_INVALID_INPUT,
  MDOC_VERIFIER_ARGUMENTS_TOO_SMALL,
  MDOC_VERIFIER_ATTRIBUTE_NUMBER_MISMATCH,
  MDOC_VERIFIER_INVALID_ZK_SPEC_VERSION,
  MDOC_VERIFIER_INVALID_CBOR,
} MdocVerifierErrorCode;

// Return codes for the generate_circuit method.
typedef enum {
  CIRCUIT_GENERATION_SUCCESS = 0,
  CIRCUIT_GENERATION_NULL_INPUT,
  CIRCUIT_GENERATION_ZLIB_FAILURE,
  CIRCUIT_GENERATION_GENERAL_FAILURE,
  CIRCUIT_GENERATION_INVALID_ZK_SPEC_VERSION,
} CircuitGenerationErrorCode;

// This structure represents a version of ZK specification supported by this
// library. It is passed into all the methods for circuit generation, running
// the prover and verifier.
// It allows us to version the specification of the ZK system. The prover and
// the verifier are supposed to negotiate the version of the specification they
// both support before executing digital credential presentment.
typedef struct {
  // The ZK system name and version- "longfellow-libzk-v*" for Google library.
  const char* system;
  // The hash of the compressed circuit (the way it's generated and passed to
  // prover/verifier)
  const char circuit_hash[65];
  // The number of attributes that the circuit supports.
  size_t num_attributes;
  // The version of the ZK specification.
  size_t version;
  // The block_enc parameter for the ZK proof.
  size_t block_enc_hash, block_enc_sig;
} ZkSpecStruct;

static const char kDefaultDocType[] = "org.iso.18013.5.1.mDL";

// An upper-bound on the decompressed circuit size. It is better to make this
// bound tight to avoid memory failure in the resource restricted Android
// gmscore environment.
static const size_t kCircuitSizeMax = 150000000;

// The run_mdoc2_prover method takes byte-oriented inputs that describe a
// circuit, mdoc, the public key of the issuer for the mdoc, a transcript
// for the mdoc request operation, an array of RequestedAttribute that
// represents claims that you want to prove, and a 20-char representation of the
// current time. It writes the proof and its length into the input parameter prf
// and proof_len. It is the responsibility of the caller to later free the proof
// memory. If the prover fails to produce a proof, e.g., because the mdoc is
// invalid, or the now time does not satisfy the validFrom and validUntil
// constraints, then the prover returns an error code.
// The following lines document how attributes can be opened in ZK.
// {(uint8_t *)"family_name", 11, (uint8_t *)"Mustermann", 10},
// {(uint8_t *)"height", 6, (uint8_t *)"\x18\xaf", 2},
// {(uint8_t *)"birth_date", 10, (uint8_t *)"\xD9\x03\xEC\x6A" "1971-09-01",
// 14},
// {(uint8_t *)"issue_date", 10, (uint8_t *)"\xD9\x03\xEC\x6A" "2024-03-15",
// 14},
MdocProverErrorCode run_mdoc_prover(
    const uint8_t* bcp, size_t bcsz,          /* circuit data */
    const uint8_t* mdoc, size_t mdoc_len,     /* full mdoc */
    const char* pkx, const char* pky,         /* string rep of public key */
    const uint8_t* transcript, size_t tr_len, /* session transcript */
    const RequestedAttribute* attrs, size_t attrs_len,
    const char* now, /* time formatted as "2023-11-02T09:00:00Z" */
    uint8_t** prf, size_t* proof_len, const ZkSpecStruct* zk_spec_version);

// The run_mdoc2_verifier method accepts a byte representation of the circuit,
// the public key of the issuer, the transcript, an array of RequestedAttribute
// that represents claims that you want to verify, and a 20-char representation
// of the time, as well as the proof and its length.
MdocVerifierErrorCode run_mdoc_verifier(
    const uint8_t* bcp, size_t bcsz,          /* circuit data */
    const char* pkx, const char* pky,         /* string rep of public key */
    const uint8_t* transcript, size_t tr_len, /* session transcript */
    const RequestedAttribute* attrs, size_t attrs_len,
    const char* now, /* time formatted as "2023-11-02T09:00:00Z" */
    const uint8_t* zkproof, size_t proof_len, const char* docType,
    const ZkSpecStruct* zk_spec_version);

// Produces a compressed version of the circuit bytes for the specified number
// of attributes. The generator only supports the latest version of the ZKSpec
// for a number of attributes. Attempt to generate older circuits will result in
// an error.
CircuitGenerationErrorCode generate_circuit(const ZkSpecStruct* zk_spec_version,
                                            uint8_t** cb, size_t* clen);

// Produces an identifier for a pair of circuits (c_1, c_2) over (Fp256, f_128)
// respectively. This method parses the input bytes into two circuits, computes
// the circuit's ids of each, and then computes the SHA256 hash of the two ids.
// This method is used to identify "circuit bundles" consisting of multiple
// circuits.
int circuit_id(uint8_t id[/*kSHA256DigestSize*/], const uint8_t* bcp,
               size_t bcsz, const ZkSpecStruct* zk_spec);

enum { kNumZkSpecs = 12 };
// This is a hardcoded list of all the ZK specifications supported by this
// library. Every time a new breaking change is introduced in either the circuit
// format or its interpretation, a new version must be added here.
// It is possible to remove old versions, if we're sure that they are not used
// by either provers of verifiers in the wild.
extern const ZkSpecStruct kZkSpecs[kNumZkSpecs];

// Returns a static pointer to the ZkSpecStruct that matches the given system
// name and circuit hash. Returns nullptr if no matching ZkSpecStruct is found.
const ZkSpecStruct* find_zk_spec(const char* system_name,
                                 const char* circuit_hash);

#ifdef __cplusplus
}

namespace proofs {
// Function is private, but it is declared here for testing.
bool cbor_validate(const uint8_t* in, size_t len);
}  // namespace proofs
#endif

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_ZK_H_
