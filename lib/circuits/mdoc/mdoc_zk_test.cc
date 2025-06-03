// Copyright 2024 Google LLC.
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

#include "circuits/mdoc/mdoc_zk.h"

#include <stdio.h>
#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "circuits/mdoc/mdoc_examples.h"
#include "random/secure_random_engine.h"
#include "util/log.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

// Test fixture for MdocZK that handles 1 and 2 attribute circuits.
// This class produces static versions of the 1- and 2- attribute circuits
// and reuses them for all tests.
class MdocZKTest : public testing::Test {
 protected:
  MdocZKTest() { set_log_level(INFO); }

  static void SetUpTestCase() {
    const ZkSpecStruct &zk_spec_1 = kZkSpecs[0];
    const ZkSpecStruct &zk_spec_2 = kZkSpecs[1];
    if (circuit1_ == nullptr) {
      EXPECT_EQ(generate_circuit(&zk_spec_1, &circuit1_, &circuit_len1_),
                CIRCUIT_GENERATION_SUCCESS);
      EXPECT_EQ(generate_circuit(&zk_spec_2, &circuit2_, &circuit_len2_),
                CIRCUIT_GENERATION_SUCCESS);
    }
  }

  static void TearDownTestCase() {
    if (circuit1_ != nullptr) {
      free(circuit1_);
      free(circuit2_);
      circuit1_ = nullptr;
      circuit2_ = nullptr;
    }
  }

  void run_test(size_t num_attrs, const RequestedAttribute *attrs,
                const MdocTests *test,
                MdocProverErrorCode want_ret = MDOC_PROVER_SUCCESS) {
    uint8_t *circuit = num_attrs == 1 ? circuit1_ : circuit2_;
    size_t circuit_len = num_attrs == 1 ? circuit_len1_ : circuit_len2_;
    const ZkSpecStruct zk_spec = num_attrs == 1 ? kZkSpecs[0] : kZkSpecs[1];
    EXPECT_TRUE(circuit != nullptr);

    uint8_t *zkproof;
    size_t proof_len;

    {
      log(INFO, "starting prover");
      MdocProverErrorCode ret = run_mdoc_prover(
          circuit, circuit_len, test->mdoc, test->mdoc_size,
          test->pkx.as_pointer, test->pky.as_pointer, test->transcript,
          test->transcript_size, attrs, num_attrs, (const char *)test->now,
          &zkproof, &proof_len, &zk_spec);
      EXPECT_EQ(ret, want_ret);
    }

    if (want_ret == MDOC_PROVER_SUCCESS) {
      log(INFO, "starting verifier");
      MdocVerifierErrorCode ret = run_mdoc_verifier(
          circuit, circuit_len, test->pkx.as_pointer, test->pky.as_pointer,
          test->transcript, test->transcript_size, attrs, num_attrs,
          (const char *)test->now, zkproof, proof_len, test->doc_type,
          &zk_spec);
      EXPECT_EQ(ret, MDOC_VERIFIER_SUCCESS);
      free(zkproof);
    }
  }

  // The two circuits are generated once and reused for all tests.
  static uint8_t *circuit1_, *circuit2_;
  static size_t circuit_len1_, circuit_len2_;
};

uint8_t *MdocZKTest::circuit1_ = nullptr;
uint8_t *MdocZKTest::circuit2_ = nullptr;
size_t MdocZKTest::circuit_len1_ = 0;
size_t MdocZKTest::circuit_len2_ = 0;

typedef struct {
  RequestedAttribute claims[1];
  const MdocTests *mdoc;
} Claims;

typedef struct {
  RequestedAttribute claims[2];
  const MdocTests *mdoc;
} TwoClaims;

static const RequestedAttribute age_over_18 = {
    .id = {'a', 'g', 'e', '_', 'o', 'v', 'e', 'r', '_', '1', '8'},
    .value = {0xf5},
    .id_len = 11,
    .value_len = 1};

static const RequestedAttribute not_over_18 = {
    .id = {'a', 'g', 'e', '_', 'o', 'v', 'e', 'r', '_', '1', '8'},
    .value = {0xf4},
    .id_len = 11,
    .value_len = 1};

static const RequestedAttribute familyname_mustermann = {
    .id = {'f', 'a', 'm', 'i', 'l', 'y', '_', 'n', 'a', 'm', 'e'},
    .value = {'M', 'u', 's', 't', 'e', 'r', 'm', 'a', 'n', 'n'},
    .id_len = 11,
    .value_len = 10};

static const RequestedAttribute birthdate_1971_09_01 = {
    .id = {'b', 'i', 'r', 't', 'h', '_', 'd', 'a', 't', 'e'},
    .value = {'1', '9', '7', '1', '-', '0', '9', '-', '0', '1'},
    .id_len = 10,
    .value_len = 10};

static const RequestedAttribute birthdate_1998_09_04 = {
    .id = {'b', 'i', 'r', 't', 'h', '_', 'd', 'a', 't', 'e'},
    .value = {'1', '9', '9', '8', '-', '0', '9', '-', '0', '4'},
    .id_len = 10,
    .value_len = 10};

static const RequestedAttribute height_175 = {
    {'h', 'e', 'i', 'g', 'h', 't'}, {0x18, 0xaf}, 6, 2};

TEST_F(MdocZKTest, one_claim) {
  const Claims tests[] = {{
                              {age_over_18},
                              &mdoc_tests[0],
                          },
                          {
                              {age_over_18},
                              &mdoc_tests[1],
                          },
                          {
                              {age_over_18},
                              &mdoc_tests[2],
                          },
                          {
                              {familyname_mustermann},
                              &mdoc_tests[3],
                          },
                          {
                              {birthdate_1971_09_01},
                              &mdoc_tests[3],
                          },
                          {
                              {height_175},
                              &mdoc_tests[3],
                          },
                          // Test Google IDPass which uses a different docType.
                          {
                              {birthdate_1998_09_04},
                              &mdoc_tests[4],
                          },
                          // Website explainer example.
                          {
                              {age_over_18},
                              &mdoc_tests[5],
                          }};

  for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
    run_test(1, tests[i].claims, tests[i].mdoc);
  }
}

TEST_F(MdocZKTest, two_claims) {
  const TwoClaims two_tests[] = {
      {
          {
              age_over_18,
              familyname_mustermann,
          },
          &mdoc_tests[3],
      },
      {
          {
              age_over_18,
              birthdate_1971_09_01,
          },
          &mdoc_tests[3],
      },
      {
          {
              height_175,
              {.id = {'i', 's', 's', 'u', 'e', '_', 'd', 'a', 't', 'e'},
               .value = {'2', '0', '2', '4', '-', '0', '3', '-', '1', '5'},
               .id_len = 10,
               .value_len = 10},
          },
          &mdoc_tests[3],
      },
  };

  for (size_t i = 0; i < sizeof(two_tests) / sizeof(two_tests[0]); ++i) {
    run_test(2, two_tests[i].claims, two_tests[i].mdoc);
  }
}

TEST_F(MdocZKTest, wrong_witness) {
  const Claims fail_tests[] = {
      {
          {not_over_18},
          &mdoc_tests[0],
      },
      {
          {not_over_18},
          &mdoc_tests[1],
      },
      {
          {not_over_18},
          &mdoc_tests[2],
      },
      {
          {{{'b', 'i', 'r', 't', 'h', '_', 'd', 'a', 't', 'e'},
            {'0', '9', '7', '1', '-', '0', '9', '-', '0', '1'},
            10,
            10}},
          &mdoc_tests[3],
      },
      {
          {{{'b', 'i', 'r', 't', 'h', '_', 'd', 'a', 't', 'e'},
            {'1', '8', '7', '1', '-', '0', '9', '-', '0', '1'},
            10,
            10}},
          &mdoc_tests[3],
      },
      {
          {{{'b', 'i', 'r', 't', 'h', '_', 'd', 'a', 't', 'e'},
            {0xD9, 0x03, 0xEC, 0x6A, '1', '9', '7', '1', '-', '0', '9', '-',
             '0', '1', '0'},
            10,
            15}},
          &mdoc_tests[3],
      },
  };

  for (size_t i = 0; i < sizeof(fail_tests) / sizeof(fail_tests[0]); ++i) {
    run_test(1, fail_tests[i].claims, fail_tests[i].mdoc,
             MDOC_PROVER_GENERAL_FAILURE);
  }
}

TEST_F(MdocZKTest, bad_arguments) {
  constexpr int num_attrs = 1;
  const ZkSpecStruct &zk_spec_1 = kZkSpecs[0];
  RequestedAttribute attrs[num_attrs] = {
      age_over_18,
  };
  uint8_t tr[100];
  uint8_t zkproof[30000];
  uint8_t circuit[60000];
  uint8_t mdoc[60000];
  const char *pk = "0x15";
  const char *pk2 = "bad_pk";
  const char *now = "2023-11-02T09:00:00Z";
  size_t proof_len;
  // ZStd encoding for "hello".
  uint8_t bad_circuit[50001] = {0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x05, 0x29,
                                0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f};

  // Invalid arguments to generate_circuit.
  size_t circuit_len;
  EXPECT_EQ(generate_circuit(nullptr, (uint8_t **)&circuit, &circuit_len),
            CIRCUIT_GENERATION_NULL_INPUT);
  EXPECT_EQ(generate_circuit(&zk_spec_1, nullptr, &circuit_len),
            CIRCUIT_GENERATION_NULL_INPUT);
  EXPECT_EQ(generate_circuit(&zk_spec_1, (uint8_t **)&circuit, nullptr),
            CIRCUIT_GENERATION_NULL_INPUT);

  // Basic prover tests that pass in a null ptr.
  EXPECT_EQ(run_mdoc_prover(nullptr, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            pk, tr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t **)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), nullptr, sizeof(mdoc), pk,
                            pk, tr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t **)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc),
                            nullptr, pk, tr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t **)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            nullptr, tr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t **)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            pk, nullptr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t **)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            pk, tr, sizeof(tr), nullptr, num_attrs, now,
                            (uint8_t **)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            pk, tr, sizeof(tr), attrs, num_attrs, nullptr,
                            (uint8_t **)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            pk, tr, sizeof(tr), attrs, num_attrs, now, nullptr,
                            &proof_len, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            pk, tr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t **)&zkproof, nullptr, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            pk, tr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t **)&zkproof, &proof_len, nullptr),
            MDOC_PROVER_NULL_INPUT);

  // Invalid pk.
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk2,
                            pk, tr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t **)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_INVALID_INPUT);

  // Invalid circuit.
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            pk, tr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t **)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_CIRCUIT_PARSING_FAILURE);
  EXPECT_EQ(
      run_mdoc_prover(bad_circuit, sizeof(bad_circuit), mdoc, sizeof(mdoc), pk,
                      pk, tr, sizeof(tr), attrs, num_attrs, now,
                      (uint8_t **)&zkproof, &proof_len, &zk_spec_1),
      MDOC_PROVER_CIRCUIT_PARSING_FAILURE);

  // Basic verifier tests that pass in a null ptr.
  // Broken circuit.
  EXPECT_EQ(run_mdoc_verifier(nullptr, sizeof(circuit), pk, pk, tr, sizeof(tr),
                              attrs, num_attrs, now, zkproof, sizeof(zkproof),
                              kDefaultDocType, &zk_spec_1),
            MDOC_VERIFIER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_verifier(circuit, 49999, pk, pk, tr, sizeof(tr), attrs,
                              num_attrs, now, zkproof, sizeof(zkproof),
                              kDefaultDocType, &zk_spec_1),
            MDOC_VERIFIER_ARGUMENTS_TOO_SMALL);
  EXPECT_EQ(run_mdoc_verifier(bad_circuit, sizeof(bad_circuit), pk, pk, tr,
                              sizeof(tr), attrs, num_attrs, now, zkproof,
                              sizeof(zkproof), kDefaultDocType, &zk_spec_1),
            MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE);

  // Broken pk.
  EXPECT_EQ(run_mdoc_verifier(circuit, sizeof(circuit), nullptr, pk, tr,
                              sizeof(tr), attrs, num_attrs, now, zkproof,
                              sizeof(zkproof), kDefaultDocType, &zk_spec_1),
            MDOC_VERIFIER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_verifier(circuit, sizeof(circuit), pk, nullptr, tr,
                              sizeof(tr), attrs, num_attrs, now, zkproof,
                              sizeof(zkproof), kDefaultDocType, &zk_spec_1),
            MDOC_VERIFIER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_verifier(circuit, sizeof(circuit), pk, pk2, tr, sizeof(tr),
                              attrs, num_attrs, now, zkproof, sizeof(zkproof),
                              kDefaultDocType, &zk_spec_1),
            MDOC_VERIFIER_INVALID_INPUT);

  // Broken transcript.
  EXPECT_EQ(run_mdoc_verifier(circuit, sizeof(circuit), pk, pk, nullptr,
                              sizeof(tr), attrs, num_attrs, now, zkproof,
                              sizeof(zkproof), kDefaultDocType, &zk_spec_1),
            MDOC_VERIFIER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_verifier(circuit, sizeof(circuit), pk, pk, tr, 0, attrs,
                              num_attrs, now, zkproof, sizeof(zkproof),
                              kDefaultDocType, &zk_spec_1),
            MDOC_VERIFIER_ARGUMENTS_TOO_SMALL);
  // Broken attrs.
  EXPECT_EQ(run_mdoc_verifier(circuit, sizeof(circuit), pk, pk, tr, sizeof(tr),
                              nullptr, num_attrs, now, zkproof, sizeof(zkproof),
                              kDefaultDocType, &zk_spec_1),
            MDOC_VERIFIER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_verifier(circuit, sizeof(circuit), pk, pk, tr, sizeof(tr),
                              attrs, 0, now, zkproof, sizeof(zkproof),
                              kDefaultDocType, &zk_spec_1),
            MDOC_VERIFIER_ARGUMENTS_TOO_SMALL);
  // Broken now.
  EXPECT_EQ(run_mdoc_verifier(circuit, sizeof(circuit), pk, pk, tr, sizeof(tr),
                              attrs, num_attrs, nullptr, zkproof,
                              sizeof(zkproof), kDefaultDocType, &zk_spec_1),
            MDOC_VERIFIER_NULL_INPUT);

  // Broken zkproof.
  EXPECT_EQ(run_mdoc_verifier(circuit, sizeof(circuit), pk, pk, tr, sizeof(tr),
                              attrs, num_attrs, now, nullptr, sizeof(zkproof),
                              kDefaultDocType, &zk_spec_1),
            MDOC_VERIFIER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_verifier(circuit1_, circuit_len1_, pk, pk, tr, sizeof(tr),
                              attrs, num_attrs, now, zkproof, 100,
                              kDefaultDocType, &zk_spec_1),
            MDOC_VERIFIER_ARGUMENTS_TOO_SMALL);

  uint8_t id[32];
  EXPECT_EQ(circuit_id(nullptr, circuit1_, circuit_len1_, &zk_spec_1), 0);
  EXPECT_EQ(circuit_id(id, nullptr, 0, &zk_spec_1), 0);
  EXPECT_EQ(circuit_id(id, circuit1_, circuit_len1_, nullptr), 0);
  EXPECT_EQ(circuit_id(id, circuit1_, 10, &zk_spec_1), 0);
  EXPECT_EQ(circuit_id(id, circuit1_, circuit_len1_ - 8, &zk_spec_1), 0);
}

TEST_F(MdocZKTest, attr_mismatch) {
  uint8_t *zkproof;
  size_t proof_len;
  constexpr int num_attrs = 2;
  const ZkSpecStruct &zk_spec_2 = kZkSpecs[1];
  RequestedAttribute attrs[num_attrs] = {age_over_18, age_over_18};
  const struct MdocTests *test = &mdoc_tests[0];

  {
    MdocProverErrorCode ret = run_mdoc_prover(
        circuit2_, circuit_len2_, test->mdoc, test->mdoc_size,
        test->pkx.as_pointer, test->pky.as_pointer, test->transcript,
        test->transcript_size, attrs, num_attrs, (const char *)test->now,
        &zkproof, &proof_len, &zk_spec_2);
    EXPECT_EQ(ret, MDOC_PROVER_SUCCESS);
  }
  {
    MdocVerifierErrorCode ret = run_mdoc_verifier(
        circuit2_, circuit_len2_, test->pkx.as_pointer, test->pky.as_pointer,
        test->transcript, test->transcript_size, attrs, num_attrs - 1,
        (const char *)test->now, zkproof, proof_len, kDefaultDocType,
        &zk_spec_2);
    EXPECT_EQ(ret, MDOC_VERIFIER_ATTRIBUTE_NUMBER_MISMATCH);
  }
  free(zkproof);
}

TEST_F(MdocZKTest, bad_proofs) {
  set_log_level(ERROR);
  constexpr int num_attrs = 1;
  const ZkSpecStruct &zk_spec_1 = kZkSpecs[0];
  RequestedAttribute attrs[num_attrs] = {age_over_18};
  const struct MdocTests *test = &mdoc_tests[0];

  constexpr size_t kMaxProofLen = 100000;
  uint8_t zkproof[kMaxProofLen];
  SecureRandomEngine rng;
  rng.bytes(zkproof, sizeof(zkproof));
  for (size_t proof_len = 0; proof_len < kMaxProofLen; proof_len += 1000) {
    MdocVerifierErrorCode ret = run_mdoc_verifier(
        circuit1_, circuit_len1_, test->pkx.as_pointer, test->pky.as_pointer,
        test->transcript, test->transcript_size, attrs, num_attrs,
        (const char *)test->now, zkproof, proof_len, kDefaultDocType,
        &zk_spec_1);
    EXPECT_NE(ret, MDOC_VERIFIER_SUCCESS);
  }
}

static const Claims benchmark_claim = {
    {age_over_18},
    &mdoc_tests[0],
};

void BM_MdocProver(benchmark::State &state) {
  set_log_level(ERROR);

  const ZkSpecStruct &zk_spec_1 = kZkSpecs[0];
  size_t circuit_len;
  uint8_t *circuit;
  EXPECT_EQ(generate_circuit(&zk_spec_1, &circuit, &circuit_len),
            CIRCUIT_GENERATION_SUCCESS);

  const RequestedAttribute *attrs = benchmark_claim.claims;
  const MdocTests *test = benchmark_claim.mdoc;
  size_t num_attrs = 1;
  const ZkSpecStruct zk_spec = kZkSpecs[0];

  for (auto _ : state) {
    uint8_t *zkproof;
    size_t proof_len;

    MdocProverErrorCode ret = run_mdoc_prover(
        circuit, circuit_len, test->mdoc, test->mdoc_size, test->pkx.as_pointer,
        test->pky.as_pointer, test->transcript, test->transcript_size, attrs,
        num_attrs, (const char *)test->now, &zkproof, &proof_len, &zk_spec);
    EXPECT_EQ(ret, MDOC_PROVER_SUCCESS);
    free(zkproof);
  }
}

BENCHMARK(BM_MdocProver);

void BM_MdocVerifier(benchmark::State &state) {
  set_log_level(ERROR);

  const ZkSpecStruct &zk_spec_1 = kZkSpecs[0];
  size_t circuit_len;
  uint8_t *circuit;
  EXPECT_EQ(generate_circuit(&zk_spec_1, &circuit, &circuit_len),
            CIRCUIT_GENERATION_SUCCESS);

  const RequestedAttribute *attrs = benchmark_claim.claims;
  const MdocTests *test = benchmark_claim.mdoc;
  size_t num_attrs = 1;
  const ZkSpecStruct zk_spec = kZkSpecs[0];

  uint8_t *zkproof;
  size_t proof_len;

  MdocProverErrorCode retp = run_mdoc_prover(
      circuit, circuit_len, test->mdoc, test->mdoc_size, test->pkx.as_pointer,
      test->pky.as_pointer, test->transcript, test->transcript_size, attrs,
      num_attrs, (const char *)test->now, &zkproof, &proof_len, &zk_spec);
  EXPECT_EQ(retp, MDOC_PROVER_SUCCESS);

  for (auto _ : state) {
    MdocVerifierErrorCode retv = run_mdoc_verifier(
        circuit, circuit_len, test->pkx.as_pointer, test->pky.as_pointer,
        test->transcript, test->transcript_size, attrs, num_attrs,
        (const char *)test->now, zkproof, proof_len, test->doc_type, &zk_spec);
    EXPECT_EQ(retv, MDOC_VERIFIER_SUCCESS);
  }

  free(zkproof);
}

BENCHMARK(BM_MdocVerifier);

}  // namespace
}  // namespace proofs
