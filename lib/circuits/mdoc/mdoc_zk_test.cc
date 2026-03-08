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

#include "circuits/mdoc/mdoc_zk.h"

#include <stdio.h>
#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>

#include "circuits/mdoc/mdoc_examples.h"
#include "circuits/mdoc/mdoc_test_attributes.h"
#include "circuits/mdoc/mdoc_witness.h"
#include "random/secure_random_engine.h"
#include "util/log.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"
#include <openssl/hmac.h>

namespace proofs {
namespace {

// Test fixture for MdocZK that handles 1 and 2 attribute circuits.
// This class produces static versions of the 1- and 2- attribute circuits
// and reuses them for all tests.
class MdocZKTest : public testing::Test {
 protected:
  MdocZKTest() { set_log_level(INFO); }

  static void SetUpTestCase() {
    if (circuit1_ == nullptr) {
      EXPECT_EQ(generate_circuit(&kZkSpecs[0], &circuit1_, &circuit_len1_),
                CIRCUIT_GENERATION_SUCCESS);
      EXPECT_EQ(generate_circuit(&kZkSpecs[1], &circuit2_, &circuit_len2_),
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

  void run_test(const char* test_name, size_t num_attrs,
                const RequestedAttribute* attrs, const MdocTests* test,
                MdocProverErrorCode want_ret = MDOC_PROVER_SUCCESS) {
    uint8_t* circuit = num_attrs == 1 ? circuit1_ : circuit2_;
    size_t circuit_len = num_attrs == 1 ? circuit_len1_ : circuit_len2_;
    const ZkSpecStruct zk_spec = num_attrs == 1 ? kZkSpecs[0] : kZkSpecs[1];
    EXPECT_TRUE(circuit != nullptr);

    uint8_t* zkproof = nullptr;
    size_t proof_len;

    log(INFO, "========== Test %s", test_name);
    {
      log(INFO, "starting prover");
      MdocProverErrorCode ret = run_mdoc_prover(
          circuit, circuit_len, test->mdoc, test->mdoc_size,
          test->pkx.as_pointer, test->pky.as_pointer, test->transcript,
          test->transcript_size, attrs, num_attrs, (const char*)test->now,
          &zkproof, &proof_len, &zk_spec);
      EXPECT_EQ(ret, want_ret);
    }

    if (want_ret == MDOC_PROVER_SUCCESS) {
      log(INFO, "starting verifier");
      MdocVerifierErrorCode ret = run_mdoc_verifier(
          circuit, circuit_len, test->pkx.as_pointer, test->pky.as_pointer,
          test->transcript, test->transcript_size, attrs, num_attrs,
          (const char*)test->now, zkproof, proof_len, test->doc_type, &zk_spec);
      EXPECT_EQ(ret, MDOC_VERIFIER_SUCCESS);
    }

    if (zkproof != nullptr) {
      free(zkproof);
    }
  }

  // The two circuits are generated once and reused for all tests.
  static uint8_t *circuit1_, *circuit2_;
  static size_t circuit_len1_, circuit_len2_;
};

uint8_t* MdocZKTest::circuit1_ = nullptr;
uint8_t* MdocZKTest::circuit2_ = nullptr;
size_t MdocZKTest::circuit_len1_ = 0;
size_t MdocZKTest::circuit_len2_ = 0;

// used in the pseudonym tests as an input into the pseudonym generation
const uint8_t kVerifierId[32] = {
    0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x40, 0x63, 0x6c, 0x69,
    0x65, 0x6e, 0x74, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
    0x63, 0x6f, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x00
};

// used in the pseudonym tests as an input into the pseudonym generation
const uint8_t kPpidContext[32] = {
    0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// used in the pseudonym tests to prepare the public outputs
void SetupPpidTestOutputs(const uint8_t* mdoc_data, size_t mdoc_size, RequestedAttribute public_outputs[2]) {
  ParsedMdoc pm;
  EXPECT_EQ(pm.parse_device_response(mdoc_size, mdoc_data), MDOC_PROVER_SUCCESS);

  const uint8_t *seed_val = nullptr;
  const uint8_t *over_18_val = nullptr;
  size_t over_18_len = 0;
  size_t seed_len = 0;

  // extract the pseudonym seed and age_over_18 from the mdoc itself
  EXPECT_TRUE(pm.extract_cbor_value("pseudonym_seed", &seed_val, &seed_len));
  EXPECT_TRUE(pm.extract_cbor_value("age_over_18", &over_18_val, &over_18_len));

  // compute the pseudonym as HMAC(seed, verifier_id || context) and store it
  // in hmac_out
  uint8_t seed[32];
  memcpy(seed, seed_val, 32);

  uint8_t hmac_data[64];
  memcpy(hmac_data, kVerifierId, 32);
  memcpy(hmac_data + 32, kPpidContext, 32);

  uint8_t hmac_out[32];
  unsigned int hmac_len = 32;
  HMAC(EVP_sha256(), seed, 32, hmac_data, 64, hmac_out, &hmac_len);

  // populate the public outputs with the age_over_18 and the computed pseudonym
  // also include the verifier id and context for the pseudonym
  public_outputs[0] = test::eudi_age_over_18;
  memcpy(public_outputs[0].cbor_value, over_18_val, over_18_len);
  public_outputs[0].cbor_value_len = over_18_len;

  public_outputs[1] = test::eudi_pairwise_pseudonym;
  public_outputs[1].cbor_value[0] = 0x58; // CBOR byte string (32 bytes)
  public_outputs[1].cbor_value[1] = 0x20;
  memcpy(&public_outputs[1].cbor_value[2], hmac_out, 32);
  public_outputs[1].cbor_value_len = 34;
  memcpy(public_outputs[1].verifier_id, kVerifierId, 32);
  memcpy(public_outputs[1].ppid_context, kPpidContext, 32);
}

typedef struct {
  const char* test_name;
  RequestedAttribute claims[1];
  const MdocTests* mdoc;
} Claims;

typedef struct {
  const char* test_name;
  RequestedAttribute claims[2];
  const MdocTests* mdoc;
} TwoClaims;

TEST_F(MdocZKTest, one_claim) {
  const Claims tests[] = {
      {"+18-mdoc[0]", {test::age_over_18}, &mdoc_tests[0]},
      {"+18-mdoc[1]", {test::age_over_18}, &mdoc_tests[1]},
      {"+18-mdoc[2]", {test::age_over_18}, &mdoc_tests[2]},
      {"+18-mdoc[9]", {test::europa_age_over_18}, &mdoc_tests[9]},
      {"familyname_mustermann-mdoc[3]",
       {test::familyname_mustermann},
       &mdoc_tests[3]},
      {"birthdate_1971_09_01-mdoc[3]",
       {test::birthdate_1971_09_01},
       &mdoc_tests[3]},
      {"height_175-mdoc[3]", {test::height_175}, &mdoc_tests[3]},
      // Test Google IDPass which uses a different docType.
      {"birthdate_1998_09_04-idpass-mdoc[4]",
       {test::birthdate_1998_09_04},
       &mdoc_tests[4]},
      // Website explainer example.
      {"age_over_18-website-mdoc[5]", {test::age_over_18}, &mdoc_tests[5]},
      // Large mdoc from 2025-06-10.
      {"not_over_18-large-mdoc[6]", {test::not_over_18}, &mdoc_tests[6]},
      // Integer field.
      {"age_birth_year-mdoc[8]", {test::age_birth_year}, &mdoc_tests[8]},
      // AAMVA DHS_compliance field.
      {"DHS_compliance-mdoc[10]",
       {test::aamva_dhs_compliance},
       &mdoc_tests[10]},
      // Sparkasse Age Assurance test.
      {"Sparkasse_Age-mdoc[11]", {test::age_over_18}, &mdoc_tests[11]},
      // MT Prod test
      {"MT_Prod_Age_Over_18-mdoc[12]", {test::age_over_18}, &mdoc_tests[12]},
      {"MT_Prod_Age_Over_18-mdoc[14]", {test::age_over_18}, &mdoc_tests[14]},
      // AZ Prod test
      {"AZ_Prod_Age_Over_18-mdoc[13]", {test::age_over_18}, &mdoc_tests[13]},
      // EUAV order tests
      {"EUAV_Age_Over_18-mdoc[15]", {test::age_over_18}, &mdoc_tests[15]},
      {"EUAV_Age_Over_18-mdoc[16]", {test::age_over_18}, &mdoc_tests[16]},
      {"EUAV_Age_Over_18-mdoc[17]", {test::age_over_18}, &mdoc_tests[17]},
      {"EUAV_Age_Over_18-mdoc[18]", {test::age_over_18}, &mdoc_tests[18]},
      {"EUAV_Age_Over_18-mdoc[19]", {test::age_over_18}, &mdoc_tests[19]},
      {"EUAV_Age_Over_18-mdoc[20]", {test::age_over_18}, &mdoc_tests[20]},
      {"EUAV_Age_Over_18-mdoc[21]", {test::age_over_18}, &mdoc_tests[21]},
      {"EUAV_Age_Over_18-mdoc[22]", {test::age_over_18}, &mdoc_tests[22]},
      {"EUAV_Age_Over_18-mdoc[23]", {test::age_over_18}, &mdoc_tests[23]},
      {"EUAV_Age_Over_18-mdoc[24]", {test::age_over_18}, &mdoc_tests[24]},
      {"Aadhaar_age_above18-mdoc[25]", {test::age_above18}, &mdoc_tests[25]},
  };

  for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
    run_test(tests[i].test_name, 1, tests[i].claims, tests[i].mdoc);
  }
}

TEST_F(MdocZKTest, long_attribute) {
  uint8_t* zkproof;
  size_t proof_len;
  RequestedAttribute attrs[1] = {test::age_over_18};
  auto test = &mdoc_tests[0];
  {
    log(INFO, "starting prover");
    MdocProverErrorCode ret = run_mdoc_prover(
        circuit1_, circuit_len1_, test->mdoc, test->mdoc_size,
        test->pkx.as_pointer, test->pky.as_pointer, test->transcript,
        test->transcript_size, attrs, 1, (const char*)test->now, &zkproof,
        &proof_len, &kZkSpecs[0]);
    EXPECT_EQ(ret, MDOC_PROVER_SUCCESS);
  }

  // Attr is too long.
  RequestedAttribute long_attr[1] = {
      {.namespace_id = {'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1', '8', '0',
                        '1', '3', '.', '5', '.', '1'},
       .id = {'a', 'g', 'e', '_', 'o', 'v', 'e', 'r', '_', '1', '8',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'},
       .cbor_value = {0xf5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
       .namespace_len = 17,
       .id_len = 32,
       .cbor_value_len = 64}};

  MdocVerifierErrorCode ret = run_mdoc_verifier(
      circuit1_, circuit_len1_, test->pkx.as_pointer, test->pky.as_pointer,
      test->transcript, test->transcript_size, long_attr, 1,
      (const char*)test->now, zkproof, proof_len, test->doc_type, &kZkSpecs[0]);
  EXPECT_EQ(ret, MDOC_VERIFIER_INVALID_CBOR);
  free(zkproof);
}

TEST_F(MdocZKTest, two_claims) {
  const TwoClaims two_tests[] = {
      {
          "18+,familyname_mustermann-mdoc[3]",
          {
              test::age_over_18,
              test::familyname_mustermann,
          },
          &mdoc_tests[3],
      },
      {
          "18+,birthdate_1971_09_01-mdoc[3]",
          {
              test::age_over_18,
              test::birthdate_1971_09_01,
          },
          &mdoc_tests[3],
      },
      {
          "height175,issue_date_2024-03-15-mdoc[3]",
          {
              test::height_175,
              test::issue_date_2024_03_15,
          },
          &mdoc_tests[3],
      },
      {
          "birthdate_1968_04_27,issue_date_2025-07-21T04:00:00Z-mdoc[8]",
          {
              test::birthdate_1968_04_27,
              test::issue_date_2025_07_21,
          },
          &mdoc_tests[7],
      },
  };

  for (size_t i = 0; i < sizeof(two_tests) / sizeof(two_tests[0]); ++i) {
    run_test(two_tests[i].test_name, 2, two_tests[i].claims, two_tests[i].mdoc);
  }
}

TEST_F(MdocZKTest, wrong_witness) {
  const Claims fail_tests[] = {
      {"fail-not_over_18-mdoc[0]", {test::not_over_18}, &mdoc_tests[0]},
      {"fail-not_over_18-mdoc[1]", {test::not_over_18}, &mdoc_tests[1]},
      {"fail-not_over_18-mdoc[2]", {test::not_over_18}, &mdoc_tests[2]},
      {
          "fail-birthdate_1971_09_01-mdoc[3]",
          {RequestedAttribute(
              {.namespace_id = {'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1',
                                '8', '0', '1', '3', '.', '5', '.', '1'},
               .id = {'b', 'i', 'r', 't', 'h', '_', 'd', 'a', 't', 'e'},
               .cbor_value = {0xD9, 0x03, 0xEC, 0x6A, '0', '9', '7', '1', '-',
                              '0', '9', '-', '0', '1'},
               .namespace_len = 17,
               .id_len = 10,
               .cbor_value_len = 14})},
          &mdoc_tests[3],
      },
      {
          "fail-birthdate_1871_09_01-mdoc[3]",
          {RequestedAttribute(
              {.namespace_id = {'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1',
                                '8', '0', '1', '3', '.', '5', '.', '1'},
               .id = {'b', 'i', 'r', 't', 'h', '_', 'd', 'a', 't', 'e'},
               .cbor_value = {0xD9, 0x03, 0xEC, 0x6A, '1', '8', '7', '1', '-',
                              '0', '9', '-', '0', '1'},
               .namespace_len = 17,
               .id_len = 10,
               .cbor_value_len = 14})},
          &mdoc_tests[3],
      },
      {
          "fail-birthdate_1971_09_01-mdoc[3]",
          {RequestedAttribute(
              {.namespace_id = {'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1',
                                '8', '0', '1', '3', '.', '5', '.', '1'},
               .id = {'b', 'i', 'r', 't', 'h', '_', 'd', 'a', 't', 'e'},
               .cbor_value = {0xD9, 0x03, 0xEC, 0x6A, '1', '9', '7', '1', '-',
                              '0', '9', '-', '0', '1', '0'},
               .namespace_len = 17,
               .id_len = 10,
               .cbor_value_len = 15})},
          &mdoc_tests[3],
      },
  };

  for (size_t i = 0; i < sizeof(fail_tests) / sizeof(fail_tests[0]); ++i) {
    run_test(fail_tests[i].test_name, 1, fail_tests[i].claims,
             fail_tests[i].mdoc, MDOC_PROVER_GENERAL_FAILURE);
  }
}

TEST_F(MdocZKTest, bad_arguments) {
  constexpr int num_attrs = 1;
  const ZkSpecStruct& zk_spec_1 = kZkSpecs[0];
  RequestedAttribute attrs[num_attrs] = {
      test::age_over_18,
  };
  uint8_t tr[100] = {0};
  uint8_t zkproof[30000] = {0};
  uint8_t circuit[60000] = {0};
  uint8_t mdoc[60000] = {0};
  const char* pk = "0x15";
  const char* pk2 = "bad_pk";
  const char* now = "2023-11-02T09:00:00Z";
  size_t proof_len;
  // ZStd encoding for "hello".
  uint8_t bad_circuit[50001] = {0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x05, 0x29,
                                0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f};

  // Invalid arguments to generate_circuit.
  size_t circuit_len;
  EXPECT_EQ(generate_circuit(nullptr, (uint8_t**)&circuit, &circuit_len),
            CIRCUIT_GENERATION_NULL_INPUT);
  EXPECT_EQ(generate_circuit(&zk_spec_1, nullptr, &circuit_len),
            CIRCUIT_GENERATION_NULL_INPUT);
  EXPECT_EQ(generate_circuit(&zk_spec_1, (uint8_t**)&circuit, nullptr),
            CIRCUIT_GENERATION_NULL_INPUT);

  // Basic prover tests that pass in a null ptr.
  EXPECT_EQ(run_mdoc_prover(nullptr, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            pk, tr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t**)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), nullptr, sizeof(mdoc), pk,
                            pk, tr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t**)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc),
                            nullptr, pk, tr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t**)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            nullptr, tr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t**)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            pk, nullptr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t**)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            pk, tr, sizeof(tr), nullptr, num_attrs, now,
                            (uint8_t**)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            pk, tr, sizeof(tr), attrs, num_attrs, nullptr,
                            (uint8_t**)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            pk, tr, sizeof(tr), attrs, num_attrs, now, nullptr,
                            &proof_len, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            pk, tr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t**)&zkproof, nullptr, &zk_spec_1),
            MDOC_PROVER_NULL_INPUT);
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            pk, tr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t**)&zkproof, &proof_len, nullptr),
            MDOC_PROVER_NULL_INPUT);

  // Invalid pk.
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk2,
                            pk, tr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t**)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_INVALID_INPUT);

  // Invalid circuit.
  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            pk, tr, sizeof(tr), attrs, num_attrs, now,
                            (uint8_t**)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_CIRCUIT_PARSING_FAILURE);
  EXPECT_EQ(
      run_mdoc_prover(bad_circuit, sizeof(bad_circuit), mdoc, sizeof(mdoc), pk,
                      pk, tr, sizeof(tr), attrs, num_attrs, now,
                      (uint8_t**)&zkproof, &proof_len, &zk_spec_1),
      MDOC_PROVER_CIRCUIT_PARSING_FAILURE);

  // Invalid attributes, two different namespaces.
  RequestedAttribute attrs2[2] = {test::age_over_18,
                                  test::aamva_name_suffix_mr};

  EXPECT_EQ(run_mdoc_prover(circuit, sizeof(circuit), mdoc, sizeof(mdoc), pk,
                            pk, tr, sizeof(tr), attrs2, 2, now,
                            (uint8_t**)&zkproof, &proof_len, &zk_spec_1),
            MDOC_PROVER_INVALID_INPUT);
  EXPECT_EQ(run_mdoc_verifier(circuit1_, circuit_len1_, pk, pk, tr, sizeof(tr),
                              attrs2, 2, now, zkproof, 100, kDefaultDocType,
                              &zk_spec_1),
            MDOC_VERIFIER_INVALID_INPUT);

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

  RequestedAttribute attrs_prefix[1] = {RequestedAttribute(
      {.namespace_id = {'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1', '8', '0',
                        '1', '3', '.', '5', '.', '1'},
       .id = {'b', 'i', 'r', 't', 'h', '_', 'd', 'a', 't', 'e'},
       .cbor_value = {0xD9, 0x03, 0xEC, 0x6A, '1', '9', '7', '1', '-', '0', '9',
                      '-', '0'},
       .namespace_len = 17,
       .id_len = 10,
       .cbor_value_len = 13})};
  EXPECT_EQ(run_mdoc_verifier(circuit, sizeof(circuit), pk, pk, tr, sizeof(tr),
                              attrs_prefix, 1, now, zkproof, sizeof(zkproof),
                              kDefaultDocType, &zk_spec_1),
            MDOC_VERIFIER_INVALID_CBOR);

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
  EXPECT_EQ(
      circuit_id(id, circuit1_, circuit_len1_, (const ZkSpecStruct*)nullptr),
      0);
  EXPECT_EQ(circuit_id(id, circuit1_, 10, &zk_spec_1), 0);
  EXPECT_EQ(circuit_id(id, circuit1_, circuit_len1_ - 8, &zk_spec_1), 0);
}

TEST_F(MdocZKTest, attr_mismatch) {
  uint8_t* zkproof;
  size_t proof_len;
  constexpr int num_attrs = 2;
  const ZkSpecStruct& zk_spec_2 = kZkSpecs[1];
  RequestedAttribute attrs[num_attrs] = {test::age_over_18, test::age_over_18};
  const struct MdocTests* test = &mdoc_tests[0];

  {
    MdocProverErrorCode ret = run_mdoc_prover(
        circuit2_, circuit_len2_, test->mdoc, test->mdoc_size,
        test->pkx.as_pointer, test->pky.as_pointer, test->transcript,
        test->transcript_size, attrs, num_attrs, (const char*)test->now,
        &zkproof, &proof_len, &zk_spec_2);
    EXPECT_EQ(ret, MDOC_PROVER_SUCCESS);
  }
  {
    MdocVerifierErrorCode ret = run_mdoc_verifier(
        circuit2_, circuit_len2_, test->pkx.as_pointer, test->pky.as_pointer,
        test->transcript, test->transcript_size, attrs, num_attrs - 1,
        (const char*)test->now, zkproof, proof_len, kDefaultDocType,
        &zk_spec_2);
    EXPECT_EQ(ret, MDOC_VERIFIER_ATTRIBUTE_NUMBER_MISMATCH);
  }
  free(zkproof);
}

TEST_F(MdocZKTest, ppid_generation_circuit) {
  set_log_level(INFO);
  constexpr int num_attrs = 2;
  const ZkSpecStruct& zk_spec = kZkSpecs[1]; // 2-attr circuit
  const struct MdocTests *test = &mdoc_tests[26]; // mdoc with a pseudonym seed

  // =====================================================================
  // WALLET
  // =====================================================================
  // The wallet reads the over_18 and pseudonym_seed from its local mdoc
  // and prepares the public_outputs array (copying the over_18 attribute,
  // and calculating the HMAC for the pairwise_pseudonym). The public_outputs
  // also contain the verifier_id and ppid_context, for the verifier to check.
  RequestedAttribute public_outputs[num_attrs];
  SetupPpidTestOutputs(test->mdoc, test->mdoc_size, public_outputs);

  size_t proof_len;
  uint8_t *zkproof = nullptr;

  // Wallet calls the prover
  {
    MdocProverErrorCode ret = run_mdoc_prover(
        circuit2_, circuit_len2_, test->mdoc, test->mdoc_size,
        test->pkx.as_pointer, test->pky.as_pointer, test->transcript,
        test->transcript_size, public_outputs, num_attrs,
        (const char *)test->now, &zkproof, &proof_len, &zk_spec);
    EXPECT_EQ(ret, MDOC_PROVER_SUCCESS);
  }

  // =====================================================================
  // VERIFIER
  // =====================================================================
  // The verifier receives the public outputs and the zkproof
  // from the wallet. It verifies the proof.
  {
    MdocVerifierErrorCode ret = run_mdoc_verifier(
        circuit2_, circuit_len2_, test->pkx.as_pointer, test->pky.as_pointer,
        test->transcript, test->transcript_size, public_outputs, num_attrs,
        (const char *)test->now, zkproof, proof_len, test->doc_type, &zk_spec);
    EXPECT_EQ(ret, MDOC_VERIFIER_SUCCESS);
  }

  // Final check that the public outputs are what we expect.

  // Expected over_18 should be 0xf5 (CBOR True)
  EXPECT_EQ(public_outputs[0].cbor_value_len, 1);
  EXPECT_EQ(public_outputs[0].cbor_value[0], 0xf5);

  // Independently verify the HMAC value
  // Note: in a real implementation, the verifier doesn't know the seed,
  // it just uses the PPID value directly for its purposes. But for this test,
  // we are verifying the prover's math and output.
  EXPECT_EQ(public_outputs[1].cbor_value_len, 34);
  EXPECT_EQ(public_outputs[1].cbor_value[0], 0x58);
  EXPECT_EQ(public_outputs[1].cbor_value[1], 0x20);

  // We check it against an independently generated HMAC using the hardcoded
  // seed from the test vector
  const uint8_t expected_seed[32] = {
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11,
      0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22,
      0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22};
  uint8_t expected_hmac_out[32];
  unsigned int expected_hmac_len = 32;

  int expected_hmac_data_size = 64;
  uint8_t expected_hmac_data[64];
  memcpy(expected_hmac_data, kVerifierId, 32);
  memcpy(expected_hmac_data + 32, kPpidContext, 32);
  HMAC(EVP_sha256(), expected_seed, 32, expected_hmac_data, 64, expected_hmac_out,
       &expected_hmac_len);

  EXPECT_EQ(memcmp(&public_outputs[1].cbor_value[2], expected_hmac_out, 32), 0);

  free(zkproof);
}

TEST_F(MdocZKTest, bad_proofs) {
  set_log_level(ERROR);
  constexpr int num_attrs = 1;
  const ZkSpecStruct& zk_spec_1 = kZkSpecs[0];
  RequestedAttribute attrs[num_attrs] = {test::age_over_18};
  const struct MdocTests* test = &mdoc_tests[0];

  constexpr size_t kMaxProofLen = 100000;
  uint8_t zkproof[kMaxProofLen];
  SecureRandomEngine rng;
  rng.bytes(zkproof, sizeof(zkproof));
  for (size_t proof_len = 0; proof_len < kMaxProofLen; proof_len += 1000) {
    MdocVerifierErrorCode ret = run_mdoc_verifier(
        circuit1_, circuit_len1_, test->pkx.as_pointer, test->pky.as_pointer,
        test->transcript, test->transcript_size, attrs, num_attrs,
        (const char*)test->now, zkproof, proof_len, kDefaultDocType,
        &zk_spec_1);
    EXPECT_NE(ret, MDOC_VERIFIER_SUCCESS);
  }
}

TEST(CircuitGenerationTest, attempt_to_generate_old_circuit) {
  set_log_level(ERROR);
  constexpr int num_attrs = 1;

  // Find the smallest version of the circuit for the given number of
  // attributes.
  const ZkSpecStruct* old_zk_spec = nullptr;
  int num_circuits = 0;
  for (int i = 0; i < kNumZkSpecs; ++i) {
    if (kZkSpecs[i].num_attributes == num_attrs) {
      num_circuits++;
      if (old_zk_spec == nullptr ||
          kZkSpecs[i].version < old_zk_spec->version) {
        old_zk_spec = &kZkSpecs[i];
      }
    }
  }

  EXPECT_GE(num_circuits, 1);
  if (num_circuits == 1) {
    return;  // No old circuit to test against, it's OK to skip this test.
  }

  static uint8_t* circuit = nullptr;
  static size_t circuit_len;
  EXPECT_EQ(generate_circuit(old_zk_spec, &circuit, &circuit_len),
            CIRCUIT_GENERATION_INVALID_ZK_SPEC_VERSION);
}

TEST(CborValidate, ValidInputs) {
  // Integer 0
  EXPECT_TRUE(proofs::cbor_validate((const uint8_t[]){0x00}, 1));
  // Integer 1
  EXPECT_TRUE(proofs::cbor_validate((const uint8_t[]){0x01}, 1));
  // Integer -1
  EXPECT_TRUE(proofs::cbor_validate((const uint8_t[]){0x20}, 1));
  // Boolean True
  EXPECT_TRUE(proofs::cbor_validate((const uint8_t[]){0xF5}, 1));
  // Boolean False
  EXPECT_TRUE(proofs::cbor_validate((const uint8_t[]){0xF4}, 1));
  // Empty String
  EXPECT_TRUE(proofs::cbor_validate((const uint8_t[]){0x60}, 1));
  // String "a"
  EXPECT_TRUE(proofs::cbor_validate((const uint8_t[]){0x61, 'a'}, 2));
  // Empty Bytes
  EXPECT_TRUE(proofs::cbor_validate((const uint8_t[]){0x40}, 1));
  // Bytes 0x01
  EXPECT_TRUE(proofs::cbor_validate((const uint8_t[]){0x41, 0x01}, 2));

  // Fulldate: Tag 1004 (D9 03 EC) + String (6A) + 10 bytes -> 14 bytes
  std::vector<uint8_t> fulldate = {0xD9, 0x03, 0xEC, 0x6A};
  fulldate.insert(fulldate.end(), 10, '0');
  EXPECT_EQ(fulldate.size(), 14);
  EXPECT_TRUE(proofs::cbor_validate(fulldate.data(), fulldate.size()));

  // Tdate: Tag 0 (C0) + String (74, len 20) + 20 bytes -> 22 bytes
  std::vector<uint8_t> tdate = {0xC0, 0x74};
  tdate.insert(tdate.end(), 20, '0');
  EXPECT_EQ(tdate.size(), 22);
  EXPECT_TRUE(proofs::cbor_validate(tdate.data(), tdate.size()));
}

TEST(CborValidate, InvalidInputs) {
  // Null/Empty
  EXPECT_FALSE(proofs::cbor_validate(nullptr, 0));

  // Array (not allowed)
  EXPECT_FALSE(proofs::cbor_validate((const uint8_t[]){0x80}, 1));
  // Map (not allowed)
  EXPECT_FALSE(proofs::cbor_validate((const uint8_t[]){0xA0}, 1));

  // Malformed length (String len 1 but missing data)
  EXPECT_FALSE(proofs::cbor_validate((const uint8_t[]){0x61}, 1));

  // Boolean, wrong length
  EXPECT_FALSE(proofs::cbor_validate((const uint8_t[]){0xF5, 0xF5}, 2));

  // Wrong Tag (e.g. Tag 2)
  EXPECT_FALSE(proofs::cbor_validate((const uint8_t[]){0xC2, 0x40},
                                     2));  // Tag 2 + Bytes

  // Fulldate wrong length
  // 14 bytes expected. Try 13.
  std::vector<uint8_t> fulldate_wrong = {0xD9, 0x03, 0xEC,
                                         0x69};  // String len 9
  fulldate_wrong.insert(fulldate_wrong.end(), 9, '0');
  EXPECT_EQ(fulldate_wrong.size(), 13);
  EXPECT_FALSE(
      proofs::cbor_validate(fulldate_wrong.data(), fulldate_wrong.size()));
  // Try 15 bytes
  fulldate_wrong.insert(fulldate_wrong.end(), 2, '0');
  EXPECT_FALSE(
      proofs::cbor_validate(fulldate_wrong.data(), fulldate_wrong.size()));
  // Try 22 bytes
  fulldate_wrong.insert(fulldate_wrong.end(), 7, '0');
  EXPECT_FALSE(
      proofs::cbor_validate(fulldate_wrong.data(), fulldate_wrong.size()));

  // Fulldate inner type mismatch (Tag 1004 + Integer)
  EXPECT_FALSE(
      proofs::cbor_validate((const uint8_t[]){0xD9, 0x03, 0xEC, 0x00}, 4));

  // Tdate wrong length
  // 22 bytes expected. Try 21.
  std::vector<uint8_t> tdate_short = {0xC0, 0x73};  // String len 19
  tdate_short.insert(tdate_short.end(), 19, '0');
  EXPECT_EQ(tdate_short.size(), 21);
  EXPECT_FALSE(proofs::cbor_validate(tdate_short.data(), tdate_short.size()));

  // Tdate inner type mismatch (Tag 0 + Integer)
  EXPECT_FALSE(proofs::cbor_validate((const uint8_t[]){0xC0, 0x00}, 2));
}

// ============================ Benchmarks ====================================
static const Claims benchmark_claim = {
    "benchmark",
    {test::age_over_18},
    &mdoc_tests[0],
};

void BM_MdocProver(benchmark::State& state) {
  set_log_level(ERROR);

  const ZkSpecStruct& zk_spec_1 = kZkSpecs[0];
  size_t circuit_len;
  uint8_t* circuit;
  EXPECT_EQ(generate_circuit(&zk_spec_1, &circuit, &circuit_len),
            CIRCUIT_GENERATION_SUCCESS);

  const RequestedAttribute* attrs = benchmark_claim.claims;
  const MdocTests* test = benchmark_claim.mdoc;
  size_t num_attrs = 1;
  const ZkSpecStruct zk_spec = kZkSpecs[0];

  for (auto _ : state) {
    uint8_t* zkproof;
    size_t proof_len;

    MdocProverErrorCode ret = run_mdoc_prover(
        circuit, circuit_len, test->mdoc, test->mdoc_size, test->pkx.as_pointer,
        test->pky.as_pointer, test->transcript, test->transcript_size, attrs,
        num_attrs, (const char*)test->now, &zkproof, &proof_len, &zk_spec);
    EXPECT_EQ(ret, MDOC_PROVER_SUCCESS);
    free(zkproof);
  }
}

BENCHMARK(BM_MdocProver);

void BM_MdocVerifier(benchmark::State& state) {
  set_log_level(ERROR);

  const ZkSpecStruct& zk_spec_1 = kZkSpecs[0];
  size_t circuit_len;
  uint8_t* circuit;
  EXPECT_EQ(generate_circuit(&zk_spec_1, &circuit, &circuit_len),
            CIRCUIT_GENERATION_SUCCESS);

  const RequestedAttribute* attrs = benchmark_claim.claims;
  const MdocTests* test = benchmark_claim.mdoc;
  size_t num_attrs = 1;
  const ZkSpecStruct zk_spec = kZkSpecs[0];

  uint8_t* zkproof;
  size_t proof_len;

  MdocProverErrorCode retp = run_mdoc_prover(
      circuit, circuit_len, test->mdoc, test->mdoc_size, test->pkx.as_pointer,
      test->pky.as_pointer, test->transcript, test->transcript_size, attrs,
      num_attrs, (const char*)test->now, &zkproof, &proof_len, &zk_spec);
  EXPECT_EQ(retp, MDOC_PROVER_SUCCESS);

  for (auto _ : state) {
    MdocVerifierErrorCode retv = run_mdoc_verifier(
        circuit, circuit_len, test->pkx.as_pointer, test->pky.as_pointer,
        test->transcript, test->transcript_size, attrs, num_attrs,
        (const char*)test->now, zkproof, proof_len, test->doc_type, &zk_spec);
    EXPECT_EQ(retv, MDOC_VERIFIER_SUCCESS);
  }

  free(zkproof);
}

TEST_F(MdocZKTest, ppid_generation_bad_seed) {
  set_log_level(INFO);
  constexpr int num_attrs = 2;
  const ZkSpecStruct& zk_spec = kZkSpecs[1];
  const struct MdocTests *test = &mdoc_tests[26];

  const uint8_t verifier_id[32] = {
    0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x40, 0x63, 0x6c, 0x69,
    0x65, 0x6e, 0x74, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
    0x63, 0x6f, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  const uint8_t ppid_context[32] = {
    0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  // switch a byte in the seed, breaking the signature on the mdoc
  std::vector<uint8_t> bad_mdoc(test->mdoc, test->mdoc + test->mdoc_size);
  const uint8_t target[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  auto it = std::search(bad_mdoc.begin(), bad_mdoc.end(), target, target + sizeof(target));
  EXPECT_NE(it, bad_mdoc.end());
  if (it != bad_mdoc.end()) {
    *it = 0x22;
  }

  ParsedMdoc pm;
  EXPECT_EQ(pm.parse_device_response(bad_mdoc.size(), bad_mdoc.data()), MDOC_PROVER_SUCCESS);

  const uint8_t *seed_val = nullptr;
  const uint8_t *over_18_val = nullptr;
  size_t over_18_len = 0;
  size_t seed_len = 0;

  EXPECT_TRUE(pm.extract_cbor_value("pseudonym_seed", &seed_val, &seed_len));
  EXPECT_TRUE(pm.extract_cbor_value("age_over_18", &over_18_val, &over_18_len));

  uint8_t seed[32];
  memcpy(seed, seed_val, 32);

  uint8_t hmac_data[64];
  memcpy(hmac_data, verifier_id, 32);
  memcpy(hmac_data + 32, ppid_context, 32);

  uint8_t hmac_out[32];
  unsigned int hmac_len = 32;
  HMAC(EVP_sha256(), seed, 32, hmac_data, 64, hmac_out, &hmac_len);

  RequestedAttribute public_outputs[num_attrs];

  public_outputs[0] = test::eudi_age_over_18;
  memcpy(public_outputs[0].cbor_value, over_18_val, over_18_len);
  public_outputs[0].cbor_value_len = over_18_len;

  public_outputs[1] = test::eudi_pairwise_pseudonym;
  public_outputs[1].cbor_value[0] = 0x58; // CBOR byte string (32 bytes)
  public_outputs[1].cbor_value[1] = 0x20;
  memcpy(&public_outputs[1].cbor_value[2], hmac_out, 32);
  public_outputs[1].cbor_value_len = 34;
  memcpy(public_outputs[1].verifier_id, verifier_id, 32);
  memcpy(public_outputs[1].ppid_context, ppid_context, 32);

  size_t proof_len;
  uint8_t *zkproof = nullptr;

  MdocProverErrorCode ret = run_mdoc_prover(
      circuit2_, circuit_len2_, bad_mdoc.data(), bad_mdoc.size(),
      test->pkx.as_pointer, test->pky.as_pointer, test->transcript,
      test->transcript_size, public_outputs, num_attrs,
      (const char *)test->now, &zkproof, &proof_len, &zk_spec);
  EXPECT_NE(ret, MDOC_PROVER_SUCCESS);
  
  if (zkproof != nullptr) free(zkproof);
}

TEST_F(MdocZKTest, ppid_generation_bad_public_output_before_prover) {
  set_log_level(INFO);
  constexpr int num_attrs = 2;
  const ZkSpecStruct& zk_spec = kZkSpecs[1];
  const struct MdocTests *test = &mdoc_tests[26];

  RequestedAttribute public_outputs[num_attrs];
  SetupPpidTestOutputs(test->mdoc, test->mdoc_size, public_outputs);

  // Modify the HMAC output passed to the prover
  public_outputs[1].cbor_value[2] ^= 1;

  size_t proof_len;
  uint8_t *zkproof = nullptr;

  MdocProverErrorCode ret = run_mdoc_prover(
      circuit2_, circuit_len2_, test->mdoc, test->mdoc_size,
      test->pkx.as_pointer, test->pky.as_pointer, test->transcript,
      test->transcript_size, public_outputs, num_attrs,
      (const char *)test->now, &zkproof, &proof_len, &zk_spec);
  EXPECT_NE(ret, MDOC_PROVER_SUCCESS);
  
  if (zkproof != nullptr) free(zkproof);
}

TEST_F(MdocZKTest, ppid_generation_bad_public_output_after_prover) {
  set_log_level(INFO);
  constexpr int num_attrs = 2;
  const ZkSpecStruct& zk_spec = kZkSpecs[1];
  const struct MdocTests *test = &mdoc_tests[26];

  RequestedAttribute public_outputs[num_attrs];
  SetupPpidTestOutputs(test->mdoc, test->mdoc_size, public_outputs);

  size_t proof_len;
  uint8_t *zkproof = nullptr;

  MdocProverErrorCode ret = run_mdoc_prover(
      circuit2_, circuit_len2_, test->mdoc, test->mdoc_size,
      test->pkx.as_pointer, test->pky.as_pointer, test->transcript,
      test->transcript_size, public_outputs, num_attrs,
      (const char *)test->now, &zkproof, &proof_len, &zk_spec);
  EXPECT_EQ(ret, MDOC_PROVER_SUCCESS);
  
  // Modify the HMAC output passed to the verifier
  // (simulating a malicious wallet trying to assert a different PPID)
  public_outputs[1].cbor_value[2] ^= 1;

  MdocVerifierErrorCode retv = run_mdoc_verifier(
      circuit2_, circuit_len2_, test->pkx.as_pointer, test->pky.as_pointer,
      test->transcript, test->transcript_size, public_outputs, num_attrs,
      (const char *)test->now, zkproof, proof_len, test->doc_type, &zk_spec);
  EXPECT_NE(retv, MDOC_VERIFIER_SUCCESS);

  if (zkproof != nullptr) free(zkproof);
}

TEST_F(MdocZKTest, ppid_generation_bad_verifier_id) {
  set_log_level(INFO);
  constexpr int num_attrs = 2;
  const ZkSpecStruct& zk_spec = kZkSpecs[1];
  const struct MdocTests *test = &mdoc_tests[26];

  RequestedAttribute public_outputs[num_attrs];
  SetupPpidTestOutputs(test->mdoc, test->mdoc_size, public_outputs);

  size_t proof_len;
  uint8_t *zkproof = nullptr;

  MdocProverErrorCode ret = run_mdoc_prover(
      circuit2_, circuit_len2_, test->mdoc, test->mdoc_size,
      test->pkx.as_pointer, test->pky.as_pointer, test->transcript,
      test->transcript_size, public_outputs, num_attrs,
      (const char *)test->now, &zkproof, &proof_len, &zk_spec);
  EXPECT_EQ(ret, MDOC_PROVER_SUCCESS);

  // Modify verifier ID
  // (simulating the case where the verifier ID seen by the wallet doesn't
  // match the verifier ID used by the verifier)
  public_outputs[1].verifier_id[0] ^= 1;

  MdocVerifierErrorCode retv = run_mdoc_verifier(
      circuit2_, circuit_len2_, test->pkx.as_pointer, test->pky.as_pointer,
      test->transcript, test->transcript_size, public_outputs, num_attrs,
      (const char *)test->now, zkproof, proof_len, test->doc_type, &zk_spec);
  EXPECT_NE(retv, MDOC_VERIFIER_SUCCESS);

  if (zkproof != nullptr) free(zkproof);
}

TEST_F(MdocZKTest, ppid_generation_bad_context) {
  set_log_level(INFO);
  constexpr int num_attrs = 2;
  const ZkSpecStruct& zk_spec = kZkSpecs[1];
  const struct MdocTests *test = &mdoc_tests[26];

  RequestedAttribute public_outputs[num_attrs];
  SetupPpidTestOutputs(test->mdoc, test->mdoc_size, public_outputs);

  size_t proof_len;
  uint8_t *zkproof = nullptr;

  MdocProverErrorCode ret = run_mdoc_prover(
      circuit2_, circuit_len2_, test->mdoc, test->mdoc_size,
      test->pkx.as_pointer, test->pky.as_pointer, test->transcript,
      test->transcript_size, public_outputs, num_attrs,
      (const char *)test->now, &zkproof, &proof_len, &zk_spec);
  EXPECT_EQ(ret, MDOC_PROVER_SUCCESS);

  // Modify context
  // (simulating the case where the context seen by the wallet doesn't match
  // the context used by the verifier)
  public_outputs[1].ppid_context[0] ^= 1;

  MdocVerifierErrorCode retv = run_mdoc_verifier(
      circuit2_, circuit_len2_, test->pkx.as_pointer, test->pky.as_pointer,
      test->transcript, test->transcript_size, public_outputs, num_attrs,
      (const char *)test->now, zkproof, proof_len, test->doc_type, &zk_spec);
  EXPECT_NE(retv, MDOC_VERIFIER_SUCCESS);

  if (zkproof != nullptr) free(zkproof);
}

BENCHMARK(BM_MdocVerifier);

}  // namespace
}  // namespace proofs
