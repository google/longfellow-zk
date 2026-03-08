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

#include "circuits/mdoc/mdoc_signature.h"

#include <stdint.h>

#include <cstddef>
#include <memory>
#include <vector>

#include "algebra/fp_p128.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/mac/mac_reference.h"
#include "circuits/mdoc/mdoc_examples.h"
#include "circuits/mdoc/mdoc_hash.h"
#include "circuits/mdoc/mdoc_test_attributes.h"
#include "circuits/mdoc/mdoc_witness.h"
#include "circuits/mdoc/mdoc_zk.h"
#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "random/secure_random_engine.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "util/panic.h"
#include "zk/zk_testing.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
/*
For Mdoc, we only need to be testing on P256, so we can
declare these types globally.
*/

// For now, mac is chosen here.
using gf2k = GF2_128<>::Elt;

TEST(mdoc, mdoc_signature_test) {
  using MdocSw = MdocSignatureWitness<P256, Fp256Scalar>;
  using Elt = Fp256Base::Elt;

  set_log_level(INFO);

  std::unique_ptr<Circuit<Fp256Base>> CIRCUIT;

  // ======== compile time =========================
  {
    using CompilerBackend = CompilerBackend<Fp256Base>;
    using LogicCircuit = Logic<Fp256Base, CompilerBackend>;
    using EltW = LogicCircuit::EltW;
    using v128 = LogicCircuit::v128;
    using MdocSig = MdocSignature<LogicCircuit, Fp256Base, P256>;
    QuadCircuit<Fp256Base> Q(p256_base);
    const CompilerBackend cbk(&Q);
    const LogicCircuit LC(&cbk, p256_base);

    MdocSig mdoc_sig(LC, p256, n256_order);

    EltW pkX = LC.eltw_input(), pkY = LC.eltw_input(), htr = LC.eltw_input();
    v128 emac[2] = {LC.vinput<128>(), LC.vinput<128>()};
    v128 xmac[2] = {LC.vinput<128>(), LC.vinput<128>()};
    v128 ymac[2] = {LC.vinput<128>(), LC.vinput<128>()};

    v128 a_v = LC.vinput<128>();
    Q.private_input();

    MdocSig::Witness vwc;
    vwc.input(LC);

    mdoc_sig.assert_signatures(pkX, pkY, htr, emac, xmac, ymac, a_v, vwc);

    CIRCUIT = Q.mkcircuit(/*nc=*/1);
    dump_info("mdoc signature", Q);
    log(INFO, "Compile done");
  }

  // ======== Witness
  // Generate a witness from the mdoc data structure to remain close
  // to the application use case.
  GF2_128<> gf;
  gf2k ap[6], mac[6];
  gf2k av = gf.of_scalar_field(2983471870111);
  Elt pkX, pkY;
  MdocSw sw(p256, p256_scalar, gf);

  {
    constexpr size_t t_ind = 2;
    const uint8_t* mdoc = mdoc_tests[t_ind].mdoc;
    pkX = p256_base.of_string(mdoc_tests[t_ind].pkx);
    pkY = p256_base.of_string(mdoc_tests[t_ind].pky);
    MdocProverErrorCode ok = sw.compute_witness(
        pkX, pkY, mdoc, mdoc_tests[t_ind].mdoc_size,
        mdoc_tests[t_ind].transcript, mdoc_tests[t_ind].transcript_size);

    check(ok == MDOC_PROVER_SUCCESS, "Could not compute signature witness");

    MACReference<GF2_128<>> mac_ref;

    // Should be chosen by prover and added to commitment.
    SecureRandomEngine rng;
    mac_ref.sample(ap, 6, &rng);

    // This value is chosen after the prover commits.
    uint8_t buf[Fp256Base::kBytes];

    Elt tt[3] = {sw.e_, sw.dpkx_, sw.dpky_};
    for (size_t i = 0; i < 3; ++i) {
      p256_base.to_bytes_field(buf, tt[i]);
      sw.macs_[i].compute_witness(&ap[2 * i], buf);
      mac_ref.compute(&mac[2 * i], av, &ap[2 * i], buf);
    }

    log(INFO, "Witness done");
  }

  // ========= Fill witness
  auto W = Dense<Fp256Base>(1, CIRCUIT->ninputs);
  auto pub = Dense<Fp256Base>(1, CIRCUIT->npub_in);
  DenseFiller<Fp256Base> filler(W);
  DenseFiller<Fp256Base> pub_filler(pub);

  filler.push_back(p256_base.one());
  pub_filler.push_back(p256_base.one());
  filler.push_back(pkX);
  pub_filler.push_back(pkX);
  filler.push_back(pkY);
  pub_filler.push_back(pkY);
  filler.push_back(sw.e2_);
  pub_filler.push_back(sw.e2_);

  for (size_t i = 0; i < 6; ++i) {
    fill_gf2k<GF2_128<>, Fp256Base>(mac[i], filler, p256_base);
    fill_gf2k<GF2_128<>, Fp256Base>(mac[i], pub_filler, p256_base);
  }

  fill_gf2k<GF2_128<>, Fp256Base>(av, filler, p256_base);
  fill_gf2k<GF2_128<>, Fp256Base>(av, pub_filler, p256_base);

  sw.fill_witness(filler);
  log(INFO, "Fill done");

  // =========== ZK test
  run2_test_zk(
      *CIRCUIT, W, pub, p256_base,
      p256_base.of_string("1126492241464102818735004576096902583730188404304894"
                          "08729223714171582664680802"), /* omega_x*/
      p256_base.of_string("8408799435854090769574046142781866056018216899718237"
                          "8749313018254450460212908"), /* omega_y */
      1ull << 31);
}

TEST(mdoc, mdoc_issuer_list_valid) {
  using Elt = Fp256Base::Elt;
  // Verify the two constraints on issuer lists.

  size_t sz = sizeof(kIssuerPKY) / sizeof(char*);
  std::vector<Elt> pkY(sz);
  for (size_t i = 0; i < sz; ++i) {
    Elt pkX = p256_base.of_string(kIssuerPKX[i]);
    pkY[i] = p256_base.of_string(kIssuerPKY[i]);
    EXPECT_TRUE(p256.is_on_curve(pkX, pkY[i]));
  }

  // n^2 test ok for small n.
  for (size_t i = 0; i < sz; ++i) {
    for (size_t j = i + 1; j < sz; ++j) {
      EXPECT_FALSE(pkY[i] == p256_base.negf(pkY[j]));
    }
  }
}

TEST(mdoc, mdoc_signature_test_vector_26) {
  using MdocSw = MdocSignatureWitness<P256, Fp256Scalar>;
  using Elt = Fp256Base::Elt;

  set_log_level(INFO);
  GF2_128<> gf;
  MdocSw sw(p256, p256_scalar, gf);

  const size_t t_ind = 26;
  const uint8_t* mdoc = mdoc_tests[t_ind].mdoc;
  Elt pkX = p256_base.of_string(mdoc_tests[t_ind].pkx);
  Elt pkY = p256_base.of_string(mdoc_tests[t_ind].pky);
  
  EXPECT_TRUE(p256.is_on_curve(pkX, pkY));
  
  MdocProverErrorCode ok = sw.compute_witness(
      pkX, pkY, mdoc, mdoc_tests[t_ind].mdoc_size,
      mdoc_tests[t_ind].transcript, mdoc_tests[t_ind].transcript_size);

  EXPECT_EQ(ok, MDOC_PROVER_SUCCESS);
}

TEST(mdoc, mdoc_signature_test_with_issuer_list) {
  using MdocSw = MdocSignatureWitness<P256, Fp256Scalar>;
  using Elt = Fp256Base::Elt;

  constexpr size_t MAX_ISSUERS = 50;
  set_log_level(INFO);

  std::unique_ptr<Circuit<Fp256Base>> CIRCUIT;

  // ======== compile time =========================
  {
    using CompilerBackend = CompilerBackend<Fp256Base>;
    using LogicCircuit = Logic<Fp256Base, CompilerBackend>;
    using EltW = LogicCircuit::EltW;
    using v128 = LogicCircuit::v128;
    using MdocSig = MdocSignature<LogicCircuit, Fp256Base, P256>;
    QuadCircuit<Fp256Base> Q(p256_base);
    const CompilerBackend cbk(&Q);
    const LogicCircuit LC(&cbk, p256_base);

    MdocSig mdoc_sig(LC, p256, n256_order);

    // public inputs
    EltW htr = LC.eltw_input();
    v128 emac[2] = {LC.vinput<128>(), LC.vinput<128>()};
    v128 xmac[2] = {LC.vinput<128>(), LC.vinput<128>()};
    v128 ymac[2] = {LC.vinput<128>(), LC.vinput<128>()};

    v128 a_v = LC.vinput<128>();
    EltW xlist[MAX_ISSUERS], ylist[MAX_ISSUERS];
    for (size_t i = 0; i < MAX_ISSUERS; ++i) {
      xlist[i] = LC.eltw_input();
    }
    for (size_t i = 0; i < MAX_ISSUERS; ++i) {
      ylist[i] = LC.eltw_input();
    }

    Q.private_input();
    EltW pkX = LC.eltw_input(), pkY = LC.eltw_input();
    MdocSig::Witness vwc;
    vwc.input(LC);

    mdoc_sig.assert_signatures_with_issuer_list(
        htr, emac, xmac, ymac, a_v, xlist, ylist, MAX_ISSUERS, pkX, pkY, vwc);

    CIRCUIT = Q.mkcircuit(/*nc=*/1);
    dump_info("mdoc signature_with_issuer", Q);
    log(INFO, "Compile done");
  }

  // ======== Witness
  // Generate a witness from the mdoc data structure to remain close
  // to the application use case.
  GF2_128<> gf;
  gf2k ap[6], mac[6];
  gf2k av = gf.of_scalar_field(2983471870111);
  Elt pkX, pkY;
  Elt issuerX[MAX_ISSUERS], issuerY[MAX_ISSUERS];
  MdocSw sw(p256, p256_scalar, gf);

  {
    constexpr size_t t_ind = 2;
    const uint8_t* mdoc = mdoc_tests[t_ind].mdoc;
    pkX = p256_base.of_string(mdoc_tests[t_ind].pkx);
    pkY = p256_base.of_string(mdoc_tests[t_ind].pky);
    MdocProverErrorCode ok = sw.compute_witness(
        pkX, pkY, mdoc, mdoc_tests[t_ind].mdoc_size,
        mdoc_tests[t_ind].transcript, mdoc_tests[t_ind].transcript_size);

    check(ok == MDOC_PROVER_SUCCESS, "Could not compute signature witness");

    MACReference<GF2_128<>> mac_ref;

    // Should be chosen by prover and added to commitment.
    SecureRandomEngine rng;
    mac_ref.sample(ap, 6, &rng);

    // This value is chosen after the prover commits.
    uint8_t buf[Fp256Base::kBytes];

    Elt tt[3] = {sw.e_, sw.dpkx_, sw.dpky_};
    for (size_t i = 0; i < 3; ++i) {
      p256_base.to_bytes_field(buf, tt[i]);
      sw.macs_[i].compute_witness(&ap[2 * i], buf);
      mac_ref.compute(&mac[2 * i], av, &ap[2 * i], buf);
    }

    // It is OK to repeat the issuers.
    size_t numIssuer = sizeof(kIssuerPKX) / sizeof(char*);
    for (size_t i = 0; i < MAX_ISSUERS; ++i) {
      issuerX[i] = p256_base.of_string(kIssuerPKX[i % numIssuer]);
      issuerY[i] = p256_base.of_string(kIssuerPKY[i % numIssuer]);
    }

    log(INFO, "Witness created");
  }

  // ========= Fill witness
  auto W = Dense<Fp256Base>(1, CIRCUIT->ninputs);
  auto pub = Dense<Fp256Base>(1, CIRCUIT->npub_in);
  DenseFiller<Fp256Base> filler(W);
  DenseFiller<Fp256Base> pub_filler(pub);

  filler.push_back(p256_base.one());
  pub_filler.push_back(p256_base.one());
  filler.push_back(sw.e2_);
  pub_filler.push_back(sw.e2_);

  for (size_t i = 0; i < 6; ++i) {
    fill_gf2k<GF2_128<>, Fp256Base>(mac[i], filler, p256_base);
    fill_gf2k<GF2_128<>, Fp256Base>(mac[i], pub_filler, p256_base);
  }

  fill_gf2k<GF2_128<>, Fp256Base>(av, filler, p256_base);
  fill_gf2k<GF2_128<>, Fp256Base>(av, pub_filler, p256_base);

  for (size_t i = 0; i < MAX_ISSUERS; ++i) {
    filler.push_back(issuerX[i]);
    pub_filler.push_back(issuerX[i]);
  }
  for (size_t i = 0; i < MAX_ISSUERS; ++i) {
    filler.push_back(issuerY[i]);
    pub_filler.push_back(issuerY[i]);
  }

  filler.push_back(pkX);
  filler.push_back(pkY);
  sw.fill_witness(filler);
  log(INFO, "Fill done");

  // =========== ZK test
  run2_test_zk(
      *CIRCUIT, W, pub, p256_base,
      p256_base.of_string("1126492241464102818735004576096902583730188404304894"
                          "08729223714171582664680802"), /* omega_x*/
      p256_base.of_string("8408799435854090769574046142781866056018216899718237"
                          "8749313018254450460212908"), /* omega_y */
      1ull << 31);
}

template <class Field>
void mdoc_hash_run(const typename Field::Elt& omega, uint64_t omega_order,
                   const Field& F, std::vector<RequestedAttribute> attrs) {
  using MdocHw = MdocHashWitness<P256, Field>;

  set_log_level(INFO);

  std::unique_ptr<Circuit<Field>> CIRCUIT;

  // ======== compile time =========================
  {
    using CompilerBackend = CompilerBackend<Field>;
    using LogicCircuit = Logic<Field, CompilerBackend>;
    using v8 = typename LogicCircuit::v8;
    using v256 = typename LogicCircuit::v256;
    using MdocHash = MdocHash<LogicCircuit, Field>;
    QuadCircuit<Field> Q(F);
    const CompilerBackend cbk(&Q);
    const LogicCircuit LC(&cbk, F);

    std::vector<typename MdocHash::OpenedAttribute> oa(attrs.size());
    MdocHash mdoc_hash(LC);
    for (size_t ai = 0; ai < attrs.size(); ++ai) {
      oa[ai].input(LC);
    }

    v8 now[20];
    for (size_t i = 0; i < 20; ++i) {
      now[i] = LC.template vinput<8>();
    }

    v8 verifier_id_len = LC.template vinput<8>();
    v8 ppid_context_len = LC.template vinput<8>();
    v8 verifier_id[32];
    v8 ppid_context[32];
    for (size_t i = 0; i < 32; ++i) verifier_id[i] = LC.template vinput<8>();
    for (size_t i = 0; i < 32; ++i) ppid_context[i] = LC.template vinput<8>();

    Q.private_input();
    v256 e = LC.template vinput<256>();
    v256 dpkx = LC.template vinput<256>();
    v256 dpky = LC.template vinput<256>();

    typename MdocHash::Witness vwc(attrs.size());
    vwc.input(LC);

    mdoc_hash.assert_valid_hash_mdoc(oa.data(), now, e, dpkx, dpky, vwc, false, verifier_id, ppid_context);

    CIRCUIT = Q.mkcircuit(/*nc=*/1);
    dump_info("mdoc hash and parse", Q);
    log(INFO, "Compile done");
  }

  // ======== Witness: use the large Canonical Playground example
  MdocHw hw(attrs.size(), p256, F);
  constexpr size_t t_ind = 3;
  const uint8_t* mdoc = mdoc_tests[t_ind].mdoc;

  MdocProverErrorCode ok = hw.compute_witness(
      mdoc, mdoc_tests[t_ind].mdoc_size, mdoc_tests[t_ind].transcript,
      mdoc_tests[t_ind].transcript_size, attrs.data(), attrs.size(),
      7 /* version */);

  check(ok == MDOC_PROVER_SUCCESS, "Could not compute hash witness");

  log(INFO, "Witness done");

  // ========= Fill witness
  auto W = Dense<Field>(1, CIRCUIT->ninputs);
  auto pub = Dense<Field>(1, CIRCUIT->npub_in);
  DenseFiller<Field> filler(W);
  DenseFiller<Field> pub_filler(pub);
  filler.push_back(F.one());
  pub_filler.push_back(F.one());

  for (size_t ai = 0; ai < attrs.size(); ++ai) {
    fill_attribute(filler, attrs[ai], F, 7 /* version */);
    fill_attribute(pub_filler, attrs[ai], F, 7 /* version */);
  }
  fill_bit_string(filler, mdoc_tests[t_ind].now, 20, 20, F);
  fill_bit_string(pub_filler, mdoc_tests[t_ind].now, 20, 20, F);

  filler.push_back(0, 8, F);
  pub_filler.push_back(0, 8, F);
  filler.push_back(0, 8, F);
  pub_filler.push_back(0, 8, F);
  uint8_t zeros[32] = {0};
  fill_bit_string(filler, zeros, 32, 32, F);
  fill_bit_string(pub_filler, zeros, 32, 32, F);
  fill_bit_string(filler, zeros, 32, 32, F);
  fill_bit_string(pub_filler, zeros, 32, 32, F);

  // Private inputs
  uint8_t buf[Fp256Base::kBytes];
  Fp256Base::Elt tt[3] = {hw.e_, hw.dpkx_, hw.dpky_};
  for (size_t i = 0; i < 3; ++i) {
    p256_base.to_bytes_field(buf, tt[i]);
    fill_bit_string(filler, buf, 32, 32, F);
  }

  hw.fill_witness(filler, 7);

  log(INFO, "Fill done");

  // =========== ZK prover

  run_test_zk<Field>(*CIRCUIT, W, pub, omega, omega_order, F);
}

TEST(mdoc, mdoc_hash_test_fp128) {
  std::vector<RequestedAttribute> oa;
  oa.push_back(test::age_over_18);

  static const Fp128<> Fg;
  mdoc_hash_run<Fp128<>>(
      Fg.of_string("164956748514267535023998284330560247862"), 1ull << 32, Fg,
      oa);
}

TEST(mdoc, mdoc_hash_test_fp128_2) {
  std::vector<RequestedAttribute> oa;
  oa.push_back(test::age_over_18);

  oa.push_back(test::familyname_mustermann);
  oa.shrink_to_fit();

  static const Fp128<> Fg;
  mdoc_hash_run<Fp128<>>(
      Fg.of_string("164956748514267535023998284330560247862"), 1ull << 32, Fg,
      oa);
}

}  // namespace
}  // namespace proofs
