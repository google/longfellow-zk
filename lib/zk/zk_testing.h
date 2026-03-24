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

#ifndef PRIVACY_PROOFS_ZK_LIB_ZK_ZK_TESTING_H_
#define PRIVACY_PROOFS_ZK_LIB_ZK_ZK_TESTING_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"
#include "gtest/gtest.h"

namespace proofs {

constexpr size_t kLigeroRate = 4;
constexpr size_t kLigeroNreq = 189;
constexpr size_t kVersion = 4;

// Runs a zk prover and verifier for a field that requires a field extension
// to perform the commitment.
template <class Field>
void run2_test_zk(const Circuit<Field>& circuit, Dense<Field>& W,
                  const Dense<Field>& pub, const Field& base,
                  const typename Field::Elt& root_x,
                  const typename Field::Elt& root_y, size_t root_order) {
  // Build the relevant algebra objects.
  using Field2 = Fp2<Field>;
  using Elt2 = typename Field2::Elt;
  using FftExtConvolutionFactory = FFTExtConvolutionFactory<Field, Field2>;
  using RSFactory = ReedSolomonFactory<Field, FftExtConvolutionFactory>;

  const Field2 base_2(base);
  const Elt2 omega{root_x, root_y};
  const FftExtConvolutionFactory fft(base, base_2, omega, root_order);
  const RSFactory rsf(fft, base);

  ZkProof<Field> zkpr(circuit, kLigeroRate, kLigeroNreq);

  Transcript tp((uint8_t*)"zk_test", 7, kVersion);
  SecureRandomEngine rng;
  ZkProver<Field, RSFactory> prover(circuit, base, rsf);
  prover.commit(zkpr, W, tp, rng);
  EXPECT_TRUE(prover.prove(zkpr, W, tp));
  log(INFO, "ZK Prover done");

  std::vector<uint8_t> zbuf;
  zkpr.write(zbuf, base);
  log(INFO, "zkp len: %zu bytes", zbuf.size());

  // ======= run verifier =============
  // Re-parse the proof to simulate a different client.
  ZkProof<Field> zkpv(circuit, kLigeroRate, kLigeroNreq);
  ReadBuffer rb(zbuf);
  EXPECT_TRUE(zkpv.read(rb, base));

  ZkVerifier<Field, RSFactory> verifier(circuit, rsf, kLigeroRate, kLigeroNreq,
                                        base);
  Transcript tv((uint8_t*)"zk_test", 7, kVersion);
  verifier.recv_commitment(zkpv, tv);
  EXPECT_TRUE(verifier.verify(zkpv, pub, tv));
  log(INFO, "ZK Verify done");
}

template <class Field>
void run_failing_test_zk2(const Circuit<Field>& circuit, Dense<Field>& W,
                          const Dense<Field>& pub, const Field& base,
                          const typename Field::Elt& root_x,
                          const typename Field::Elt& root_y,
                          size_t root_order) {
  // Build the relevant algebra objects.
  using Field2 = Fp2<Field>;
  using Elt2 = typename Field2::Elt;
  using FftExtConvolutionFactory = FFTExtConvolutionFactory<Field, Field2>;
  using RSFactory = ReedSolomonFactory<Field, FftExtConvolutionFactory>;

  const Field2 base_2(base);
  const Elt2 omega{root_x, root_y};
  const FftExtConvolutionFactory fft(base, base_2, omega, root_order);
  const RSFactory rsf(fft, base);

  ZkProof<Field> zkpr(circuit, kLigeroRate, kLigeroNreq);

  Transcript tp((uint8_t*)"zk_test", 7, kVersion);
  SecureRandomEngine rng;
  ZkProver<Field, RSFactory> prover(circuit, base, rsf);
  prover.commit(zkpr, W, tp, rng);
  bool p_ok = prover.prove(zkpr, W, tp);
  EXPECT_FALSE(p_ok);
}

// Runs a zk prover and verifier for a field that has a suitable root of unity.
template <class Field>
void run_test_zk(const Circuit<Field>& circuit, Dense<Field>& W,
                 const Dense<Field>& pub, const typename Field::Elt& omega,
                 uint64_t omega_order, const Field& F) {
  using FftConvolutionFactory = FFTConvolutionFactory<Field>;

  FftConvolutionFactory fft(F, omega, omega_order);
  using RSFactory = ReedSolomonFactory<Field, FftConvolutionFactory>;
  const RSFactory rsf(fft, F);

  ZkProof<Field> zkpr(circuit, kLigeroRate, kLigeroNreq);

  Transcript tp((uint8_t*)"zk_test", 7, kVersion);
  SecureRandomEngine rng;
  ZkProver<Field, RSFactory> prover(circuit, F, rsf);
  prover.commit(zkpr, W, tp, rng);
  EXPECT_TRUE(prover.prove(zkpr, W, tp));

  log(INFO, "ZK Prover done");

  std::vector<uint8_t> zbuf;
  zkpr.write(zbuf, F);
  log(INFO, "zkp len: %zu bytes", zbuf.size());

  // ======= zk verifier =============
  // Re-parse the proof to simulate a different client.
  ZkProof<Field> zkpv(circuit, kLigeroRate, kLigeroNreq);
  ReadBuffer rb(zbuf);
  EXPECT_TRUE(zkpv.read(rb, F));

  ZkVerifier<Field, RSFactory> verifier(circuit, rsf, kLigeroRate, kLigeroNreq,
                                        F);
  Transcript tv((uint8_t*)"zk_test", 7, kVersion);
  verifier.recv_commitment(zkpv, tv);
  EXPECT_TRUE(verifier.verify(zkpv, pub, tv));
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ZK_ZK_TESTING_H_
