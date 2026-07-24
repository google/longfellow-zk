
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

#include "circuits/hidden_pk/hidden_pk_circuit.h"
#include "circuits/hidden_pk/hidden_pk_witness.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/reed_solomon.h"
#include "algebra/static_string.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/sha3/sha3_reference.h"
#include "ec/p256k1.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "util/panic.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_testing.h"
#include "zk/zk_verifier.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using Field = Fp256k1Base;
using EC    = P256k1;
using Nat   = Fp256k1Nat;
using Elt   = Field::Elt;

// Derive the 20-byte Ethereum address for a secp256k1 public key.
// Address = keccak256(pkx_big_endian || pky_big_endian)[12:32].
std::vector<uint8_t> derive_eth_address(Elt pkx_mont, Elt pky_mont) {
  const Field& F = p256k1_base;
  uint8_t msg[64] = {};
  Nat nx = F.from_montgomery(pkx_mont);
  Nat ny = F.from_montgomery(pky_mont);
  for (size_t i = 0; i < 32; ++i) {
    uint8_t bx = 0, by = 0;
    for (int j = 0; j < 8; ++j) {
      if (nx.bit(255 - (i * 8 + j))) bx |= (1u << (7 - j));
      if (ny.bit(255 - (i * 8 + j))) by |= (1u << (7 - j));
    }
    msg[i]      = bx;
    msg[32 + i] = by;
  }
  uint8_t hash[32];
  Sha3Reference::keccak256Hash(msg, 64, hash);
  return std::vector<uint8_t>(hash + 12, hash + 32);
}

// Build the compiled circuit once and reuse.
std::unique_ptr<Circuit<Field>> make_circuit() {
  using CompilerBackend = CompilerBackend<Field>;
  using LogicType       = Logic<Field, CompilerBackend>;
  using CircuitType     = HiddenPKCircuit<LogicType>;

  QuadCircuit<Field> Q(p256k1_base);
  const CompilerBackend cbk(&Q);
  const LogicType lc(&cbk, p256k1_base);
  CircuitType circuit(lc);

  // Public inputs: eth_addr (20 bytes) then e (1 field element).
  std::vector<typename CircuitType::v8> eth_addr(20);
  for (size_t i = 0; i < 20; ++i) {
    eth_addr[i] = lc.template vinput<8>();
  }
  auto e = lc.eltw_input();

  Q.private_input();

  typename CircuitType::Witness w;
  w.input(lc);

  circuit.assert_hidden_pk(eth_addr, e, w);
  return Q.mkcircuit(/*nc=*/1);
}

// Fill the dense witness vector.
void fill_dense(Dense<Field>& W, const HiddenPKWitness& hw,
                const Nat& e_nat, bool prover) {
  const Field& F = p256k1_base;
  DenseFiller<Field> filler(W);

  // Position 0: constant 1.
  filler.push_back(F.one());

  // Positions 1..160: eth_addr bits (20 bytes, LSB-first per byte).
  auto addr = hw.eth_address_bytes();
  for (size_t i = 0; i < 20; ++i) {
    filler.push_back(addr[i], 8, F);
  }

  // Position 161: e as a field element.
  filler.push_back(F.to_montgomery(e_nat));

  if (prover) {
    hw.fill_witness(filler);
  }
}


TEST(HiddenPK, CircuitSize) {
  set_log_level(INFO);
  auto CIRCUIT = make_circuit();
  log(INFO, "HiddenPK circuit: ninputs=%zu npub_in=%zu nl=%zu",
      CIRCUIT->ninputs, CIRCUIT->npub_in, CIRCUIT->nl);
}

TEST(HiddenPK, ZkProverVerifier) {
  const Field& F = p256k1_base;

  // Everything in this test is derived from a single sk.
  // DISCLAIMER: Fixed k below is for testing only. Never reuse k in production.
  Nat sk("0x9FE33A7A06BD0FE6F5208A61991C49B5B4DD12DC42D9903E789F5118F9675030");

  // pk = sk * G  (secp256k1 key derivation)
  EC::ECPoint Qpt = p256k1.scalar_multf(p256k1.generator(), sk);
  p256k1.normalize(Qpt);
  Elt pkx = Qpt.x;
  Elt pky = Qpt.y;

  // eth_addr = keccak256(pkx_bytes || pky_bytes)[12:32]
  auto addr = derive_eth_address(pkx, pky);
  ASSERT_EQ(addr.size(), 20u);

  Nat e_n("0xb94f6f125c79e932d738873f2584e5de7e816ed39e5c26df7ef96a73efacffcd");
  Nat k_n("0x4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a");

  // R = k * G;  r = R.x mod n
  EC::ECPoint R_pt = p256k1.scalar_multf(p256k1.generator(), k_n);
  p256k1.normalize(R_pt);
  Nat r_raw = p256k1_base.from_montgomery(R_pt.x);
  Nat r_n   = p256k1_scalar.from_montgomery(p256k1_scalar.to_montgomery(r_raw));

  // s = k^{-1} * (e + r * sk) mod n
  Nat k_inv    = p256k1_scalar.from_montgomery(
      p256k1_scalar.invertf(p256k1_scalar.to_montgomery(k_n)));
  auto e_mont  = p256k1_scalar.to_montgomery(e_n);
  auto r_mont  = p256k1_scalar.to_montgomery(r_n);
  auto sk_mont = p256k1_scalar.to_montgomery(sk);
  auto r_sk    = p256k1_scalar.mulf(r_mont, sk_mont);
  auto e_rsk   = p256k1_scalar.addf(e_mont, r_sk);
  auto k_inv_m = p256k1_scalar.to_montgomery(k_inv);
  auto s_mont  = p256k1_scalar.mulf(k_inv_m, e_rsk);
  Nat s_n      = p256k1_scalar.from_montgomery(s_mont);

  // Verify the ECDSA equation algebraically: s * k == e + r * sk  (mod n).
  // This proves that (r, s) was produced by the same sk that generated pk,
  // and therefore the address, the public key, and the signature all belong
  // to one key pair.
  {
    auto lhs = p256k1_scalar.mulf(p256k1_scalar.to_montgomery(s_n),
                                  p256k1_scalar.to_montgomery(k_n));
    auto rhs = p256k1_scalar.addf(e_mont, r_sk);
    ASSERT_EQ(p256k1_scalar.from_montgomery(lhs),
              p256k1_scalar.from_montgomery(rhs))
        << "ECDSA self-consistency failed: s*k != e + r*sk mod n";
  }

  // Compute ZK witnesses.
  HiddenPKWitness hw;
  ASSERT_TRUE(hw.compute(pkx, pky, e_n, r_n, s_n))
      << "ECDSA witness computation failed";

  // The witness's address must match addr derived directly from pk.
  EXPECT_EQ(hw.eth_address_bytes(), addr);

  // Build circuit and witnesses.
  auto CIRCUIT = make_circuit();
  const size_t npub = CIRCUIT->npub_in;
  const size_t nin  = CIRCUIT->ninputs;

  auto W   = std::make_unique<Dense<Field>>(1, nin);
  auto pub = std::make_unique<Dense<Field>>(1, npub);

  fill_dense(*W,   hw, e_n, /*prover=*/true);
  fill_dense(*pub, hw, e_n, /*prover=*/false);

  // ZK proof via CRT256 + CrtConvolutionFactory (secp256k1-compatible RS).
  using Crt256         = CRT256<Field>;
  using CrtConvFactory = CrtConvolutionFactory<Crt256, Field>;
  using RSFactory      = ReedSolomonFactory<Field, CrtConvFactory>;

  const CrtConvFactory conv(p256k1_base);
  const RSFactory      rsf(conv, p256k1_base);

  ZkProof<Field> zkpr(*CIRCUIT, kLigeroRate, kLigeroNreq);
  Transcript     tp((uint8_t*)"hidden_pk_test", 14, kVersion);
  SecureRandomEngine rng;

  ZkProver<Field, RSFactory> prover(*CIRCUIT, p256k1_base, rsf);
  prover.commit(zkpr, *W, tp, rng);
  ASSERT_TRUE(prover.prove(zkpr, *W, tp)) << "ZK proof failed";

  // Verify.
  ZkVerifier<Field, RSFactory> verifier(*CIRCUIT, rsf, kLigeroRate,
                                        kLigeroNreq, p256k1_base);
  Transcript tv((uint8_t*)"hidden_pk_test", 14, kVersion);
  verifier.recv_commitment(zkpr, tv);
  EXPECT_TRUE(verifier.verify(zkpr, *pub, tv)) << "ZK verification failed";
}

void BM_HiddenPKProver(benchmark::State& state) {
  set_log_level(LogLevel::ERROR);

  Nat sk("0x9FE33A7A06BD0FE6F5208A61991C49B5B4DD12DC42D9903E789F5118F9675030");
  EC::ECPoint Qpt = p256k1.scalar_multf(p256k1.generator(), sk);
  p256k1.normalize(Qpt);

  Nat e_n("0xb94f6f125c79e932d738873f2584e5de7e816ed39e5c26df7ef96a73efacffcd");
  Nat k_n("0x4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a");

  EC::ECPoint R_pt = p256k1.scalar_multf(p256k1.generator(), k_n);
  p256k1.normalize(R_pt);
  Nat r_raw = p256k1_base.from_montgomery(R_pt.x);
  Nat r_n   = p256k1_scalar.from_montgomery(p256k1_scalar.to_montgomery(r_raw));

  Nat k_inv  = p256k1_scalar.from_montgomery(
      p256k1_scalar.invertf(p256k1_scalar.to_montgomery(k_n)));
  auto s_mont = p256k1_scalar.mulf(
      p256k1_scalar.to_montgomery(k_inv),
      p256k1_scalar.addf(
          p256k1_scalar.to_montgomery(e_n),
          p256k1_scalar.mulf(p256k1_scalar.to_montgomery(r_n),
                             p256k1_scalar.to_montgomery(sk))));
  Nat s_n = p256k1_scalar.from_montgomery(s_mont);

  HiddenPKWitness hw;
  hw.compute(Qpt.x, Qpt.y, e_n, r_n, s_n);

  auto CIRCUIT = make_circuit();
  auto W = std::make_unique<Dense<Field>>(1, CIRCUIT->ninputs);
  fill_dense(*W, hw, e_n, true);

  using Crt256         = CRT256<Field>;
  using CrtConvFactory = CrtConvolutionFactory<Crt256, Field>;
  using RSFactory      = ReedSolomonFactory<Field, CrtConvFactory>;
  const CrtConvFactory conv(p256k1_base);
  const RSFactory      rsf(conv, p256k1_base);

  for (auto s : state) {
    ZkProof<Field>     zkpr(*CIRCUIT, kLigeroRate, kLigeroNreq);
    Transcript         tp((uint8_t*)"bench", 5, kVersion);
    SecureRandomEngine rng;
    ZkProver<Field, RSFactory> prover(*CIRCUIT, p256k1_base, rsf);
    prover.commit(zkpr, *W, tp, rng);
    prover.prove(zkpr, *W, tp);
  }
}
BENCHMARK(BM_HiddenPKProver);

}  // namespace
}  // namespace proofs
