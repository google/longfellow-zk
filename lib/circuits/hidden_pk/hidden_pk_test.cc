
// Tests for HiddenPKCircuit: secp256k1 ECDSA + SHA-256 commitment.

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
using Nat   = Fp256k1Nat;  // = Field::N = Nat<4>
using Elt   = Field::Elt;

// Build the compiled circuit once and reuse.
std::unique_ptr<Circuit<Field>> make_circuit() {
  using CompilerBackend = CompilerBackend<Field>;
  using LogicType       = Logic<Field, CompilerBackend>;
  using CircuitType     = HiddenPKCircuit<LogicType>;

  QuadCircuit<Field> Q(p256k1_base);
  const CompilerBackend cbk(&Q);
  const LogicType lc(&cbk, p256k1_base);
  CircuitType circuit(lc);

  auto pkHash = lc.template vinput<256>();
  auto e      = lc.eltw_input();

  Q.private_input();

  // Private inputs.
  typename CircuitType::Witness w;
  w.input(lc);

  circuit.assert_hidden_pk(pkHash, e, w);
  return Q.mkcircuit(/*nc=*/1);
}

// Fill the dense witness vector.
// If prover=true, fill private witnesses too; otherwise only public inputs.
void fill_dense(Dense<Field>& W, const HiddenPKWitness& hw,
                const Nat& e_nat, bool prover) {
  const Field& F = p256k1_base;
  DenseFiller<Field> filler(W);

  // Position 0: constant 1.
  filler.push_back(F.one());

  // Positions 1..256: pkHash bits (LSB-first).
  // hash_bytes[0] = MSB byte; pkHash_bits[i] = bit i of hash integer (LSB=0).
  auto hash_bytes = hw.pk_hash_bytes();
  for (size_t i = 0; i < 256; ++i) {
    size_t byte_idx = 31 - (i / 8);  // byte 31 = LSB byte (bits 7..0)
    size_t bit_pos  = i % 8;
    int bit         = (hash_bytes[byte_idx] >> bit_pos) & 1;
    filler.push_back(F.of_scalar(bit));
  }

  // Position 257: e as a field element (Montgomery form of e_nat mod p).
  filler.push_back(F.to_montgomery(e_nat));

  if (prover) {
    hw.fill_witness(filler);
  }
}


TEST(HiddenPK, EvalCorrect) {
  // Full circuit evaluation is covered by ZkProverVerifier.
  GTEST_SKIP() << "See ZkProverVerifier for end-to-end check.";
}

TEST(HiddenPK, CircuitSize) {
  set_log_level(INFO);
  auto CIRCUIT = make_circuit();
  log(INFO, "HiddenPK circuit: ninputs=%zu npub_in=%zu nl=%zu",
      CIRCUIT->ninputs, CIRCUIT->npub_in, CIRCUIT->nl);
}

TEST(HiddenPK, ZkProverVerifier) {
  const Field& F = p256k1_base;

  // Derive pk from sk.
  Nat sk("0x9FE33A7A06BD0FE6F5208A61991C49B5B4DD12DC42D9903E789F5118F9675030");
  EC::ECPoint Qpt = p256k1.scalar_multf(p256k1.generator(), sk);
  p256k1.normalize(Qpt);
  Elt pkx = Qpt.x;
  Elt pky = Qpt.y;

  // Message hash (public).
  Nat e_n("0xb94f6f125c79e932d738873f2584e5de7e816ed39e5c26df7ef96a73efacffcd");

  // Disclaimer: Fixed k for testing only - never use in production.
  Nat k_n("0x4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a");

  // R = k*G; r = Rx mod scalar order.
  EC::ECPoint R_pt = p256k1.scalar_multf(p256k1.generator(), k_n);
  p256k1.normalize(R_pt);
  Nat r_raw = p256k1_base.from_montgomery(R_pt.x);
  // Reduce r mod scalar order n via the scalar field.
  Nat r_n = p256k1_scalar.from_montgomery(p256k1_scalar.to_montgomery(r_raw));

  // s = k^{-1} * (e + r * sk) mod n.
  Nat k_inv = p256k1_scalar.from_montgomery(
      p256k1_scalar.invertf(p256k1_scalar.to_montgomery(k_n)));
  auto e_mont  = p256k1_scalar.to_montgomery(e_n);
  auto r_mont  = p256k1_scalar.to_montgomery(r_n);
  auto sk_mont = p256k1_scalar.to_montgomery(sk);
  auto r_sk    = p256k1_scalar.mulf(r_mont, sk_mont);
  auto e_rsk   = p256k1_scalar.addf(e_mont, r_sk);
  auto s_mont  = p256k1_scalar.mulf(p256k1_scalar.to_montgomery(k_inv), e_rsk);
  Nat s_n      = p256k1_scalar.from_montgomery(s_mont);

  // Compute witnesses.
  HiddenPKWitness hw;
  ASSERT_TRUE(hw.compute(pkx, pky, e_n, r_n, s_n))
      << "ECDSA witness computation failed — bad test vectors?";

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
