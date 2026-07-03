// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// ...

#include "circuits/tests/ec/bip340/bip340_verify.h"

#include <cstddef>
#include <cstdint>
#include <memory>

#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/ec/bip340/bip340_witness.h"
#include "ec/p256k1.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/log.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

constexpr size_t kRate = 4;
constexpr size_t kQueries = 128;

using Field = Fp256k1Base;
using Nat = typename Field::N;
using Elt = typename Field::Elt;
using EC = P256k1;

// ======================== Evaluation Tests ==============================

class Bip340EvalTest : public ::testing::Test {
 protected:
  using EvalBackend = EvaluationBackend<Field>;
  using LogicType = Logic<Field, EvalBackend>;
  using EltW = typename LogicType::EltW;
  using VerifyC = Bip340Verify<LogicType, Field, EC>;

  const Field& F = p256k1_base;
  const EC& ec = p256k1;

  /// Build a witness from known scalars and verify the circuit.
  /// expected = true: circuit should accept (no assertion failed).
  void CheckVerify(const Nat& s_nat, const Nat& e_nat,
                   const Elt& px, const Elt& py,
                   const Elt& rx, bool expected) {
    Bip340Witness wit(ec);
    ASSERT_TRUE(wit.compute_from_scalars(s_nat, e_nat, px, py));

    const EvalBackend ebk(F, expected);
    const LogicType l(&ebk, F);
    VerifyC circuit(l, ec);

    EltW rxx = l.konst(rx);
    EltW pxx = l.konst(px);
    EltW ee = l.konst(wit.e_);

    typename VerifyC::Witness w;
    for (size_t i = 0; i < 256; ++i) {
      w.bits_s[i] = l.konst(wit.bits_s_[i]);
      w.bits_e[i] = l.konst(wit.bits_e_[i]);
      if (i < 255) {
        w.int_sx[i] = l.konst(wit.int_sx_[i]);
        w.int_sy[i] = l.konst(wit.int_sy_[i]);
        w.int_sz[i] = l.konst(wit.int_sz_[i]);
        w.int_ex[i] = l.konst(wit.int_ex_[i]);
        w.int_ey[i] = l.konst(wit.int_ey_[i]);
        w.int_ez[i] = l.konst(wit.int_ez_[i]);
      }
    }
    w.py = l.konst(wit.py_);

    circuit.assert_verify(rxx, pxx, ee, w);

    if (expected) {
      ASSERT_FALSE(ebk.assertion_failed());
    } else {
      ASSERT_TRUE(ebk.assertion_failed());
    }
  }

  /// Compute R = sG - eP and return R.x (normalized). Also returns py.
  Elt compute_rx(const Nat& s_nat, const Nat& e_nat,
                 const Elt& px, Elt& py_out) {
    // Pick the even square root of px.
    Elt x2 = F.mulf(px, px);
    Elt x3 = F.mulf(x2, px);
    Elt y2 = F.addf(x3, ec.b_);
    py_out = sqrt_even(y2);

    auto G = ec.generator();
    auto sG = ec.scalar_multf(G, s_nat);

    typename EC::ECPoint P = {px, py_out, F.one()};
    auto eP = ec.scalar_multf(P, e_nat);

    auto neg_eP = typename EC::ECPoint{eP.x, F.negf(eP.y), eP.z};
    ec.addE(sG, neg_eP);
    ec.normalize(sG);
    return sG.x;
  }

  /// sqrt mod p (p ≡ 3 mod 4), choosing even root.
  Elt sqrt_even(const Elt& a) {
    Nat exp("0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c");
    Elt root = F.one();
    Elt base = a;
    for (int i = 255; i >= 0; --i) {
      root = F.mulf(root, root);
      if (exp.bit(i)) {
        root = F.mulf(root, base);
      }
    }
    Nat r0 = F.from_montgomery(root);
    if (r0.bit(0) == 0) return root;
    return F.negf(root);
  }
};

TEST_F(Bip340EvalTest, ValidWitness) {
  // Pick known scalars and verify.
  Nat s_nat(123456789ull);
  Nat e_nat(987654321ull);
  Nat sk_nat(3ull);

  // Compute P = sk * G.
  auto G = ec.generator();
  auto P = ec.scalar_multf(G, sk_nat);
  ec.normalize(P);

  // Pick the even square root of P.x.
  Elt py;
  Elt rx = compute_rx(s_nat, e_nat, P.x, py);

  CheckVerify(s_nat, e_nat, P.x, py, rx, true);
}

TEST_F(Bip340EvalTest, WrongPublicKeyFails) {
  Nat s_nat(123456789ull);
  Nat e_nat(987654321ull);

  // Use wrong public key (different sk).
  auto G = ec.generator();
  auto P = ec.scalar_multf(G, Nat(3ull));
  ec.normalize(P);

  auto P_wrong = ec.scalar_multf(G, Nat(5ull));
  ec.normalize(P_wrong);

  Elt py_wrong;
  Elt rx_wrong = compute_rx(s_nat, e_nat, P_wrong.x, py_wrong);

  // Try to verify with P.x but R.x for P_wrong.
  CheckVerify(s_nat, e_nat, P.x, py_wrong, rx_wrong, false);
}

TEST_F(Bip340EvalTest, WrongRXFails) {
  Nat s_nat(123456789ull);
  Nat e_nat(987654321ull);

  auto G = ec.generator();
  auto P = ec.scalar_multf(G, Nat(3ull));
  ec.normalize(P);

  Elt py;
  Elt rx = compute_rx(s_nat, e_nat, P.x, py);

  // Use wrong rx (negate it).
  Elt wrong_rx = F.negf(rx);
  CheckVerify(s_nat, e_nat, P.x, py, wrong_rx, false);
}

TEST_F(Bip340EvalTest, WrongChallengeFails) {
  Nat s_nat(123456789ull);
  Nat e_nat(987654321ull);
  Nat e_wrong_nat(987654322ull);  // off by 1

  auto G = ec.generator();
  auto P = ec.scalar_multf(G, Nat(3ull));
  ec.normalize(P);

  Elt py, rx;
  rx = compute_rx(s_nat, e_nat, P.x, py);

  // Build witness with wrong e.
  Bip340Witness wit(ec);
  ASSERT_TRUE(wit.compute_from_scalars(s_nat, e_nat, P.x, py));

  // But pass e_wrong as the public input.
  const EvalBackend ebk(F, false);
  const LogicType l(&ebk, F);
  VerifyC circuit(l, ec);

  EltW rxx = l.konst(rx);
  EltW pxx = l.konst(P.x);
  EltW ee = l.konst(F.to_montgomery(e_wrong_nat));  // wrong!

  typename VerifyC::Witness w;
  for (size_t i = 0; i < 256; ++i) {
    w.bits_s[i] = l.konst(wit.bits_s_[i]);
    w.bits_e[i] = l.konst(wit.bits_e_[i]);
    if (i < 255) {
      w.int_sx[i] = l.konst(wit.int_sx_[i]);
      w.int_sy[i] = l.konst(wit.int_sy_[i]);
      w.int_sz[i] = l.konst(wit.int_sz_[i]);
      w.int_ex[i] = l.konst(wit.int_ex_[i]);
      w.int_ey[i] = l.konst(wit.int_ey_[i]);
      w.int_ez[i] = l.konst(wit.int_ez_[i]);
    }
  }
  w.py = l.konst(wit.py_);

  circuit.assert_verify(rxx, pxx, ee, w);
  ASSERT_TRUE(ebk.assertion_failed());
}

// ========================= Circuit Size ==================================

TEST(Bip340SizeTest, CircuitSize) {
  using CompilerBackendType = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackendType>;
  using EltW = typename LogicCircuit::EltW;
  using VerifyC = Bip340Verify<LogicCircuit, Field, EC>;

  QuadCircuit<Field> Q(p256k1_base);
  const CompilerBackendType cbk(&Q);
  const LogicCircuit lc(&cbk, p256k1_base);
  VerifyC circuit(lc, p256k1);

  typename VerifyC::Witness w;
  Q.private_input();
  w.input(lc);

  EltW rx = lc.eltw_input();
  EltW px = lc.eltw_input();
  EltW e = lc.eltw_input();

  circuit.assert_verify(rx, px, e, w);
  auto C = Q.mkcircuit(1);
  dump_info("bip340 verify", Q);

  EXPECT_GT(C->npub_in, 0);
  EXPECT_GT(C->ninputs, C->npub_in);
}

// ===================== ZK Prover / Verifier ==============================

class Bip340ZkTest : public ::testing::Test {
 protected:
  using CompilerBackendType = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackendType>;
  using EltW = typename LogicCircuit::EltW;
  using VerifyC = Bip340Verify<LogicCircuit, Field, EC>;

  const Field& F = p256k1_base;
  const EC& ec = p256k1;

  std::unique_ptr<Circuit<Field>> make_circuit() {
    QuadCircuit<Field> Q(F);
    const CompilerBackendType cbk(&Q);
    const LogicCircuit lc(&cbk, F);
    VerifyC circuit(lc, ec);

    EltW rx = lc.eltw_input();
    EltW px = lc.eltw_input();
    EltW e = lc.eltw_input();

    Q.private_input();
    typename VerifyC::Witness w;
    w.input(lc);

    circuit.assert_verify(rx, px, e, w);
    return Q.mkcircuit(1);
  }

  void run_zk_test(const Nat& s_nat, const Nat& e_nat,
                   const Elt& px, const Elt& py, const Elt& rx) {
    Bip340Witness wit(ec);
    ASSERT_TRUE(wit.compute_from_scalars(s_nat, e_nat, px, py));

    auto circuit = make_circuit();
    auto W = std::make_unique<Dense<Field>>(1, circuit->ninputs);

    // Fill prover witness.
    {
      DenseFiller<Field> filler(*W);
      filler.push_back(F.one());
      filler.push_back(rx);
      filler.push_back(px);
      filler.push_back(wit.e_);
      wit.fill_witness(filler);
    }

    using Crt = CRT256<Field>;
    using ConvolutionFactory = CrtConvolutionFactory<Crt, Field>;
    using RSFactory = ReedSolomonFactory<Field, ConvolutionFactory>;

    ConvolutionFactory factory(F);
    RSFactory rsf(factory, F);

    Transcript tp((uint8_t*)"bip340 zk test", 14);
    SecureRandomEngine rng;

    ZkProof<Field> zkpr(*circuit, kRate, kQueries);
    ZkProver<Field, RSFactory> prover(*circuit, F, rsf);
    prover.commit(zkpr, *W, tp, rng);
    prover.prove(zkpr, *W, tp);
    log(INFO, "BIP-340 Prover done");

    Transcript tv((uint8_t*)"bip340 zk test", 14);
    auto pub = Dense<Field>(1, circuit->npub_in);
    {
      DenseFiller<Field> filler(pub);
      filler.push_back(F.one());
      filler.push_back(rx);
      filler.push_back(px);
      filler.push_back(wit.e_);
    }

    ZkVerifier<Field, RSFactory> verifier(*circuit, rsf, kRate, kQueries, F);
    verifier.recv_commitment(zkpr, tv);
    EXPECT_TRUE(verifier.verify(zkpr, pub, tv));
    log(INFO, "BIP-340 Verifier done");
  }

  struct TestData {
    Nat s_nat;
    Nat e_nat;
    Elt px;
    Elt py;
    Elt rx;
  };

  TestData setup_test_data(Nat s_nat = Nat(123456789ull),
                           Nat e_nat = Nat(987654321ull),
                           Nat sk = Nat(3ull)) {
    auto G = ec.generator();
    auto P = ec.scalar_multf(G, sk);
    ec.normalize(P);

    Nat exp("0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c");
    Elt x2 = F.mulf(P.x, P.x);
    Elt x3 = F.mulf(x2, P.x);
    Elt y2 = F.addf(x3, ec.b_);
    Elt py = F.one();
    Elt base = y2;
    for (int i = 255; i >= 0; --i) {
      py = F.mulf(py, py);
      if (exp.bit(i)) py = F.mulf(py, base);
    }
    if (F.from_montgomery(py).bit(0) != 0) py = F.negf(py);

    auto sG = ec.scalar_multf(G, s_nat);
    auto eP = ec.scalar_multf(
        typename EC::ECPoint{P.x, py, F.one()}, e_nat);
    auto neg_eP = typename EC::ECPoint{eP.x, F.negf(eP.y), eP.z};
    ec.addE(sG, neg_eP);
    ec.normalize(sG);

    return {s_nat, e_nat, P.x, py, sG.x};
  }
};

TEST_F(Bip340ZkTest, SmallScalars) {
  auto d = setup_test_data();
  run_zk_test(d.s_nat, d.e_nat, d.px, d.py, d.rx);
}

TEST_F(Bip340ZkTest, WrongPublicInputFails) {
  auto d = setup_test_data();

  // Use wrong rx (negate it).
  Elt wrong_rx = F.negf(d.rx);

  Bip340Witness wit(ec);
  ASSERT_TRUE(wit.compute_from_scalars(d.s_nat, d.e_nat, d.px, d.py));

  auto circuit = make_circuit();
  auto W = std::make_unique<Dense<Field>>(1, circuit->ninputs);
  {
    DenseFiller<Field> filler(*W);
    filler.push_back(F.one());
    filler.push_back(d.rx);  // prover uses correct rx
    filler.push_back(d.px);
    filler.push_back(wit.e_);
    wit.fill_witness(filler);
  }

  using Crt = CRT256<Field>;
  using ConvolutionFactory = CrtConvolutionFactory<Crt, Field>;
  using RSFactory = ReedSolomonFactory<Field, ConvolutionFactory>;

  ConvolutionFactory factory(F);
  RSFactory rsf(factory, F);

  Transcript tp((uint8_t*)"bip340 wrong", 12);
  SecureRandomEngine rng;

  ZkProof<Field> zkpr(*circuit, kRate, kQueries);
  ZkProver<Field, RSFactory> prover(*circuit, F, rsf);
  prover.commit(zkpr, *W, tp, rng);
  prover.prove(zkpr, *W, tp);

  // Verifier uses wrong rx.
  Transcript tv((uint8_t*)"bip340 wrong", 12);
  auto pub = Dense<Field>(1, circuit->npub_in);
  {
    DenseFiller<Field> filler(pub);
    filler.push_back(F.one());
    filler.push_back(wrong_rx);  // wrong!
    filler.push_back(d.px);
    filler.push_back(wit.e_);
  }

  ZkVerifier<Field, RSFactory> verifier(*circuit, rsf, kRate, kQueries, F);
  verifier.recv_commitment(zkpr, tv);
  EXPECT_FALSE(verifier.verify(zkpr, pub, tv))
      << "Verification should fail with wrong public input";
}

TEST_F(Bip340ZkTest, LargerScalars) {
  Nat s_nat("0x4a5e1bca99fee8a7c3d1f0e5b6a728394c5d6e7f8091a2b3c4d5e6f708192a3b");
  Nat e_nat("0x1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c");
  auto d = setup_test_data(s_nat, e_nat);
  run_zk_test(d.s_nat, d.e_nat, d.px, d.py, d.rx);
}

}  // namespace
}  // namespace proofs
