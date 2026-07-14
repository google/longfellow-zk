// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// ...

#include "circuits/bip340/bip340_verify.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/bip340/bip340_guard.h"
#include "circuits/bip340/bip340_witness.h"
#include "ec/p256k1.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/log.h"
#include "util/power_of_two.h"
#include "util/readbuffer.h"
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

/// Stable public-input filling helper: pushes [F.one(), rx, px, e]
/// in the order expected by the production circuit.
template <class Field>
void PushBip340PublicInputs(DenseFiller<Field>& filler, const Field& F,
                            typename Field::Elt rx,
                            typename Field::Elt px,
                            typename Field::Elt e) {
  filler.push_back(F.one());
  filler.push_back(rx);
  filler.push_back(px);
  filler.push_back(e);
}

/// Centralized eval-witness builder: fills a VerifyC::Witness from a
/// Bip340Witness using a LogicType to create konst wires.  This is the
/// single place where eval witness fields are copied; all eval tests
/// use this helper (except tests that intentionally mutate fields).
template <class LogicType, class VerifyC>
typename VerifyC::Witness MakeEvalWitness(const LogicType& l,
                                          const Bip340Witness& wit) {
  typename VerifyC::Witness w;
  for (size_t i = 0; i < Bip340Witness::kBits; ++i) {
    w.bits_s[i] = l.konst(wit.bits_s_[i]);
    w.bits_e[i] = l.konst(wit.bits_e_[i]);
    w.bits_ry[i] = l.konst(wit.bits_ry_[i]);
    if (i < Bip340Witness::kBits - 1) {
      w.int_sx[i] = l.konst(wit.int_sx_[i]);
      w.int_sy[i] = l.konst(wit.int_sy_[i]);
      w.int_sz[i] = l.konst(wit.int_sz_[i]);
      w.int_ex[i] = l.konst(wit.int_ex_[i]);
      w.int_ey[i] = l.konst(wit.int_ey_[i]);
      w.int_ez[i] = l.konst(wit.int_ez_[i]);
    }
  }
  w.py = l.konst(wit.py_);
  w.ry = l.konst(wit.ry_);
  w.rz_inv = l.konst(wit.rz_inv_);
  return w;
}

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

    typename VerifyC::Witness w = MakeEvalWitness<LogicType, VerifyC>(l, wit);

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

  /// sqrt mod p (p =  3 mod 4), choosing even root.
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
  // Pick scalars that produce even R.y (verified via Sage).
  Nat s_nat(2ull);
  Nat e_nat(1ull);
  Nat sk_nat(1ull);

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
  Nat s_nat(2ull);
  Nat e_nat(1ull);

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
  Nat s_nat(2ull);
  Nat e_nat(1ull);

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
  Nat s_nat(2ull);
  Nat e_nat(1ull);
  Nat e_wrong_nat(2ull);  // off by 1

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

  typename VerifyC::Witness w = MakeEvalWitness<LogicType, VerifyC>(l, wit);

  circuit.assert_verify(rxx, pxx, ee, w);
  ASSERT_TRUE(ebk.assertion_failed());
}

// ====================== BIP-340 Test Vector Tests =======================

// Returns the integer value of a hex character (0-15), or -1 if invalid.
inline int HexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

// Parses a hex string to a byte vector.  Returns std::nullopt on any
// malformed input (odd length or invalid hex characters).
inline std::optional<std::vector<uint8_t>> ParseHexVec(const char* hex) {
  size_t len = std::strlen(hex);
  if (len % 2 != 0) return std::nullopt;
  std::vector<uint8_t> out(len / 2);
  for (size_t i = 0; i < len; i += 2) {
    int hi = HexValue(hex[i]);
    int lo = HexValue(hex[i + 1]);
    if (hi == -1 || lo == -1) return std::nullopt;
    out[i / 2] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return out;
}

// Helper: parse hex string to byte vector, failing the current test
// on malformed input.
inline std::vector<uint8_t> hex_vec(const char* hex) {
  auto result = ParseHexVec(hex);
  EXPECT_TRUE(result.has_value()) << "hex_vec: malformed hex string \"" << hex << "\"";
  if (!result.has_value()) return {};
  return *result;
}

TEST(Bip340FixtureTest, HexVecRejectsMalformedInput) {
  // Valid hex characters.
  EXPECT_EQ(HexValue('0'), 0);
  EXPECT_EQ(HexValue('9'), 9);
  EXPECT_EQ(HexValue('A'), 10);
  EXPECT_EQ(HexValue('F'), 15);
  EXPECT_EQ(HexValue('a'), 10);
  EXPECT_EQ(HexValue('f'), 15);
  // Invalid characters.
  EXPECT_EQ(HexValue('g'), -1);
  EXPECT_EQ(HexValue(' '), -1);
  EXPECT_EQ(HexValue('\x00'), -1);
  EXPECT_EQ(HexValue('@'), -1);

  // Valid hex string.
  auto v = ParseHexVec("0A1b");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->size(), 2u);
  EXPECT_EQ((*v)[0], 0x0A);
  EXPECT_EQ((*v)[1], 0x1B);

  // Empty string.
  v = ParseHexVec("");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->size(), 0u);

  // Odd length.
  EXPECT_FALSE(ParseHexVec("0A1").has_value());
  EXPECT_FALSE(ParseHexVec("A").has_value());

  // Invalid characters.
  EXPECT_FALSE(ParseHexVec("0g").has_value());
  EXPECT_FALSE(ParseHexVec("GG").has_value());
}

struct Bip340RealVector {
  const char* pk_hex;
  const char* msg_hex;
  const char* sig_hex;
  bool valid;
};

struct Bip340GoldenFact {
  size_t index;
  bool valid;
  bool compute_success;
  const char* rx_hex;
  const char* px_hex;
  const char* e_hex;
  const char* py_hex;
  const char* ry_hex;
};

/// Expected rejection layer for invalid vectors.
enum class RejectBy {
  kAccept = 0,          // valid signature; circuit must accept
  kInputValidation,     // rejected by compute() before reaching circuit
  kCircuit,             // accepted by compute() but rejected by circuit
};

/// For each invalid vector, which layer is expected to catch it.
/// Indexed by vector number; entries for valid vectors are kAccept.
constexpr RejectBy kRejectLayer[] = {
    RejectBy::kAccept,            // 0: valid
    RejectBy::kAccept,            // 1: valid
    RejectBy::kAccept,            // 2: valid
    RejectBy::kAccept,            // 3: valid
    RejectBy::kAccept,            // 4: valid
    RejectBy::kInputValidation,   // 5: pk not on curve (lift fails)
    RejectBy::kCircuit,           // 6: odd R.y - detected by LSB-zero gate
    RejectBy::kCircuit,           // 7: negated message
    RejectBy::kCircuit,           // 8: negated s value
    RejectBy::kCircuit,           // 9: R = infinity (rx=0) - R.z*rz_inv=1 fails
    RejectBy::kCircuit,           // 10: R = infinity (rx=1)
    RejectBy::kCircuit,           // 11: r not a quadratic residue - R.x==rx fails
    RejectBy::kInputValidation,   // 12: r >= p
    RejectBy::kInputValidation,   // 13: s >= n
    RejectBy::kInputValidation,   // 14: pk >= p
    RejectBy::kAccept,            // 15: valid (empty msg)
    RejectBy::kAccept,            // 16: valid (1-byte msg)
    RejectBy::kAccept,            // 17: valid (17-byte msg)
    RejectBy::kAccept,            // 18: valid (100-byte msg)
};
static_assert(sizeof(kRejectLayer) / sizeof(kRejectLayer[0]) == 19,
              "kRejectLayer must cover all 19 vectors");

// Upstream BIP-340 test vectors from Bitcoin Core.
// Auto-generated from testdata/bip340_test_vectors.csv.
// To regenerate: python3 docs/specs/code/generate_bip340_vectors_inc.py
const Bip340RealVector kRealVectors[] = {
#include "testdata/bip340_vectors.inc"
};
static_assert(sizeof(kRealVectors) / sizeof(kRealVectors[0]) == 19,
              "kRealVectors must cover all 19 vectors");

const Bip340GoldenFact kGoldenFacts[] = {
#include "testdata/bip340_golden.inc"
};
static_assert(sizeof(kGoldenFacts) / sizeof(kGoldenFacts[0]) == 19,
              "kGoldenFacts must cover all 19 vectors");

Elt EltFromHex(const Field& F, const char* hex) {
  auto be = hex_vec(hex);
  uint8_t le[32] = {0};
  for (size_t i = 0; i < be.size(); ++i) {
    le[i] = be[be.size() - 1 - i];
  }
  return F.to_montgomery(Nat::of_bytes(le, 256));
}

TEST(Bip340RealVectorTest, EvalTestVectors) {
  using EvalBackend = EvaluationBackend<Field>;
  using LogicType = Logic<Field, EvalBackend>;
  using EltW = typename LogicType::EltW;
  using VerifyC = Bip340Verify<LogicType, Field, EC>;

  const Field& F = p256k1_base;
  const EC& ec = p256k1;

  for (size_t vi = 0; vi < sizeof(kRealVectors) / sizeof(kRealVectors[0]);
       ++vi) {
    const auto& tv = kRealVectors[vi];
    auto pk = hex_vec(tv.pk_hex);
    auto msg = hex_vec(tv.msg_hex);
    auto sig = hex_vec(tv.sig_hex);
    RejectBy expected = kRejectLayer[vi];

    SCOPED_TRACE("vector " + std::to_string(vi));

    Bip340Witness wit(ec);
    bool computed = wit.compute(sig.data(), pk.data(),
                                msg.data(), msg.size());

    if (expected == RejectBy::kAccept) {
      // Valid vector: compute() must succeed, circuit must accept.
      ASSERT_TRUE(computed) << "compute() failed for valid vector " << vi;
      const EvalBackend ebk(F, false);
      const LogicType l(&ebk, F);
      VerifyC circuit(l, ec);

      EltW rx = l.konst(F.to_montgomery(
          Bip340Witness::nat_from_be_bytes(sig.data())));
      EltW px = l.konst(F.to_montgomery(
          Bip340Witness::nat_from_be_bytes(pk.data())));
      EltW e = l.konst(wit.e_);

      auto w = MakeEvalWitness<LogicType, VerifyC>(l, wit);
      circuit.assert_verify(rx, px, e, w);
      ASSERT_FALSE(ebk.assertion_failed())
          << "Valid vector " << vi << " should pass";
      continue;
    }

    if (expected == RejectBy::kInputValidation) {
      // compute() must reject this vector before reaching the circuit.
      ASSERT_FALSE(computed)
          << "Vector " << vi << " should fail input validation";
      continue;
    }

    // kCircuit: compute() may succeed but the circuit must reject.
    if (!computed) {
      // compute() caught it early - still valid, but log a note.
      log(INFO, "Vector %zu: input validation caught what circuit should", vi);
      continue;
    }

    log(INFO, "Testing invalid vector %zu through circuit", vi);
    const EvalBackend ebk(F, false);
    const LogicType l(&ebk, F);
    VerifyC circuit(l, ec);

    EltW rx = l.konst(F.to_montgomery(
        Bip340Witness::nat_from_be_bytes(sig.data())));
    EltW px = l.konst(F.to_montgomery(
        Bip340Witness::nat_from_be_bytes(pk.data())));
    EltW e = l.konst(wit.e_);

    auto w = MakeEvalWitness<LogicType, VerifyC>(l, wit);
    circuit.assert_verify(rx, px, e, w);
    ASSERT_TRUE(ebk.assertion_failed())
        << "Invalid vector " << vi << " should fail circuit check";
  }
}

// Compares only semantic facts invariant across the Sage affine model
// and the C++ projective double-and-add witness.  Implementation-
// specific projective values (e.g. rz_inv) are intentionally excluded
// because Sage and the production C++ verifier compute them differently.
TEST(Bip340RealVectorTest, CppWitnessMatchesSemanticGoldenFacts) {
  const Field& F = p256k1_base;
  const EC& ec = p256k1;

  for (size_t vi = 0; vi < sizeof(kRealVectors) / sizeof(kRealVectors[0]);
       ++vi) {
    const auto& tv = kRealVectors[vi];
    const auto& fact = kGoldenFacts[vi];
    auto pk = hex_vec(tv.pk_hex);
    auto msg = hex_vec(tv.msg_hex);
    auto sig = hex_vec(tv.sig_hex);

    SCOPED_TRACE("vector " + std::to_string(vi));
    ASSERT_EQ(fact.index, vi);
    ASSERT_EQ(fact.valid, tv.valid);

    Bip340Witness wit(ec);
    bool computed = wit.compute(sig.data(), pk.data(),
                                msg.data(), msg.size());
    if (!computed) {
      ASSERT_FALSE(tv.valid);
      continue;
    }

    if (!fact.compute_success) {
      ASSERT_FALSE(tv.valid);
      continue;
    }

    EXPECT_EQ(wit.e_, EltFromHex(F, fact.e_hex));
    EXPECT_EQ(wit.py_, EltFromHex(F, fact.py_hex));
    EXPECT_EQ(wit.ry_, EltFromHex(F, fact.ry_hex));
  }
}

TEST(Bip340RealVectorTest, ZkProverVerifier_Vector0) {
  set_log_level(INFO);
  const Field& F = p256k1_base;
  const EC& ec = p256k1;

  const auto& tv = kRealVectors[0];
  auto pk = hex_vec(tv.pk_hex);
  auto msg = hex_vec(tv.msg_hex);
  auto sig = hex_vec(tv.sig_hex);

  Bip340Witness wit(ec);
  ASSERT_TRUE(wit.compute(sig.data(), pk.data(), msg.data(), msg.size()));

  // Build circuit.
  using CompilerBackendType = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackendType>;
  using EltWC = typename LogicCircuit::EltW;
  using VerifyCC = Bip340Verify<LogicCircuit, Field, EC>;

  QuadCircuit<Field> Q(F);
  const CompilerBackendType cbk(&Q);
  const LogicCircuit lc(&cbk, F);
  VerifyCC circuit(lc, ec);

  EltWC rx = lc.eltw_input();
  EltWC px = lc.eltw_input();
  EltWC e = lc.eltw_input();
  Q.private_input();
  typename VerifyCC::Witness w;
  w.input(lc);
  circuit.assert_verify(rx, px, e, w);
  auto CIRCUIT = Q.mkcircuit(1);

  // CRT guard: ensure block_enc fits within 2^22 FFT order.
  {
    using Crt = CRT256<Field>;
    size_t block_enc = CIRCUIT->ninputs - CIRCUIT->npub_in +
                       Q.nquad_terms_ + 1;
    auto err = check_crt_block_enc<Crt>(block_enc);
    ASSERT_TRUE(err.empty()) << "CRT capacity: " << err;
  }

  auto W = std::make_unique<Dense<Field>>(1, CIRCUIT->ninputs);
  {
    DenseFiller<Field> filler(*W);
    PushBip340PublicInputs(filler, F,
        F.to_montgomery(Bip340Witness::nat_from_be_bytes(sig.data())),
        F.to_montgomery(Bip340Witness::nat_from_be_bytes(pk.data())),
        wit.e_);
    wit.fill_witness(filler);
  }

  using Crt = CRT256<Field>;
  using ConvolutionFactory = CrtConvolutionFactory<Crt, Field>;
  using RSFactory = ReedSolomonFactory<Field, ConvolutionFactory>;

  ConvolutionFactory factory(F);
  RSFactory rsf(factory, F);

  Transcript tp((uint8_t*)"bip340 real vec0", 16);
  SecureRandomEngine rng;

  ZkProof<Field> zkpr(*CIRCUIT, kRate, kQueries);
  ZkProver<Field, RSFactory> prover(*CIRCUIT, F, rsf);
  prover.commit(zkpr, *W, tp, rng);
  prover.prove(zkpr, *W, tp);
  log(INFO, "BIP-340 real-vector prover done");

  Transcript trv((uint8_t*)"bip340 real vec0", 16);
  auto pub = Dense<Field>(1, CIRCUIT->npub_in);
  {
    DenseFiller<Field> filler(pub);
    PushBip340PublicInputs(filler, F,
        F.to_montgomery(Bip340Witness::nat_from_be_bytes(sig.data())),
        F.to_montgomery(Bip340Witness::nat_from_be_bytes(pk.data())),
        wit.e_);
  }

  ZkVerifier<Field, RSFactory> verifier(*CIRCUIT, rsf, kRate, kQueries, F);
  verifier.recv_commitment(zkpr, trv);
  EXPECT_TRUE(verifier.verify(zkpr, pub, trv));
  log(INFO, "BIP-340 real-vector verifier done");
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

  EltW rx = lc.eltw_input();
  EltW px = lc.eltw_input();
  EltW e = lc.eltw_input();

  typename VerifyC::Witness w;
  Q.private_input();
  w.input(lc);

  circuit.assert_verify(rx, px, e, w);
  auto C = Q.mkcircuit(1);
  dump_info("bip340 verify", Q);

  EXPECT_GT(C->npub_in, 0);
  EXPECT_GT(C->ninputs, C->npub_in);
}

// ===================== ZK Prover / Verifier ==============================

struct Bip340TestData {
  Nat s_nat;
  Nat e_nat;
  Elt px;
  Elt py;
  Elt rx;
};

inline Bip340TestData MakeTestData(Nat s_nat = Nat(2ull),
                                   Nat e_nat = Nat(1ull),
                                   Nat sk = Nat(1ull)) {
  const Field& F = p256k1_base;
  const EC& ec = p256k1;
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

// ====================== Soundness Tests ================================

TEST(Bip340SoundnessTest, OddRYWitnessFails) {
  using EvalBackend = EvaluationBackend<Field>;
  using LogicType = Logic<Field, EvalBackend>;
  using VerifyC = Bip340Verify<LogicType, Field, EC>;

  const Field& F = p256k1_base;
  const EC& ec = p256k1;

  auto d = MakeTestData();
  Bip340Witness wit(ec);
  ASSERT_TRUE(wit.compute_from_scalars(d.s_nat, d.e_nat, d.px, d.py));

  // Subcase 1: odd ry with consistent odd bits - fails LSB-zero check.
  {
    const EvalBackend ebk(F, false);
    const LogicType l(&ebk, F);
    VerifyC circuit(l, ec);

    auto rxx = l.konst(d.rx);
    auto pxx = l.konst(d.px);
    auto ee = l.konst(wit.e_);

    auto w = MakeEvalWitness<LogicType, VerifyC>(l, wit);

    // Mutate: set ry to odd (negate it) and fill bits_ry for the odd value.
    Elt odd_ry = F.negf(wit.ry_);
    w.ry = l.konst(odd_ry);
    Nat odd_ry_nat = F.from_montgomery(odd_ry);
    for (size_t i = 0; i < 256; ++i) {
      w.bits_ry[i] = l.konst(
          F.of_scalar(odd_ry_nat.bit(255 - i)));
    }

    circuit.assert_verify(rxx, pxx, ee, w);
    EXPECT_TRUE(ebk.assertion_failed())
        << "Odd ry with odd bits should fail LSB-zero check";
  }

  // Subcase 2: odd ry with original even bits - fails reconstruction.
  {
    const EvalBackend ebk(F, false);
    const LogicType l(&ebk, F);
    VerifyC circuit(l, ec);

    auto rxx = l.konst(d.rx);
    auto pxx = l.konst(d.px);
    auto ee = l.konst(wit.e_);

    auto w = MakeEvalWitness<LogicType, VerifyC>(l, wit);

    // Mutate: set ry to odd but keep original even bits.
    w.ry = l.konst(F.negf(wit.ry_));

    circuit.assert_verify(rxx, pxx, ee, w);
    EXPECT_TRUE(ebk.assertion_failed())
        << "Odd ry with even bits should fail reconstruction";
  }
}

TEST(Bip340SoundnessTest, RejectsScalarSAtOrAboveCurveOrder) {
  using EvalBackend = EvaluationBackend<Field>;
  using LogicType = Logic<Field, EvalBackend>;
  using VerifyC = Bip340Verify<LogicType, Field, EC>;

  const Field& F = p256k1_base;
  const EC& ec = p256k1;

  auto d = MakeTestData();

  // n + 2 is congruent to the valid test scalar 2 modulo the secp256k1
  // group order, so the group equation still holds.  The circuit must
  // reject it because BIP-340 requires the encoded scalar to satisfy s < n.
  Nat s_plus_n(
      "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364143");
  Bip340Witness wit(ec);
  ASSERT_TRUE(wit.compute_from_scalars(s_plus_n, d.e_nat, d.px, d.py));

  const EvalBackend ebk(F, false);
  const LogicType l(&ebk, F);
  VerifyC circuit(l, ec);

  auto w = MakeEvalWitness<LogicType, VerifyC>(l, wit);
  circuit.assert_verify(l.konst(d.rx), l.konst(d.px),
                         l.konst(wit.e_), w);

  EXPECT_TRUE(ebk.assertion_failed())
      << "Scalar s >= n should be rejected even when the group equation holds";
}

// ====================== Mutation Tests ==================================

TEST(Bip340MutationTest, PrivateWitnessMutations) {
  using EvalBackend = EvaluationBackend<Field>;
  using LogicType = Logic<Field, EvalBackend>;
  using EltW = typename LogicType::EltW;
  using VerifyC = Bip340Verify<LogicType, Field, EC>;

  const Field& F = p256k1_base;
  const EC& ec = p256k1;

  auto d = MakeTestData();
  Bip340Witness wit(ec);
  ASSERT_TRUE(wit.compute_from_scalars(d.s_nat, d.e_nat, d.px, d.py));

  // Test each mutation: build eval circuit, mutate one witness field,
  // assert circuit rejects.
  auto run_mutation = [&](const char* name,
                          std::function<void(typename VerifyC::Witness&,
                                             const LogicType&)> mutate) {
    const EvalBackend ebk(F, false);
    const LogicType l(&ebk, F);
    VerifyC circuit(l, ec);

    auto w = MakeEvalWitness<LogicType, VerifyC>(l, wit);
    mutate(w, l);

    circuit.assert_verify(l.konst(d.rx), l.konst(d.px),
                           l.konst(wit.e_), w);
    EXPECT_TRUE(ebk.assertion_failed())
        << "Mutation '" << name << "' should be rejected";
  };

  run_mutation("flip bits_s[10]", [&](auto& w, const auto& l) {
    w.bits_s[10] = l.konst(F.subf(F.one(), wit.bits_s_[10]));
  });
  run_mutation("flip bits_e[20]", [&](auto& w, const auto& l) {
    w.bits_e[20] = l.konst(F.subf(F.one(), wit.bits_e_[20]));
  });
  // Use the last intermediate (index 254) which is non-trivial
  // for typical scalar values (not the point at infinity).
  run_mutation("corrupt int_sx[254]", [&](auto& w, const auto& l) {
    w.int_sx[254] = l.konst(F.zero());
  });
  run_mutation("corrupt int_sy[254]", [&](auto& w, const auto& l) {
    w.int_sy[254] = l.konst(F.zero());
  });
  run_mutation("corrupt int_sz[254]", [&](auto& w, const auto& l) {
    w.int_sz[254] = l.konst(F.zero());
  });
  run_mutation("negate py", [&](auto& w, const auto& l) {
    w.py = l.konst(F.negf(wit.py_));
  });
  run_mutation("corrupt bits_ry[0]", [&](auto& w, const auto& l) {
    w.bits_ry[0] = l.konst(F.subf(F.one(), wit.bits_ry_[0]));
  });
  run_mutation("set rz_inv to zero", [&](auto& w, const auto& l) {
    w.rz_inv = l.konst(F.zero());
  });
  run_mutation("corrupt int_ey[254]", [&](auto& w, const auto& l) {
    w.int_ey[254] = l.konst(F.zero());
  });
}

TEST(Bip340MutationTest, PublicInputMutations) {
  using EvalBackend = EvaluationBackend<Field>;
  using LogicType = Logic<Field, EvalBackend>;
  using VerifyC = Bip340Verify<LogicType, Field, EC>;

  const Field& F = p256k1_base;
  const EC& ec = p256k1;

  auto d = MakeTestData();
  Bip340Witness wit(ec);
  ASSERT_TRUE(wit.compute_from_scalars(d.s_nat, d.e_nat, d.px, d.py));

  // Wrong rx.
  {
    const EvalBackend ebk(F, false);
    const LogicType l(&ebk, F);
    VerifyC circuit(l, ec);
    auto w = MakeEvalWitness<LogicType, VerifyC>(l, wit);
    circuit.assert_verify(l.konst(F.negf(d.rx)), l.konst(d.px),
                           l.konst(wit.e_), w);
    EXPECT_TRUE(ebk.assertion_failed()) << "Wrong rx should be rejected";
  }
  // Wrong px.
  {
    const EvalBackend ebk(F, false);
    const LogicType l(&ebk, F);
    VerifyC circuit(l, ec);
    auto w = MakeEvalWitness<LogicType, VerifyC>(l, wit);
    circuit.assert_verify(l.konst(d.rx), l.konst(F.negf(d.px)),
                           l.konst(wit.e_), w);
    EXPECT_TRUE(ebk.assertion_failed()) << "Wrong px should be rejected";
  }
  // Wrong e.
  {
    const EvalBackend ebk(F, false);
    const LogicType l(&ebk, F);
    VerifyC circuit(l, ec);
    auto w = MakeEvalWitness<LogicType, VerifyC>(l, wit);
    Elt wrong_e = F.addf(wit.e_, F.one());
    circuit.assert_verify(l.konst(d.rx), l.konst(d.px),
                           l.konst(wrong_e), w);
    EXPECT_TRUE(ebk.assertion_failed()) << "Wrong e should be rejected";
  }
}

class Bip340ZkTest : public ::testing::Test {
 protected:
  using CompilerBackendType = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackendType>;
  using EltW = typename LogicCircuit::EltW;
  using VerifyC = Bip340Verify<LogicCircuit, Field, EC>;

  const Field& F = p256k1_base;
  const EC& ec = p256k1;

  std::pair<std::unique_ptr<Circuit<Field>>, size_t> make_circuit_with_quads() {
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
    return {Q.mkcircuit(1), Q.nquad_terms_};
  }

  void run_zk_test(const Nat& s_nat, const Nat& e_nat,
                   const Elt& px, const Elt& py, const Elt& rx) {
    Bip340Witness wit(ec);
    ASSERT_TRUE(wit.compute_from_scalars(s_nat, e_nat, px, py));

    auto [circuit, nquad] = make_circuit_with_quads();

    // CRT guard: ensure block_enc fits within 2^22 FFT order.
    {
      using Crt = CRT256<Field>;
      size_t block_enc = circuit->ninputs - circuit->npub_in + nquad + 1;
      auto err = check_crt_block_enc<Crt>(block_enc);
      ASSERT_TRUE(err.empty()) << "CRT capacity: " << err;
    }

    auto W = std::make_unique<Dense<Field>>(1, circuit->ninputs);

    // Fill prover witness.
    {
      DenseFiller<Field> filler(*W);
      PushBip340PublicInputs(filler, F, rx, px, wit.e_);
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
      PushBip340PublicInputs(filler, F, rx, px, wit.e_);
    }

    ZkVerifier<Field, RSFactory> verifier(*circuit, rsf, kRate, kQueries, F);
    verifier.recv_commitment(zkpr, tv);
    EXPECT_TRUE(verifier.verify(zkpr, pub, tv));
    log(INFO, "BIP-340 Verifier done");
  }

  Bip340TestData setup_test_data(Nat s_nat = Nat(2ull),
                                 Nat e_nat = Nat(1ull),
                                 Nat sk = Nat(1ull)) {
    return MakeTestData(s_nat, e_nat, sk);
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

  auto circuit = make_circuit_with_quads().first;
  auto W = std::make_unique<Dense<Field>>(1, circuit->ninputs);
  {
    DenseFiller<Field> filler(*W);
    PushBip340PublicInputs(filler, F, d.rx, d.px, wit.e_);
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
    PushBip340PublicInputs(filler, F, wrong_rx, d.px, wit.e_);
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

// ===================== CRT Parameter Guard ==============================

// ===================== Randomized Test ==================================

TEST(Bip340RandomizedTest, DeterministicSmallScalarCases) {
  using EvalBackend = EvaluationBackend<Field>;
  using LogicType = Logic<Field, EvalBackend>;
  using VerifyC = Bip340Verify<LogicType, Field, EC>;

  const Field& F = p256k1_base;
  const EC& ec = p256k1;
  constexpr size_t kNumCases = 32;

  // Deterministic seed: small consecutive values, not randomness.
  size_t collected = 0;
  for (uint64_t sk = 1; sk < 300 && collected < kNumCases; ++sk) {
    for (uint64_t s = 1; s < 300 && collected < kNumCases; ++s) {
      for (uint64_t e = 1; e < 20 && collected < kNumCases; ++e) {
        Nat sk_nat(sk), s_nat(s), e_nat(e);
        auto G = ec.generator();
        auto P = ec.scalar_multf(G, sk_nat);
        ec.normalize(P);

        // Pick even py.
        Nat exp_n("0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c");
        Elt x2 = F.mulf(P.x, P.x);
        Elt x3 = F.mulf(x2, P.x);
        Elt y2 = F.addf(x3, ec.b_);
        Elt py = F.one(), base = y2;
        for (int i = 255; i >= 0; --i) { py = F.mulf(py, py); if (exp_n.bit(i)) py = F.mulf(py, base); }
        if (F.from_montgomery(py).bit(0) != 0) py = F.negf(py);
        if (F.mulf(py, py) != y2) continue;  // P.x not liftable

        // Compute R from the witness's own intermediates (same algorithm
        // as the circuit's double-and-add, so projective coords match).
        Bip340Witness wit(ec);
        ASSERT_TRUE(wit.compute_from_scalars(s_nat, e_nat, P.x, py));

        // Extract final sG and eP from witness intermediates.
        typename EC::ECPoint sG_pt = {
            wit.int_sx_[Bip340Witness::kBits - 1],
            wit.int_sy_[Bip340Witness::kBits - 1],
            wit.int_sz_[Bip340Witness::kBits - 1]};
        typename EC::ECPoint eP_pt = {
            wit.int_ex_[Bip340Witness::kBits - 1],
            wit.int_ey_[Bip340Witness::kBits - 1],
            wit.int_ez_[Bip340Witness::kBits - 1]};

        // R = sG - eP.
        auto neg_ep = typename EC::ECPoint{eP_pt.x, F.negf(eP_pt.y), eP_pt.z};
        ec.addE(sG_pt, neg_ep);
        ec.normalize(sG_pt);

        // Skip cases with odd R.y.
        if (F.from_montgomery(sG_pt.y).bit(0) != 0) continue;
        Elt rx = sG_pt.x;

        const EvalBackend ebk(F, true);
        const LogicType l(&ebk, F);
        VerifyC circuit(l, ec);
        auto w = MakeEvalWitness<LogicType, VerifyC>(l, wit);
        circuit.assert_verify(l.konst(rx), l.konst(P.x), l.konst(wit.e_), w);
        ASSERT_FALSE(ebk.assertion_failed())
            << "sk=" << sk << " s=" << s << " e=" << e;
        ++collected;
      }
    }
  }
  log(INFO, "Randomized test: %zu even-R cases collected", collected);
  EXPECT_GE(collected, kNumCases);
}

// ===================== Proof Tamper Test =================================

TEST(Bip340TamperTest, TamperedProofFailsVerification) {
  set_log_level(INFO);
  const Field& F = p256k1_base;
  const EC& ec = p256k1;

  const auto& tv = kRealVectors[0];
  auto pk = hex_vec(tv.pk_hex);
  auto msg = hex_vec(tv.msg_hex);
  auto sig = hex_vec(tv.sig_hex);

  Bip340Witness wit(ec);
  ASSERT_TRUE(wit.compute(sig.data(), pk.data(), msg.data(), msg.size()));

  using CompilerBackendType = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackendType>;
  using VerifyCC = Bip340Verify<LogicCircuit, Field, EC>;

  QuadCircuit<Field> Q(F);
  const CompilerBackendType cbk(&Q);
  const LogicCircuit lc(&cbk, F);
  VerifyCC circuit(lc, ec);

  auto rxx = lc.eltw_input();
  auto pxx = lc.eltw_input();
  auto ee = lc.eltw_input();
  Q.private_input();
  typename VerifyCC::Witness w;
  w.input(lc);
  circuit.assert_verify(rxx, pxx, ee, w);
  auto CIRCUIT = Q.mkcircuit(1);

  // CRT guard.
  {
    using Crt = CRT256<Field>;
    size_t block_enc = CIRCUIT->ninputs - CIRCUIT->npub_in +
                       Q.nquad_terms_ + 1;
    auto err = check_crt_block_enc<Crt>(block_enc);
    ASSERT_TRUE(err.empty()) << "CRT capacity: " << err;
  }

  auto W = std::make_unique<Dense<Field>>(1, CIRCUIT->ninputs);
  {
    DenseFiller<Field> filler(*W);
    PushBip340PublicInputs(filler, F,
        F.to_montgomery(Bip340Witness::nat_from_be_bytes(sig.data())),
        F.to_montgomery(Bip340Witness::nat_from_be_bytes(pk.data())),
        wit.e_);
    wit.fill_witness(filler);
  }

  using Crt = CRT256<Field>;
  using ConvolutionFactory = CrtConvolutionFactory<Crt, Field>;
  using RSFactory = ReedSolomonFactory<Field, ConvolutionFactory>;

  ConvolutionFactory factory(F);
  RSFactory rsf(factory, F);

  Transcript tp((uint8_t*)"bip340 tamper", 13);
  SecureRandomEngine rng;

  ZkProof<Field> zkpr(*CIRCUIT, kRate, kQueries);
  ZkProver<Field, RSFactory> prover(*CIRCUIT, F, rsf);
  prover.commit(zkpr, *W, tp, rng);
  prover.prove(zkpr, *W, tp);

  // Serialize to bytes, corrupt one byte, read back.
  std::vector<uint8_t> buf;
  zkpr.write(buf, F);
  ASSERT_GE(buf.size(), 20u) << "Proof too small to tamper";
  buf[10] ^= 0xFF;  // flip all bits of byte 10

  ReadBuffer rbuf(buf);
  ZkProof<Field> zkpr_tampered(*CIRCUIT, kRate, kQueries);
  ASSERT_TRUE(zkpr_tampered.read(rbuf, F)) << "Failed to read tampered proof";

  // Verification with tampered proof must fail.
  Transcript tv2((uint8_t*)"bip340 tamper", 13);
  auto pub = Dense<Field>(1, CIRCUIT->npub_in);
  {
    DenseFiller<Field> filler(pub);
    PushBip340PublicInputs(filler, F,
        F.to_montgomery(Bip340Witness::nat_from_be_bytes(sig.data())),
        F.to_montgomery(Bip340Witness::nat_from_be_bytes(pk.data())),
        wit.e_);
  }

  ZkVerifier<Field, RSFactory> verifier(*CIRCUIT, rsf, kRate, kQueries, F);
  verifier.recv_commitment(zkpr_tampered, tv2);
  EXPECT_FALSE(verifier.verify(zkpr_tampered, pub, tv2))
      << "Tampered proof should fail verification";
}

// ===================== CRT Parameter Guard ==============================

TEST(Bip340GuardTest, AcceptsReasonableBlockEnc) {
  using Crt = CRT256<Field>;
  // block_enc = 1024 -> padding = 1024 < 2^22.
  EXPECT_TRUE(check_crt_block_enc<Crt>(1024).empty());
  // block_enc = 2^22 -> padding = 2^22, exactly at limit.
  EXPECT_TRUE(check_crt_block_enc<Crt>(1ull << 22).empty());
}

TEST(Bip340GuardTest, RejectsExcessiveBlockEnc) {
  using Crt = CRT256<Field>;
  // block_enc = 2^22 + 1 -> padding = 2^23, exceeds 2^22.
  auto err = check_crt_block_enc<Crt>((1ull << 22) + 1);
  EXPECT_FALSE(err.empty());
  EXPECT_NE(err.find("exceeds"), std::string::npos);
}

// ===================== Parameter Measurement ============================

TEST(Bip340ParamTest, ReportCircuitParams) {
  using CompilerBackendType = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackendType>;
  using EltW = typename LogicCircuit::EltW;
  using VerifyC = Bip340Verify<LogicCircuit, Field, EC>;

  QuadCircuit<Field> Q(p256k1_base);
  const CompilerBackendType cbk(&Q);
  const LogicCircuit lc(&cbk, p256k1_base);
  VerifyC circuit(lc, p256k1);

  EltW rx = lc.eltw_input();
  EltW px = lc.eltw_input();
  EltW e = lc.eltw_input();

  typename VerifyC::Witness w;
  Q.private_input();
  w.input(lc);

  circuit.assert_verify(rx, px, e, w);
  auto C = Q.mkcircuit(1);

  // Detailed parameter report.
  size_t nwires = Q.nwires_;
  size_t nquad = Q.nquad_terms_;
  size_t depth = Q.depth_;
  size_t nin = Q.ninput_;
  size_t npriv = C->ninputs - C->npub_in;
  size_t npub = C->npub_in;

  log(INFO, "BIP-340 Circuit Parameters:");
  log(INFO, "  wires(total)=%zu", nwires);
  log(INFO, "  quad_terms=%zu", nquad);
  log(INFO, "  depth=%zu", depth);
  log(INFO, "  inputs(total)=%zu", nin);
  log(INFO, "  public_inputs=%zu", npub);
  log(INFO, "  private_inputs=%zu", npriv);

  // The circuit should produce non-trivial parameters.
  EXPECT_GT(nwires, 1000);
  EXPECT_GT(nquad, 100);
  EXPECT_GT(depth, 0u);

  // Check LigeroParam-like derived values.
  // nw = number of witness elements ; nq = quadr constraints.
  // block_enc = (nw + nq + 1) rounded up for RS encoding.
  size_t nw_approx = npriv;
  size_t nq_approx = nquad;
  size_t block_enc_approx = nw_approx + nq_approx + 1;
  size_t pad = next_power_of_two(block_enc_approx);

  log(INFO, "  estimated block_enc=%zu, padding=%zu", block_enc_approx, pad);

  using Crt = CRT256<Field>;
  auto err = check_crt_block_enc<Crt>(block_enc_approx);
  EXPECT_TRUE(err.empty())
      << "BIP-340 circuit block_enc exceeds CRT capacity: " << err;
}

// ===================== Scale Smoke Test =================================

TEST(Bip340ScaleTest, MultiInstanceProof) {
  // Run a ZK proof with 2 instances to verify scaling works.
  set_log_level(INFO);

  using CompilerBackendType = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackendType>;
  using EltW = typename LogicCircuit::EltW;
  using VerifyC = Bip340Verify<LogicCircuit, Field, EC>;

  constexpr size_t kNumInstances = 2;

  // Build circuit with multiple BIP-340 verification instances.
  QuadCircuit<Field> Q(p256k1_base);
  const CompilerBackendType cbk(&Q);
  const LogicCircuit lc(&cbk, p256k1_base);
  VerifyC circuit(lc, p256k1);

  std::vector<typename VerifyC::Witness> ws(kNumInstances);
  std::vector<EltW> rxs(kNumInstances);
  std::vector<EltW> pxs(kNumInstances);
  std::vector<EltW> es(kNumInstances);

  for (size_t i = 0; i < kNumInstances; ++i) {
    rxs[i] = lc.eltw_input();
    pxs[i] = lc.eltw_input();
    es[i] = lc.eltw_input();
  }
  Q.private_input();
  for (size_t i = 0; i < kNumInstances; ++i) {
    ws[i].input(lc);
  }
  for (size_t i = 0; i < kNumInstances; ++i) {
    circuit.assert_verify(rxs[i], pxs[i], es[i], ws[i]);
  }
  auto CIRCUIT = Q.mkcircuit(1);

  dump_info("bip340 multi", Q);

  // Check CRT capacity.
  using Crt = CRT256<Field>;
  size_t block_enc_approx = CIRCUIT->ninputs - CIRCUIT->npub_in +
                            Q.nquad_terms_ + 1;
  auto err = check_crt_block_enc<Crt>(block_enc_approx);
  ASSERT_TRUE(err.empty()) << "Scale test exceeds CRT capacity: " << err;

  // Prepare witness data.
  auto d = MakeTestData();

  Bip340Witness wit(p256k1);
  ASSERT_TRUE(wit.compute_from_scalars(d.s_nat, d.e_nat, d.px, d.py));

  auto W = std::make_unique<Dense<Field>>(1, CIRCUIT->ninputs);
  {
    DenseFiller<Field> filler(*W);
    filler.push_back(p256k1_base.one());
    for (size_t i = 0; i < kNumInstances; ++i) {
      filler.push_back(d.rx);
      filler.push_back(d.px);
      filler.push_back(wit.e_);
    }
    for (size_t i = 0; i < kNumInstances; ++i) {
      wit.fill_witness(filler);
    }
  }

  using ConvolutionFactory = CrtConvolutionFactory<Crt, Field>;
  using RSFactory = ReedSolomonFactory<Field, ConvolutionFactory>;

  ConvolutionFactory factory(p256k1_base);
  RSFactory rsf(factory, p256k1_base);

  Transcript tp((uint8_t*)"bip340 scale", 12);
  SecureRandomEngine rng;

  ZkProof<Field> zkpr(*CIRCUIT, kRate, kQueries);
  ZkProver<Field, RSFactory> prover(*CIRCUIT, p256k1_base, rsf);
  prover.commit(zkpr, *W, tp, rng);
  prover.prove(zkpr, *W, tp);
  log(INFO, "BIP-340 scale prover done (%zu instances)", kNumInstances);

  // Verifier.
  Transcript tv((uint8_t*)"bip340 scale", 12);
  auto pub = Dense<Field>(1, CIRCUIT->npub_in);
  {
    DenseFiller<Field> filler(pub);
    filler.push_back(p256k1_base.one());
    for (size_t i = 0; i < kNumInstances; ++i) {
      filler.push_back(d.rx);
      filler.push_back(d.px);
      filler.push_back(wit.e_);
    }
  }

  ZkVerifier<Field, RSFactory> verifier(*CIRCUIT, rsf, kRate, kQueries,
                                         p256k1_base);
  verifier.recv_commitment(zkpr, tv);
  EXPECT_TRUE(verifier.verify(zkpr, pub, tv));
  log(INFO, "BIP-340 scale verifier done");
}

}  // namespace
}  // namespace proofs
