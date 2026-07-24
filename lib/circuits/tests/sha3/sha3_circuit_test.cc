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

#include "circuits/tests/sha3/sha3_circuit.h"

#include <stddef.h>

#include <cstdint>
#include <memory>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp.h"
#include "algebra/fp24.h"
#include "algebra/fp24_6.h"
#include "algebra/reed_solomon.h"
#include "algebra/reed_solomon_extension.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/sha3/sha3_reference.h"
#include "circuits/tests/sha3/sha3_slicing.h"
#include "circuits/tests/sha3/sha3_witness.h"
#include "circuits/tests/sha3/shake_test_vectors.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "sumcheck/prover.h"
#include "util/log.h"
#include "util/panic.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_testing.h"
#include "zk/zk_verifier.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
using Field = Fp24_6;
const Fp24 BaseF(8380417);
const Field F(BaseF, /*beta=*/7);
typedef CompilerBackend<Field> CompilerBackend;
typedef Logic<Field, CompilerBackend> LogicCircuit;
typedef LogicCircuit::BitW bitWC;
typedef typename LogicCircuit::template bitvec<64> v64;

typedef EvaluationBackend<Field> EvalBackend;
typedef Logic<Field, EvalBackend> Logic;
typedef Logic::BitW bitW;

std::unique_ptr<Circuit<Field>> mk_keccak_circuit(size_t nc) {
  set_log_level(INFO);
  QuadCircuit<Field> Q(F);
  const CompilerBackend cbk(&Q);
  const LogicCircuit LC(&cbk, F);
  Sha3Circuit<LogicCircuit> SHAC(LC);

  struct awrap {
    v64 a[5][5];
  };

  auto aw = std::make_unique<awrap>();
  for (size_t x = 0; x < 5; ++x) {
    for (size_t y = 0; y < 5; ++y) {
      aw->a[x][y] = LC.vinput<64>();
    }
  }

  SHAC.keccak_f_1600(aw->a);
  for (size_t x = 0; x < 5; ++x) {
    for (size_t y = 0; y < 5; ++y) {
      LC.voutput(aw->a[x][y], 64 * (y + 5 * x));
    }
  }

  auto CIRCUIT = Q.mkcircuit(nc);
  dump_info("sha3", Q);

  return CIRCUIT;
}

std::unique_ptr<Circuit<Field>> mk_keccak_witness_circuit(size_t nc) {
  set_log_level(INFO);
  QuadCircuit<Field> Q(F);
  const CompilerBackend cbk(&Q);
  const LogicCircuit LC(&cbk, F);
  Sha3Circuit<LogicCircuit> SHAC(LC);

  struct awrap {
    v64 a[5][5];
  };

  auto aw = std::make_unique<awrap>();
  for (size_t x = 0; x < 5; ++x) {
    for (size_t y = 0; y < 5; ++y) {
      aw->a[x][y] = LC.vinput<64>();
    }
  }

  typename Sha3Circuit<LogicCircuit>::BlockWitness bw;
  bw.input(LC);

  SHAC.keccak_f_1600(aw->a, bw);
  for (size_t x = 0; x < 5; ++x) {
    for (size_t y = 0; y < 5; ++y) {
      LC.voutput(aw->a[x][y], 64 * (y + 5 * x));
    }
  }

  auto CIRCUIT = Q.mkcircuit(nc);
  dump_info("sha3_witness", nc, 1, Q);

  return CIRCUIT;
}

TEST(SHA3_Circuit, Keccak_F_1600_Witness_Size) {
  auto CIRCUIT = mk_keccak_witness_circuit(1);
}

TEST(SHA3_Circuit, Keccak_F_1600) {
  constexpr size_t nc = 1;
  const EvalBackend ebk(F);
  const Logic L(&ebk, F);

  auto CIRCUIT = mk_keccak_circuit(nc);

  uint64_t st[5][5];
  auto W = std::make_unique<Dense<Field>>(nc, /*constant one*/ 1 + 64 * 5 * 5);
  W->v_[0] = F.one();
  for (size_t x = 0; x < 5; ++x) {
    for (size_t y = 0; y < 5; ++y) {
      st[x][y] = 3 * x + 1000 * y;
      for (size_t z = 0; z < 64; ++z) {
        W->v_[1 + z + 64 * (y + 5 * x)] =
            L.eval(L.bit((st[x][y] >> z) & 1)).elt();
      }
    }
  }

  Sha3Reference::keccak_f_1600_DEBUG_ONLY(st);
  Prover<Field>::inputs pin;
  Prover<Field> prover(F);
  auto V = prover.eval_circuit(&pin, CIRCUIT.get(), W->clone(), F);
  for (size_t x = 0; x < 5; ++x) {
    for (size_t y = 0; y < 5; ++y) {
      for (size_t z = 0; z < 64; ++z) {
        EXPECT_EQ(V->v_[z + 64 * (y + 5 * x)],
                  L.eval(L.bit((st[x][y] >> z) & 1)).elt());
      }
    }
  }
}

TEST(SHA3_Circuit, Keccak_F_1600_Copies) {
  constexpr size_t nc = 23;
  const EvalBackend ebk(F);
  const Logic L(&ebk, F);

  auto CIRCUIT = mk_keccak_circuit(nc);

  struct State {
    uint64_t s[5][5];
  };
  std::vector<State> st(nc);
  auto W = std::make_unique<Dense<Field>>(nc, /*constant one*/ 1 + 64 * 5 * 5);
  for (size_t c = 0; c < nc; ++c) {
    W->v_[0 * nc + c] = F.one();
    for (size_t x = 0; x < 5; ++x) {
      for (size_t y = 0; y < 5; ++y) {
        st[c].s[x][y] = 3 * x + 1000 * y + 1000000 * c;
        for (size_t z = 0; z < 64; ++z) {
          W->v_[(1 + z + 64 * (y + 5 * x)) * nc + c] =
              L.eval(L.bit((st[c].s[x][y] >> z) & 1)).elt();
        }
      }
    }
  }

  {
    Prover<Field>::inputs pin;
    Prover<Field> prover(F);
    auto V = prover.eval_circuit(&pin, CIRCUIT.get(), W->clone(), F);

    for (size_t c = 0; c < nc; ++c) {
      Sha3Reference::keccak_f_1600_DEBUG_ONLY(st[c].s);
      for (size_t x = 0; x < 5; ++x) {
        for (size_t y = 0; y < 5; ++y) {
          for (size_t z = 0; z < 64; ++z) {
            EXPECT_EQ(V->v_[(z + 64 * (y + 5 * x)) * nc + c],
                      L.eval(L.bit((st[c].s[x][y] >> z) & 1)).elt());
          }
        }
      }
    }
  }
}

TEST(SHA3_Circuit, AssertShake256) {
  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  Sha3Circuit<Logic> SHAC(L);

  for (const auto& vec : sha3::GetShake256TestVectors()) {
    std::vector<Logic::v8> seed;
    for (uint8_t byte : vec.in) {
      seed.push_back(L.vbit8(byte));
    }

    std::vector<Logic::v8> output;

    std::vector<Sha3Witness::BlockWitness> bws;
    Sha3Witness::compute_witness_shake256(vec.in, vec.out.size(), bws);

    // Create circuit-compatible witnesses
    std::vector<Sha3Circuit<Logic>::BlockWitness> circuit_bws(bws.size());
    for (size_t k = 0; k < bws.size(); ++k) {
      for (size_t round = 0; round < 24; ++round) {
        if (sha3_slice_at(round)) {
          for (size_t x = 0; x < 5; ++x) {
            for (size_t y = 0; y < 5; ++y) {
              for (size_t b = 0; b < 64; ++b) {
                circuit_bws[k].a_intermediate[round][x][y][b] =
                    L.bit((bws[k].a_intermediate[round][x][y] >> b) & 1);
              }
            }
          }
        }
      }
    }

    SHAC.assert_shake256(seed, vec.out.size(), output, circuit_bws);

    EXPECT_EQ(output.size(), vec.out.size());
    for (size_t i = 0; i < vec.out.size(); ++i) {
      uint8_t val = 0;
      for (int j = 0; j < 8; ++j) {
        if (L.eval(output[i][j]).elt() == F.one()) {
          val |= (1 << j);
        }
      }
      EXPECT_EQ(val, vec.out[i]);
    }
  }
}

TEST(SHA3_Circuit, AssertKeccak256EthereumAddress) {
  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  Sha3Circuit<Logic> SHAC(L);

  static const uint8_t pubkey[64] = {
      0x2e, 0x30, 0x8d, 0x25, 0xd2, 0x7f, 0x4c, 0x59, 0x5c, 0x4a, 0x75,
      0x43, 0x25, 0x3f, 0x3c, 0x23, 0x50, 0xc9, 0xd3, 0x23, 0xbc, 0xd5,
      0x02, 0x29, 0xc8, 0x37, 0x68, 0x1f, 0x08, 0xda, 0x6a, 0x33, 0xb8,
      0xab, 0x23, 0x8f, 0xae, 0xcd, 0x9c, 0xf2, 0xa7, 0x35, 0x9e, 0x6a,
      0x69, 0x08, 0x97, 0x10, 0x87, 0x6a, 0xb1, 0x36, 0xab, 0x01, 0x7f,
      0x88, 0x50, 0x5c, 0x03, 0x51, 0x6c, 0xc0, 0x99, 0xc6,
  };
  // Expected: last 20 bytes of keccak256(pubkey), i.e., digest[12..31].
  static const uint8_t expected_addr[20] = {
      0xb9, 0x0d, 0x65, 0xa6, 0x24, 0x90, 0x9b, 0xc3, 0x6e, 0xee,
      0x6b, 0xff, 0xde, 0xcf, 0x3c, 0x5a, 0xcd, 0x77, 0x74, 0xc0,
  };

  std::vector<Logic::v8> seed;
  for (uint8_t byte : pubkey) seed.push_back(L.vbit8(byte));

  std::vector<Sha3Witness::BlockWitness> bws;
  Sha3Witness::compute_witness_keccak256(
      std::vector<uint8_t>(pubkey, pubkey + 64), bws);

  std::vector<Sha3Circuit<Logic>::BlockWitness> circuit_bws(bws.size());
  for (size_t k = 0; k < bws.size(); ++k) {
    for (size_t round = 0; round < 24; ++round) {
      if (sha3_slice_at(round)) {
        for (size_t x = 0; x < 5; ++x) {
          for (size_t y = 0; y < 5; ++y) {
            for (size_t b = 0; b < 64; ++b) {
              circuit_bws[k].a_intermediate[round][x][y][b] =
                  L.bit((bws[k].a_intermediate[round][x][y] >> b) & 1);
            }
          }
        }
      }
    }
  }

  std::vector<Logic::v8> hash_out;
  SHAC.assert_keccak256(seed, hash_out, circuit_bws);

  ASSERT_EQ(hash_out.size(), 32u);

  // Ethereum address is hash_out[12..31].
  for (size_t i = 0; i < 20; ++i) {
    uint8_t val = 0;
    for (int j = 0; j < 8; ++j) {
      if (L.eval(hash_out[12 + i][j]).elt() == F.one()) val |= (1 << j);
    }
    EXPECT_EQ(val, expected_addr[i]) << "address byte " << i << " mismatch";
  }
}

template <class Field>
std::unique_ptr<Circuit<Field>> make_shake256_circuit(size_t seed_size,
                                                      size_t out_size,
                                                      const Field& F) {
  // Check the simplest case.
  check(seed_size < 136, "seed too long");
  check(out_size < 136, "output too long");
  size_t numblocks = 1;
  set_log_level(INFO);
  QuadCircuit<Field> Q(F);
  using CompilerBackend = proofs::CompilerBackend<Field>;
  using LogicCircuit = proofs::Logic<Field, CompilerBackend>;
  const CompilerBackend cbk(&Q);
  const LogicCircuit LC(&cbk, F);
  Sha3Circuit<LogicCircuit> SHAC(LC);

  std::vector<typename LogicCircuit::v8> seed(seed_size);
  for (size_t i = 0; i < seed_size; ++i) {
    seed[i] = LC.template vinput<8>();
  }

  std::vector<typename LogicCircuit::v8> want(out_size);
  for (size_t i = 0; i < out_size; ++i) {
    want[i] = LC.template vinput<8>();
  }

  std::vector<typename LogicCircuit::v8> out;

  // For the compiled circuit length test, we just provide free input wires.
  std::vector<typename Sha3Circuit<LogicCircuit>::BlockWitness> circuit_bws(
      numblocks);
  for (size_t k = 0; k < numblocks; ++k) {
    circuit_bws[k].input(LC);
  }

  SHAC.assert_shake256(seed, out_size, out, circuit_bws);

  EXPECT_EQ(out.size(), out_size);
  for (size_t i = 0; i < out_size; ++i) {
    LC.vassert_eq(want[i], out[i]);
  }

  auto CIRCUIT = Q.mkcircuit(1);
  dump_info("shake256_nc_blocks", 1, numblocks, Q);

  return CIRCUIT;
}

TEST(SHA3_Circuit, CircuitSizeShake256) {
  auto CIRCUIT = make_shake256_circuit<Field>(32, 64, F);
}

// Shake256 scaffold for tests and benchmarks.
// This scaffold hardcodes one of the examples from the SHAKE256 test vectors.
template <typename Field, typename RSFactory>
struct ShakeProverSystem {
  const Field& f;
  const RSFactory& rsf;
  std::unique_ptr<Circuit<Field>> circuit;
  size_t num_blocks;
  SecureRandomEngine rng;
  std::unique_ptr<ZkProof<Field>> zkpr;

  ShakeProverSystem(size_t numBlocks, const Field& f, const RSFactory& r)
      : f(f),
        rsf(r),
        // These input/output lengths are hard-coded to match the 2nd example.
        circuit(make_shake256_circuit<Field>(3, 33, f)),
        num_blocks(numBlocks) {}

  bool Prove() {
    auto vectors = sha3::GetShake256TestVectors();
    std::vector<uint8_t> seed = vectors[1].in;
    std::vector<uint8_t> want = vectors[1].out;
    check(seed.size() == 3, "seed must be 32 bytes");
    check(want.size() == 33, "want too long");
    zkpr = std::make_unique<ZkProof<Field>>(*circuit, kLigeroRate, kLigeroNreq);
    Dense<Field> w(1, circuit->ninputs);
    DenseFiller<Field> filler(w);
    filler.push_back(f.one());
    // Fill seed
    for (size_t i = 0; i < seed.size(); ++i) {
      filler.push_back(seed[i], 8, f);
    }

    // Fill want
    for (size_t i = 0; i < want.size(); ++i) {
      filler.push_back(want[i], 8, f);
    }

    // Fill witnesses
    std::vector<Sha3Witness::BlockWitness> bws;
    Sha3Witness::compute_witness_shake256(seed, want.size(), bws);
    Sha3Witness::fill_witness(filler, bws, f);

    ZkProver<Field, RSFactory> prover(*circuit, f, rsf);
    Transcript tp((uint8_t*)"test", 4);
    prover.commit(*zkpr, w, tp, rng);
    return prover.prove(*zkpr, w, tp);
  }

  bool Verify() {
    ZkVerifier<Field, RSFactory> verifier(*circuit, rsf, kLigeroRate,
                                          kLigeroNreq, f);
    Transcript tv((uint8_t*)"test", 4);
    verifier.recv_commitment(*zkpr, tv);
    Dense<Field> pub(1, 0);
    return verifier.verify(*zkpr, pub, tv);
  }
};

// ==================== 1 block SHAKE256 tests over 2 fields

TEST(SHA3_Circuit, ZkProverAndVerifierTest_GF2_128) {
  using f_128 = GF2_128<>;
  const f_128 Fs;
  using RSFactory = LCH14ReedSolomonFactory<f_128>;
  const RSFactory rsf(Fs);

  ShakeProverSystem<f_128, RSFactory> sys(1, Fs, rsf);

  EXPECT_TRUE(sys.Prove());
  EXPECT_TRUE(sys.Verify());
}

TEST(SHA3_Circuit, ZkProverAndVerifierTest_Fp64) {
  using Field = Fp<1>;
  const Field F("18446744069414584321");
  using ConvolutionFactory = FFTConvolutionFactory<Field>;
  using RSFactory = ReedSolomonFactory<Field, ConvolutionFactory>;

  const ConvolutionFactory conv_factory(F, F.of_scalar(1753635133440165772ull),
                                        1ull << 32);
  const RSFactory rs_factory(conv_factory, F);

  ShakeProverSystem<Field, RSFactory> sys(1, F, rs_factory);
  EXPECT_TRUE(sys.Prove());
  EXPECT_TRUE(sys.Verify());
}

TEST(SHA3_Circuit, ZkProverAndVerifierTest_Fp24_6) {
  using Field = Fp24_6;
  const Fp24 BaseF(8380417);
  const Field F(BaseF, /*beta=*/7);

  ReedSolomonExtensionFactory rsextf(BaseF);

  ShakeProverSystem<Field, ReedSolomonExtensionFactory> sys(1, F, rsextf);
  EXPECT_TRUE(sys.Prove());
  EXPECT_TRUE(sys.Verify());
}

// ==================== Benchmarks ====================

void BM_ShakeProver_GF2_128(benchmark::State& state) {
  using f_128 = GF2_128<>;
  const f_128 Fs;
  using RSFactory = LCH14ReedSolomonFactory<f_128>;
  const RSFactory rsf(Fs);

  ShakeProverSystem<f_128, RSFactory> sys(1, Fs, rsf);
  set_log_level(ERROR);
  for (auto _ : state) {
    sys.Prove();
  }
}
BENCHMARK(BM_ShakeProver_GF2_128);

void BM_ShakeProver_Fp64(benchmark::State& state) {
  using Field = Fp<1>;
  const Field F("18446744069414584321");
  using ConvolutionFactory = FFTConvolutionFactory<Field>;
  using RSFactory = ReedSolomonFactory<Field, ConvolutionFactory>;

  const ConvolutionFactory conv_factory(F, F.of_scalar(1753635133440165772ull),
                                        1ull << 32);
  const RSFactory rs_factory(conv_factory, F);

  ShakeProverSystem<Field, RSFactory> sys(1, F, rs_factory);
  set_log_level(ERROR);
  for (auto _ : state) {
    sys.Prove();
  }
}
BENCHMARK(BM_ShakeProver_Fp64);

}  // namespace
}  // namespace proofs
