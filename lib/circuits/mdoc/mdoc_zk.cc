// Copyright 2025 Google LLC.
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

#include <stdint.h>
#include <sys/types.h>

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/circuit_id.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/mac/mac_circuit.h"
#include "circuits/mac/mac_reference.h"
#include "circuits/mac/mac_witness.h"
#include "circuits/mdoc/mdoc_hash.h"
#include "circuits/mdoc/mdoc_signature.h"
#include "circuits/mdoc/mdoc_witness.h"
#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
#include "proto/circuit.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/crypto.h"
#include "util/log.h"
#include "util/panic.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"
#include "zstd.h"

// The result of getHashMacIndex is derived from the circuit layout.
// It represents the location of the hash MAC wire in the hash verification
// circuit and must be updated if the public interface of the hash circuit is
// changed.
// This index is part of the public input, but it is needed so that the prover
// can commit the rest of the witness (including its portion of the MAC key),
// the verifier can then select its a_v half of the mac key, the prover can
// then compute the MAC and finally place it into the correct part of the
// dense witness array.
// ex: numAttrs = 1, this function returns (1*768) + 161
// ex: numAttrs = 2, this function returns (2*929) + 161
size_t getHashMacIndex(size_t numAttrs) { return numAttrs * 8 * 96 + 160 + 1; }

namespace proofs {

// ======= Global typedefs for convenience ==========
// P256-related types
using N = Fp256Base::N;
using Scalar = Fp256Base::Elt;
using Elt = Fp256Base::Elt;
using f2_p256 = Fp2<Fp256Base>;
using Elt2 = f2_p256::Elt;
using FftExtConvolutionFactory = FFTExtConvolutionFactory<Fp256Base, f2_p256>;
using RSFactory_b = ReedSolomonFactory<Fp256Base, FftExtConvolutionFactory>;
using f_128 = GF2_128<>;
using gf2k = f_128::Elt;

using RSFactory = LCH14ReedSolomonFactory<f_128>;

constexpr size_t kLigeroRate = 4;
constexpr size_t kLigeroNreq = 128;  // 86+ bits statistical security

// Root of unity for the f_p256^2 extension field.
static constexpr char kRootX[] =
    "112649224146410281873500457609690258373018840430489408729223714171582664"
    "680802";
static constexpr char kRootY[] =
    "317040948518153410669569855215889129699039744181079354462206130544166376"
    "41043";

// An upper-bound on the decompressed circuit size. It is better to make this
// bound tight to avoid memory failure in the resource restricted Android
// gmscore environment.
static constexpr size_t kCircuitSizeMax = 150000000;

// Magic constant 4 is derived from the circuit layout.
// It represents the location of the signature MAC wire in the signature
// verification circuit and must be updated if the public interface of the sig
// circuit is changed. This index is part of the public input, but it is needed
// so that the prover can commit the rest of the witness (including its portion
// of the MAC key), the verifier can then select its a_v half of the mac key,
// the prover can then compute the MAC and finally place it into the correct
// part of the dense witness array.
static constexpr size_t kSigMacIndex = 4;

// =========== Helper methods for the main exported C functions.

// Specialization for filling the mac when using f_128.
template <>
void fill_gf2k<f_128, f_128>(const typename f_128::Elt &m,
                             DenseFiller<f_128> &df, const f_128 &f) {
  df.push_back(m);
}

void compute_macs(size_t len, const Elt x[], gf2k gmacs[/* 6 */],
                  uint8_t macs[/* 2.len.gf2k_size */],
                  const gf2k ap[/* 2.len */], gf2k av) {
  // This code relies on the assumption that an Elt can be mac'ed in 2
  // gf2k elements.
  check(f_128::kBits * 2 >= Fp256Base::kBits, "Mac is not large enough");
  f_128 gf;
  MACReference<f_128> mac_ref;
  uint8_t buf[Fp256Base::kBytes];

  for (size_t i = 0; i < len; ++i) {
    p256_base.to_bytes_field(buf, x[i]);
    mac_ref.compute(&gmacs[2 * i], av, &ap[i * 2], buf);
    gf.to_bytes_field(&macs[2 * i * f_128::kBytes], gmacs[2 * i]);
    gf.to_bytes_field(&macs[(2 * i + 1) * f_128::kBytes], gmacs[2 * i + 1]);
  }
}

struct ProverState {
  Elt common[3];  //  e2, dpkx, dpky
  gf2k ap[6];     //  mac keys for the above
  using mac_witness = MacGF2Witness;
  mac_witness macs[3];
};

// Fills the hash witness with the attributes and the time input.
void fill_attributes(DenseFiller<f_128> &hash_filler,
                     const RequestedAttribute *attrs, size_t attrs_len,
                     const uint8_t *now, const f_128 &Fs, size_t version = 4) {
  hash_filler.push_back(Fs.one());
  for (size_t ai = 0; ai < attrs_len; ++ai) {
    fill_attribute(hash_filler, attrs[ai], Fs, version);
  }
  fill_bit_string(hash_filler, now, 20, 20, Fs);
}

// Fills the signature witness with the public inputs pkX, pkY, and e.
void fill_signature_inputs(DenseFiller<Fp256Base> &sig_filler, const Elt &pkX,
                           const Elt &pkY, const Elt &e) {
  sig_filler.push_back(p256_base.one());
  sig_filler.push_back(pkX);
  sig_filler.push_back(pkY);
  sig_filler.push_back(e);
}

// Fills the public inputs for the hash and signature circuits.
// Empty values for the MAC inputs and AV are used.
void fill_public_inputs(DenseFiller<Fp256Base> &sig_filler,
                        DenseFiller<f_128> &hash_filler, const Elt &pkX,
                        const Elt &pkY, const uint8_t *tr, size_t tr_len,
                        const RequestedAttribute *attrs, size_t attrs_len,
                        const uint8_t *now, const uint8_t *docType,
                        size_t dt_len, const gf2k macs[], gf2k av,
                        const f_128 &Fs, size_t version = 4) {
  fill_attributes(hash_filler, attrs, attrs_len, now, Fs, version);

  for (size_t i = 0; i < 6; ++i) { /* 6 mac + 1 av */
    fill_gf2k<f_128, f_128>(macs[i], hash_filler, Fs);
  }
  fill_gf2k<f_128, f_128>(av, hash_filler, Fs);

  std::vector<uint8_t> docTypeBytes(docType, docType + dt_len);
  Elt e2 = p256_base.to_montgomery(
      compute_transcript_hash<N>(tr, tr_len, &docTypeBytes));
  fill_signature_inputs(sig_filler, pkX, pkY, e2);

  for (size_t i = 0; i < 6; ++i) {
    fill_gf2k<f_128, Fp256Base>(macs[i], sig_filler, p256_base);
  }
  fill_gf2k<f_128, Fp256Base>(av, sig_filler, p256_base);
}


// Fills the hash and signature public inputs and private witnesses.
bool fill_witness(DenseFiller<Fp256Base> &fill_b, DenseFiller<f_128> &fill_s,
                  const uint8_t *mdoc, size_t mdoc_len, const Elt &pkX,
                  const Elt &pkY, const uint8_t *tr, size_t tr_len,
                  const RequestedAttribute *attrs, size_t attrs_len,
                  const uint8_t *now, ProverState &state,
                  SecureRandomEngine &rng, const f_128 &Fs,
                  size_t version = 4) {
  using MdocHW = MdocHashWitness<P256, f_128>;
  using MdocSW = MdocSignatureWitness<P256, Fp256Scalar>;

  // Allocate these objects on the heap because Android has a small stack.
  auto hw = std::make_unique<MdocHW>(attrs_len, p256, Fs);
  auto sw = std::make_unique<MdocSW>(p256, p256_scalar, Fs);

  // hash public inputs
  fill_attributes(fill_s, attrs, attrs_len, now, Fs, version);

  // init mac+av to 0
  for (size_t i = 0; i < 6 + 1; ++i) { /* 6 mac + 1 av */
    fill_gf2k<f_128, f_128>(Fs.zero(), fill_s, Fs);
  }

  bool ok_h = hw->compute_witness(mdoc, mdoc_len, tr, tr_len, attrs,
                                  attrs_len, now, version);
  bool ok_s = sw->compute_witness(pkX, pkY, mdoc, mdoc_len, tr, tr_len);
  if (!ok_h || !ok_s) return false;

  // signature public inputs
  fill_signature_inputs(fill_b, pkX, pkY, sw->e2_);
  for (size_t i = 0; i < 7; ++i) {
    fill_gf2k<f_128, Fp256Base>(Fs.zero(), fill_b, p256_base);
  }

  // compute macs
  state = {.common = {hw->e_, hw->dpkx_, hw->dpky_}};
  MACReference<f_128> mac_ref;
  mac_ref.sample(state.ap, 6, &rng);

  uint8_t buf[Fp256Base::kBytes];

  Fp256Base::Elt tt[3] = {hw->e_, hw->dpkx_, hw->dpky_};
  for (size_t i = 0; i < 3; ++i) {
    p256_base.to_bytes_field(buf, tt[i]);
    sw->macs_[i].compute_witness(&state.ap[2 * i], buf);
    state.macs[i].compute_witness(&state.ap[2 * i]);
    fill_bit_string(fill_s, buf, 32, 32, Fs);
  }

  // private witnesses
  hw->fill_witness(fill_s);
  for (auto &mac : state.macs) {
    mac.fill_witness(fill_s);
  }

  sw->fill_witness(fill_b);

  return true;
}

gf2k generate_mac_key(Transcript &t) {
  f_128 gf;
  uint8_t buf[f_128::kBytes];
  t.bytes(buf, f_128::kBytes);
  return gf.of_bytes_field(buf).value();
}

// Updates the dense input array with a mac.The location
// of the start of the macs+av inputs must be passed in as (si, hi).
void update_mac_in_dense(Dense<Fp256Base> &W_sig, Dense<f_128> &W_hash,
                         size_t &si, size_t &hi, const gf2k mac,
                         const f_128 &Fs) {
  for (size_t j = 0; j < f_128::kBits; ++j) {
    W_sig.v_[si++] = mac[j] ? p256_base.one() : p256_base.zero();
  }
  W_hash.v_[hi++] = mac;
}

// Updates all macs in both dense arrays. The (si,hi) should be the index
// of the first mac in the respective dense arrays.
void update_macs(Dense<Fp256Base> &W_sig, Dense<f_128> &W_hash, size_t si,
                 size_t hi, const gf2k macs[], gf2k av, const f_128 &Fs) {
  for (size_t mi = 0; mi < 6; ++mi) {
    update_mac_in_dense(W_sig, W_hash, si, hi, macs[mi], Fs);
  }
  update_mac_in_dense(W_sig, W_hash, si, hi, av, Fs);
}

// Decompress a circuit representation into a vector that has been reserved
// with size len.  The value len needs to be a good upper-bound estimate on
// the size of the uncompressed string.
size_t decompress(std::vector<uint8_t> &bytes, size_t len,
                  const uint8_t *compressed, size_t compressed_len) {
  size_t res =
      ZSTD_decompress(bytes.data(), bytes.size(), compressed, compressed_len);

  if (ZSTD_isError(res)) {
    log(ERROR, "zlib.UncompressAtMost failed: %s", ZSTD_getErrorName(res));
    return 0;
  }
  return res;
}

bool parsePk(const char *pkx, const char *pky, Elt &pkX, Elt &pkY) {
  auto maybe_x = p256_base.of_untrusted_string(pkx);
  auto maybe_y = p256_base.of_untrusted_string(pky);
  if (!maybe_x.has_value() || !maybe_y.has_value()) {
    return false;
  }
  pkX = maybe_x.value();
  pkY = maybe_y.value();
  return true;
}

// =========== End of helper functions =====================
extern "C" {
/*
API version that uses 2 circuits over different fields.
*/
using MdocSWw = MdocSignatureWitness<P256, Fp256Scalar>;

CircuitGenerationErrorCode generate_circuit(const ZkSpecStruct *zk_spec,
                                            uint8_t **cb, size_t *clen) {
  if (zk_spec == nullptr) {
    return CIRCUIT_GENERATION_NULL_INPUT;
  }

  if (cb == nullptr || clen == nullptr) {
    log(INFO, "cb or clen is null");
    return CIRCUIT_GENERATION_NULL_INPUT;
  }

  size_t number_of_attributes = zk_spec->num_attributes;

  std::vector<uint8_t> bytes;

  // ======== serialize signature circuit =========================
  {
    using CompilerBackend = CompilerBackend<Fp256Base>;
    using LogicCircuit = Logic<Fp256Base, CompilerBackend>;
    using EltW = LogicCircuit::EltW;
    using MACTag = LogicCircuit::v128;
    using MdocSignature = MdocSignature<LogicCircuit, Fp256Base, P256>;
    QuadCircuit<Fp256Base> Q(p256_base);
    const CompilerBackend cbk(&Q);
    const LogicCircuit lc(&cbk, p256_base);
    MdocSignature mdoc_s(lc, p256, n256_order);

    EltW pkX = Q.input(), pkY = Q.input(), htr = Q.input();
    MACTag mac[7]; /* 3 macs + av */
    for (size_t i = 0; i < 7; ++i) {
      mac[i] = lc.vinput<128>();
    }
    Q.private_input();

    // Allocate this large object on heap.
    auto w = std::make_unique<MdocSignature::Witness>();
    w->input(Q, lc);
    mdoc_s.assert_signatures(pkX, pkY, htr, &mac[0], &mac[2], &mac[4], mac[6],
                             *w);

    auto circ = Q.mkcircuit(/*nc=*/1);
    dump_info("sig", Q);
    CircuitRep<Fp256Base> cr(p256_base, P256_ID);
    cr.to_bytes(*circ, bytes);
    uint8_t id[kSHA256DigestSize];
    char buf[100];
    circuit_id<Fp256Base>(id, *circ, p256_base);
    hex_to_str(buf, id, kSHA256DigestSize);
    log(INFO, "sig bytes: %zu id:%s", bytes.size(), buf);
  }
  {
    const f_128 Fs;

    using CompilerBackend = CompilerBackend<f_128>;
    using LogicCircuit = Logic<f_128, CompilerBackend>;
    using v8 = LogicCircuit::v8;
    using v256 = LogicCircuit::v256;
    using MdocHash = MdocHash<LogicCircuit, f_128>;
    using MacBitPlucker = BitPlucker<LogicCircuit, kMACPluckerBits>;
    using MAC = MACGF2<CompilerBackend, MacBitPlucker>;
    using MACWitness = typename MAC::Witness;
    using MACTag = MAC::v128;

    QuadCircuit<f_128> Q(Fs);
    const CompilerBackend cbk(&Q);
    const LogicCircuit lc(&cbk, Fs);
    MAC mac_check(lc);

    std::vector<MdocHash::OpenedAttribute> oa(number_of_attributes);
    MdocHash mdoc_h(lc);
    for (size_t ai = 0; ai < number_of_attributes; ++ai) {
      for (size_t j = 0; j < 32; ++j) {
        oa[ai].attr[j] = lc.template vinput<8>();
      }
      for (size_t j = 0; j < 64; ++j) {
        oa[ai].v1[j] = lc.template vinput<8>();
      }
    }
    v8 now[20];
    for (size_t i = 0; i < 20; ++i) {
      now[i] = lc.template vinput<8>();
    }

    MACTag mac[7]; /* 3 macs + av */
    for (size_t i = 0; i < 7; ++i) {
      mac[i] = Q.input();
    }

    Q.private_input();
    v256 e = lc.template vinput<256>();
    v256 dpkx = lc.template vinput<256>();
    v256 dpky = lc.template vinput<256>();

    // Allocate this large object on heap.
    auto w = std::make_unique<MdocHash::Witness>(number_of_attributes);
    w->input(Q, lc);

    Q.begin_full_field();
    MACWitness macw[3]; /* MACs for e, dpkx, dpky */
    for (size_t i = 0; i < 3; ++i) {
      macw[i].input(lc, Q);
    }

    mdoc_h.assert_valid_hash_mdoc(oa.data(), now, e, dpkx, dpky, *w);

    MACTag a_v = mac[6];
    mac_check.verify_mac(&mac[0], a_v, e, macw[0]);
    mac_check.verify_mac(&mac[2], a_v, dpkx, macw[1]);
    mac_check.verify_mac(&mac[4], a_v, dpky, macw[2]);

    auto circ = Q.mkcircuit(/*nc=*/1);
    dump_info("hash", Q);
    CircuitRep<f_128> cr(Fs, GF2_128_ID);
    cr.to_bytes(*circ, bytes);
    uint8_t id[kSHA256DigestSize];
    char buf[100];
    circuit_id<f_128>(id, *circ, Fs);
    hex_to_str(buf, id, kSHA256DigestSize);
    log(INFO, "hash bytes:%zu id:%s", bytes.size(), buf);
  }

  size_t sz = bytes.size();
  size_t buf_size = sz / 3 + 1;

  uint8_t *src = bytes.data();
  // Use an aggressive, apriori estimate on the compressed size to avoid
  // wasting memory.
  uint8_t *buf = (uint8_t *)malloc(buf_size);

  size_t zl = ZSTD_compress(buf, buf_size, src, sz, 16);
  log(INFO, "zstd from %zu --> %zu", sz, zl);
  *clen = zl;
  *cb = buf;

  return CIRCUIT_GENERATION_SUCCESS;
}

// Main endpoint for producing a ZK proof for mdoc properties.
// This implementation uses 2 separate circuits over 2 fields to verify
// the signature and the hash components of the mdoc.
// It is the caller's job to free the memory pointed to by prf.
MdocProverErrorCode run_mdoc_prover(
    const uint8_t *bcp, size_t bcsz, /* circuit data */
    const uint8_t *mdoc, size_t mdoc_len, const char *pkx,
    const char *pky,                          /* string rep of public key */
    const uint8_t *transcript, size_t tr_len, /* session transcript */
    const RequestedAttribute *attrs, size_t attrs_len,
    const char *now, /* time formatted as "2023-11-02T09:00:00Z" */
    uint8_t **prf, size_t *proof_len, const ZkSpecStruct *zk_spec) {
  if (bcp == nullptr || mdoc == nullptr || pkx == nullptr || pky == nullptr ||
      transcript == nullptr || attrs == nullptr || now == nullptr ||
      prf == nullptr || proof_len == nullptr || zk_spec == nullptr) {
    return MDOC_PROVER_NULL_INPUT;
  }

  Elt pkX, pkY;
  if (!parsePk(pkx, pky, pkX, pkY)) {
    log(ERROR, "invalid pkx, pky");
    return MDOC_PROVER_INVALID_INPUT;
  }

  // Parse circuits from cached byte representation.
  const f2_p256 p256_2(p256_base);
  const f_128 Fs;

  size_t len = kCircuitSizeMax;
  std::vector<uint8_t> bytes(len);
  size_t full_size = decompress(bytes, len, bcp, bcsz);

  if (full_size == 0) {
    return MDOC_PROVER_CIRCUIT_PARSING_FAILURE;
  }

  log(INFO, "bytes len: %zu", full_size);
  ReadBuffer rb_circuit(bytes.data(), full_size);

  CircuitRep<Fp256Base> cr_s(p256_base, P256_ID);
  auto c_sig = cr_s.from_bytes(rb_circuit);
  if (c_sig == nullptr) {
    log(ERROR, "signature circuit could not be parsed");
    return MDOC_PROVER_CIRCUIT_PARSING_FAILURE;
  }
  CircuitRep<f_128> cr_h(Fs, GF2_128_ID);
  auto c_hash = cr_h.from_bytes(rb_circuit);

  if (c_hash == nullptr) {
    log(ERROR, "hash circuit could not be parsed");
    return MDOC_PROVER_HASH_PARSING_FAILURE;
  }
  log(INFO, "circuit created");

  //  ============ Produce zk witness ==============
  auto W_sig = Dense<Fp256Base>(1, c_sig->ninputs);
  auto W_hash = Dense<f_128>(1, c_hash->ninputs);
  DenseFiller<Fp256Base> sig_filler(W_sig);
  DenseFiller<f_128> hash_filler(W_hash);

  SecureRandomEngine rng;
  ProverState state;
  bool ok = fill_witness(
      sig_filler, hash_filler, mdoc, mdoc_len, pkX, pkY, transcript, tr_len,
      attrs, attrs_len, (const uint8_t *)now, state, rng, Fs, zk_spec->version);
  if (!ok) {
    log(ERROR, "fill_witness failed");
    return MDOC_PROVER_WITNESS_CREATION_FAILURE;
  }

  // ========= Run prover ==============
  // Use the transcript from the session to select the random oracle.
  Transcript tp(transcript, tr_len);

  const Elt2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory fft_b(p256_base, p256_2, omega, 1ull << 31);
  const RSFactory_b rsf_b(fft_b, p256_base);
  const RSFactory the_reed_solomon_factory(Fs);

  ZkProof<f_128> h_zk(*c_hash, kLigeroRate, kLigeroNreq);
  ZkProof<Fp256Base> sig_zk(*c_sig, kLigeroRate, kLigeroNreq);

  ZkProver<f_128, RSFactory> hash_p(*c_hash, Fs, the_reed_solomon_factory);
  ZkProver<Fp256Base, RSFactory_b> sig_p(*c_sig, p256_base, rsf_b);

  hash_p.commit(h_zk, W_hash, tp, rng);
  sig_p.commit(sig_zk, W_sig, tp, rng);

  log(INFO,
      "commit created. h[nl:%zu], s[nl:%zu] hc[b:%zu r:%zu] "
      "sc[b:%zu r:%zu]",
      c_hash->nl, c_sig->nl, h_zk.param.block, h_zk.param.nrow,
      sig_zk.param.block, sig_zk.param.nrow);

  // After prover has committed to the public inputs, compute
  // verifier challenge av, and then compute MACs of the common public
  // inputs.

  gf2k av = generate_mac_key(tp), macs[6];
  uint8_t macs_b[6 * f_128::kBytes];
  compute_macs(3, state.common, macs, macs_b, state.ap, av);
  update_macs(W_sig, W_hash, kSigMacIndex, getHashMacIndex(attrs_len), macs, av,
              Fs);

  if (!hash_p.prove(h_zk, W_hash, tp)) {
    return MDOC_PROVER_GENERAL_FAILURE;
  };
  log(INFO, "ZK hash proof done");

  if (!sig_p.prove(sig_zk, W_sig, tp)) {
    return MDOC_PROVER_GENERAL_FAILURE;
  };
  log(INFO, "ZK signature proof done");

  // Serialize proof to bytes.
  // [6 mac values] [docType] [hash proof] [sig proof]
  std::vector<uint8_t> buf;
  // This sum will not overflow based on constraints of circuit & proof size.
  size_t tt = 6 * f_128::kBytes + h_zk.size() + sig_zk.size();
  buf.reserve(tt);
  buf.insert(buf.begin(), macs_b, macs_b + 6 * f_128::kBytes);
  h_zk.write(buf, Fs);
  sig_zk.write(buf, p256_base);
  *proof_len = buf.size();
  log(INFO, "proof_len: %zu ", *proof_len);

  // Allocate memory and copy proof bytes.
  *prf = (uint8_t *)malloc(*proof_len);
  if (!prf) {
    log(ERROR, "malloc failed");
    return MDOC_PROVER_MEMORY_ALLOCATION_FAILURE;
  }
  memcpy(*prf, buf.data(), buf.size());
  return MDOC_PROVER_SUCCESS;
}

MdocVerifierErrorCode run_mdoc_verifier(
    const uint8_t *bcp, size_t bcsz,          /* circuit data */
    const char *pkx, const char *pky,         /* string rep of public key */
    const uint8_t *transcript, size_t tr_len, /* session Transcript */
    const RequestedAttribute *attrs, size_t attrs_len,
    const char *now, /* time formatted as "2023-11-02T09:00:00Z" */
    const uint8_t *zkproof, size_t proof_len, const char *docType,
    const ZkSpecStruct *zk_spec) {
  if (bcp == nullptr || pkx == nullptr || pky == nullptr ||
      transcript == nullptr || now == nullptr || attrs == nullptr ||
      zkproof == nullptr || docType == nullptr || zk_spec == nullptr) {
    return MDOC_VERIFIER_NULL_INPUT;
  }

  Elt pkX, pkY;
  if (!parsePk(pkx, pky, pkX, pkY)) {
    log(ERROR, "invalid pkx, pky");
    return MDOC_VERIFIER_INVALID_INPUT;
  }

  const f_128 Fs;

  // Sanity check input sizes.
  if (bcsz < 50000 || tr_len < 1 || attrs_len < 1 || proof_len < 20000) {
    return MDOC_VERIFIER_ARGUMENTS_TOO_SMALL;
  }

  const f2_p256 p256_2(p256_base);

  // Parse circuits from cached byte representation.
  size_t len = kCircuitSizeMax;
  std::vector<uint8_t> bytes(len);
  size_t full_size = decompress(bytes, len, bcp, bcsz);

  // For now, we are not using the ZKSpec version anywhere and assuming no
  // backwards compatibility. As soon as we have a use case for it, we have to
  // pass the ZkSpecStruct to all required downstream functions.
  log(INFO, "bytes len: %zu", full_size);

  ReadBuffer rb_circuit(bytes.data(), full_size);
  CircuitRep<Fp256Base> cr_s(p256_base, P256_ID);
  auto c_sig = cr_s.from_bytes(rb_circuit);
  if (c_sig == nullptr) {
    log(ERROR, "signature circuit could not be parsed");
    return MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE;
  }

  CircuitRep<f_128> cr_h(Fs, GF2_128_ID);
  auto c_hash = cr_h.from_bytes(rb_circuit);

  if (c_hash == nullptr) {
    log(ERROR, "circuit could not be parsed");
    return MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE;
  }
  log(INFO, "circuit created. h[in:%zu], s[in:%zu]", c_hash->ninputs,
      c_sig->ninputs);

  // Parse proofs
  ZkProof<f_128> pr_hash(*c_hash, kLigeroRate, kLigeroNreq);
  ZkProof<Fp256Base> pr_sig(*c_sig, kLigeroRate, kLigeroNreq);

  const std::vector<uint8_t> zbuf(zkproof, zkproof + proof_len);
  ReadBuffer rb(zbuf);

  // Read macs from proof string.
  // The sanity check above ensures that the proof is big enough for the MACs.
  gf2k macs[6];

  for (size_t i = 0; i < 6; ++i) {
    macs[i] = Fs.of_bytes_field(rb.next(f_128::kBytes)).value();
  }

  // The proof read methods check proof length internally.
  if (!pr_hash.read(rb, Fs)) {
    log(ERROR, "hash proof could not be parsed");
    return MDOC_VERIFIER_HASH_PARSING_FAILURE;
  };
  if (!pr_sig.read(rb, p256_base)) {
    log(ERROR, "sig proof could not be parsed");
    return MDOC_VERIFIER_SIGNATURE_PARSING_FAILURE;
  }

  log(INFO, "proofs read");

  // =============== Verify

  const Elt2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory fft_b(p256_base, p256_2, omega, 1ull << 31);
  const RSFactory_b rsf_b(fft_b, p256_base);
  const RSFactory the_reed_solomon_factory(Fs);

  ZkVerifier<f_128, RSFactory> hash_v(*c_hash, the_reed_solomon_factory,
                                      kLigeroRate, kLigeroNreq, Fs);
  ZkVerifier<Fp256Base, RSFactory_b> sig_v(*c_sig, rsf_b, kLigeroRate,
                                           kLigeroNreq, p256_base);

  // Use the transcript from the session to select the random oracle.
  class Transcript tv(transcript, tr_len);

  hash_v.recv_commitment(pr_hash, tv);
  sig_v.recv_commitment(pr_sig, tv);

  gf2k av = generate_mac_key(tv);

  // =============== Create public inputs
  auto pub_hash = Dense<f_128>(1, c_hash->npub_in);
  auto pub_sig = Dense<Fp256Base>(1, c_sig->npub_in);
  DenseFiller<f_128> hash_filler(pub_hash);
  DenseFiller<Fp256Base> sig_filler(pub_sig);

  size_t dlen = strlen(docType);
  fill_public_inputs(sig_filler, hash_filler, pkX, pkY, transcript, tr_len,
                     attrs, attrs_len, (const uint8_t *)now,
                     (const uint8_t *)docType, dlen, macs, av, Fs,
                     zk_spec->version);

  if (hash_filler.size() != c_hash->npub_in ||
      sig_filler.size() != c_sig->npub_in) {
    return MDOC_VERIFIER_ATTRIBUTE_NUMBER_MISMATCH;
  }

  bool ok = hash_v.verify(pr_hash, pub_hash, tv);
  bool ok2 = sig_v.verify(pr_sig, pub_sig, tv);

  return ok && ok2 ? MDOC_VERIFIER_SUCCESS : MDOC_VERIFIER_GENERAL_FAILURE;
}

int circuit_id(uint8_t id[/*kSHA256DigestSize*/], const uint8_t *bcp,
               size_t bcsz, const ZkSpecStruct *zk_spec) {
  if (id == nullptr || bcp == nullptr || zk_spec == nullptr) {
    return 0;
  }
  SHA256 sha;
  uint8_t cid[kSHA256DigestSize];

  size_t len = kCircuitSizeMax;
  std::vector<uint8_t> bytes(len);
  size_t full_size = decompress(bytes, len, bcp, bcsz);

  ReadBuffer rb_circuit(bytes.data(), full_size);
  CircuitRep<Fp256Base> cr_s(p256_base, P256_ID);
  auto c_sig = cr_s.from_bytes(rb_circuit);
  if (c_sig == nullptr) {
    log(ERROR, "signature circuit could not be parsed");
    return 0;
  }
  circuit_id(cid, *c_sig, p256_base);
  sha.Update(cid, kSHA256DigestSize);

  const f_128 Fs;
  CircuitRep<f_128> cr_h(Fs, GF2_128_ID);
  auto c_hash = cr_h.from_bytes(rb_circuit);
  if (c_hash == nullptr) {
    log(ERROR, "circuit could not be parsed");
    return 0;
  }

  size_t remaining = rb_circuit.remaining();
  if (remaining != 0) {
    log(ERROR, "circuit bytes contains extra data: %zu bytes", remaining);
    return 0;
  }

  circuit_id(cid, *c_hash, Fs);
  sha.Update(cid, kSHA256DigestSize);

  sha.DigestData(id);
  return 1;
}

} /* extern "C" */
}  // namespace proofs