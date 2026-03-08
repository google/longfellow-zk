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

#include <stdint.h>
#include <sys/types.h>

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/mac/mac_circuit.h"
#include "circuits/mdoc/mdoc_hash.h"
#include "circuits/mdoc/mdoc_signature.h"
#include "circuits/mdoc/mdoc_witness.h"
#include "circuits/mdoc/mdoc_zk.h"
#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "proto/circuit.h"
#include "sumcheck/circuit_id.h"
#include "util/crypto.h"
#include "util/log.h"
#include "zstd.h"

namespace proofs {

using f_128 = GF2_128<>;

extern "C" {
/*
API version that uses 2 circuits over different fields.
*/
using MdocSWw = MdocSignatureWitness<P256, Fp256Scalar>;

CircuitGenerationErrorCode generate_circuit(const ZkSpecStruct* zk_spec,
                                            uint8_t** cb, size_t* clen) {
  if (zk_spec == nullptr) {
    return CIRCUIT_GENERATION_NULL_INPUT;
  }

  // Generator only supports the latest version of the ZKSpec for a number of
  // attributes. Return an error if the requested version is not the latest.
  int max_circuit_version = 0;
  for (const ZkSpecStruct& spec : kZkSpecs) {
    if (spec.num_attributes == zk_spec->num_attributes &&
        spec.version > max_circuit_version) {
      max_circuit_version = spec.version;
    }
  }

  if (zk_spec->version != max_circuit_version) {
    return CIRCUIT_GENERATION_INVALID_ZK_SPEC_VERSION;
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

    EltW pkX = lc.eltw_input(), pkY = lc.eltw_input(), htr = lc.eltw_input();
    MACTag mac[7]; /* 3 macs + av */
    for (size_t i = 0; i < 7; ++i) {
      mac[i] = lc.vinput<128>();
    }
    Q.private_input();

    // Allocate this large object on heap.
    auto w = std::make_unique<MdocSignature::Witness>();
    w->input(lc);
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
      oa[ai].input(lc);
    }
    
    v8 now[20];
    for (size_t i = 0; i < 20; ++i) {
      now[i] = lc.template vinput<8>();
    }

    // PPID inputs
    v8 verifier_id[32];
    v8 ppid_context[32];
    if (zk_spec->version >= 8) {
      for (size_t i = 0; i < 32; ++i) verifier_id[i] = lc.template vinput<8>();
      for (size_t i = 0; i < 32; ++i) ppid_context[i] = lc.template vinput<8>();
    }

    MACTag mac[7]; /* 3 macs + av */
    for (size_t i = 0; i < 7; ++i) {
      mac[i] = lc.eltw_input();
    }

    Q.private_input();
    v256 e = lc.template vinput<256>();
    v256 dpkx = lc.template vinput<256>();
    v256 dpky = lc.template vinput<256>();

    // Allocate this large object on heap.
    auto w = std::make_unique<MdocHash::Witness>(number_of_attributes);
    w->input(lc, zk_spec->version);

    Q.begin_full_field();
    MACWitness macw[3]; /* MACs for e, dpkx, dpky */
    for (size_t i = 0; i < 3; ++i) {
      macw[i].input(lc);
    }

    mdoc_h.assert_valid_hash_mdoc(oa.data(), now, e, dpkx, dpky, *w, 
                                  zk_spec->version,
                                  verifier_id, ppid_context);

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

  uint8_t* src = bytes.data();
  // Use an aggressive, apriori estimate on the compressed size to avoid
  // wasting memory.
  uint8_t* buf = (uint8_t*)malloc(buf_size);

  size_t zl = ZSTD_compress(buf, buf_size, src, sz, 16);
  log(INFO, "zstd from %zu --> %zu", sz, zl);
  *clen = zl;
  *cb = buf;

  return CIRCUIT_GENERATION_SUCCESS;
}

} /* extern "C" */
}  // namespace proofs
