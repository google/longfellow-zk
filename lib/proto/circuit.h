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

#ifndef PRIVACY_PROOFS_ZK_LIB_PROTO_CIRCUIT_H_
#define PRIVACY_PROOFS_ZK_LIB_PROTO_CIRCUIT_H_

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include "algebra/hash.h"
#include "sumcheck/circuit.h"
#include "sumcheck/circuit_id.h"
#include "sumcheck/quad.h"
#include "util/ceildiv.h"
#include "util/panic.h"
#include "util/readbuffer.h"

namespace proofs {

// CircuitRep class handles custom circuit serialization.
//
// We expect circuits to be created and stored locally by the prover and
// verifier respectively. The byte representations are thus assumed to be
// trusted. As a result, the methods below perform only basic sanity checking.
//
// An earlier experiment implemented the IO methods using protobuf parsing.
// Despite applying techniques like arena allocation, those methods required
// several seconds to deserialize the circuit. In contrast, these methods take
// 100s of ms.
//
// This class implements an optimization by which internal indices for
// wire and gate labels and circuit size statistics are stored in a configurable
// number of bytes (kBytesWritten) which we set to 4 instead of 8 to save
// space.  If this value is set to >4, there is a possibility of failure on
// 32b platforms, which currently stops execution.  Thus, all circuits must be
// tested on 32b platforms to ensure they are small enough to work.
enum FieldID {
  NONE = 0,
  P256_ID = 1,
  P384_ID = 2,
  P521_ID = 3,
  GF2_128_ID = 4,
  GF2_16_ID = 5,
  FP128_ID = 6,
  FP64_ID = 7,
  GOLDI_ID = 8,
  FP64_2_ID = 9,
  SECP_ID = 10,
};

template <class Field>
class CircuitRep {
  using Elt = typename Field::Elt;
  using QuadCorner = typename Quad<Field>::quad_corner_t;
  constexpr static size_t kMaxLayers = 10000; /* deep circuits are errors */

 public:
  // Serialize kBytesWritten bytes of a size or index used in the circuit to
  // save space.
  static constexpr size_t kBytesWritten = 3;

  explicit CircuitRep(const Field& f, FieldID field_id)
      : f_(f), field_id_(field_id) {}

  void to_bytes(const Circuit<Field>& sc_c, std::vector<uint8_t>& bytes) {
    EltHash eh(f_);
    bytes.push_back(0x1);  // version
    serialize_field_id(bytes, field_id_);
    serialize_size(bytes, sc_c.nv);
    serialize_size(bytes, sc_c.nc);
    serialize_size(bytes, sc_c.npub_in);
    serialize_size(bytes, sc_c.subfield_boundary);
    serialize_size(bytes, sc_c.ninputs);
    serialize_size(bytes, sc_c.l.size());

    // Scan the circuit to generate the constant table. To keep one
    // scan, write the quad to a separate byte vector and later copy it.
    std::vector<uint8_t> quadb;
    quadb.reserve(1 << 24);
    for (const auto& layer : sc_c.l) {
      serialize_size(quadb, layer.logw);
      serialize_size(quadb, layer.nw);
      serialize_size(quadb, layer.quad->n_);

      QuadCorner prevg(0), prevh0(0), prevh1(0);
      for (size_t i = 0; i < layer.quad->n_; ++i) {
        serialize_index(quadb, layer.quad->c_[i].g, prevg);
        prevg = layer.quad->c_[i].g;
        serialize_index(quadb, layer.quad->c_[i].h[0], prevh0);
        prevh0 = layer.quad->c_[i].h[0];
        serialize_index(quadb, layer.quad->c_[i].h[1], prevh1);
        prevh1 = layer.quad->c_[i].h[1];
        serialize_num(quadb, eh.kstore(layer.quad->c_[i].v));
      }
    }

    serialize_size(bytes, eh.constants_.size());
    for (const auto& v : eh.constants_) {
      uint8_t buf[Field::kBytes];
      f_.to_bytes_field(buf, v);
      bytes.insert(bytes.end(), buf, buf + Field::kBytes);
    }

    bytes.insert(bytes.end(), quadb.begin(), quadb.end());
    bytes.insert(bytes.end(), sc_c.id, sc_c.id + 32);
  }

  // Returns a unique_ptr<Circuit> or nullptr if there is an error in
  // deserializing the circuit.
  //
  // If ENFORCE_CIRCUIT_ID is TRUE, check that the circuit id in
  // the serialization matches the id stored in the circuit.
  std::unique_ptr<Circuit<Field>> from_bytes(ReadBuffer& buf,
                                             bool enforce_circuit_id) {
    if (!buf.have(8 * kBytesWritten + 1)) {
      return nullptr;
    }

    uint8_t version = *buf.next(1);
    if (version != 1) {
      return nullptr;
    }

    size_t fid_as_size_t = read_field_id(buf);
    size_t nv = read_size(buf);
    size_t nc = read_size(buf);
    size_t npub_in = read_size(buf);
    size_t subfield_boundary = read_size(buf);
    size_t ninputs = read_size(buf);
    size_t nl = read_size(buf);
    size_t numconst = read_size(buf);

    // Basic sanity checks.
    if (fid_as_size_t != static_cast<size_t>(field_id_) || npub_in > ninputs ||
        subfield_boundary > ninputs || nl > kMaxLayers) {
      return nullptr;
    }

    // Ensure there are enough input bytes for the quad constants.
    auto need = checked_mul(numconst, Field::kBytes);
    if (!need || !buf.have(need.value())) {
      return nullptr;
    }

    std::vector<Elt> constants(numconst);
    for (size_t i = 0; i < numconst; ++i) {
      // Fail if Elt cannot be parsed.
      auto vv = f_.of_bytes_field(buf.next(Field::kBytes));
      if (!vv.has_value()) {
        return nullptr;
      }
      constants[i] = vv.value();
    }

    auto c = std::make_unique<Circuit<Field>>();
    *c = Circuit<Field>{
        .nv = nv,
        .logv = lg(nv),
        .nc = nc,
        .logc = lg(nc),
        .nl = nl,
        .ninputs = ninputs,
        .npub_in = npub_in,
        .subfield_boundary = subfield_boundary,
    };
    c->l.reserve(nl);

    size_t max_g = nv;  // a starting bound on quad number

    for (size_t ly = 0; ly < nl; ++ly) {
      // Ensure there are enough input bytes for the layer, 3 values.
      if (!buf.have(3 * kBytesWritten)) {
        return nullptr;
      }

      size_t lw = read_size(buf);
      size_t nw = read_size(buf);
      size_t nq = read_size(buf);

      // Each quad takes 4 values, check for overflow.
      need = checked_mul(4 * kBytesWritten, nq);
      if (!need || !buf.have(need.value())) {
        return nullptr;
      }

      auto qq = std::make_unique<Quad<Field>>(nq);
      size_t prevg = 0, prevhl = 0, prevhr = 0;
      for (size_t i = 0; i < nq; ++i) {
        size_t g = read_index(buf, prevg);
        if (g > max_g) {  // index of quad must be < wires in the layer
          return nullptr;
        }
        prevg = g;
        size_t hl = read_index(buf, prevhl);
        size_t hr = read_index(buf, prevhr);
        if (hl > nw || hr > nw) {
          return nullptr;
        }
        prevhl = hl;
        prevhr = hr;
        size_t vi = read_num(buf);
        if (vi >= numconst) {
          return nullptr;
        }

        qq->c_[i] = typename Quad<Field>::corner{
            QuadCorner(g), {QuadCorner(hl), QuadCorner(hr)}, constants[vi]};
      }
      c->l.push_back(Layer<Field>{
          .nw = nw,
          .logw = lw,
          .quad = std::unique_ptr<const Quad<Field>>(std::move(qq))});
      max_g = nw;
    }
    // Read the circuit name from the serialization.
    if (!buf.have(32)) {
      return nullptr;
    }
    buf.next(32, c->id);

    if (enforce_circuit_id) {
      uint8_t idtmp[32];
      circuit_id(idtmp, *c, f_);
      if (memcmp(idtmp, c->id, 32) != 0) {
        return nullptr;
      }
    }
    return c;
  }

 private:
  static constexpr uint64_t kMaxValue = (1ULL << (kBytesWritten * 8)) - 1;

  // Multiplies arguments and checks for overflow.
  template <typename T>
  std::optional<T> checked_mul(T a, T b) {
    T ab = a * b;
    if (a == 0 || ab / a == b) return ab;
    return std::nullopt;
  }

  static void serialize_field_id(std::vector<uint8_t>& bytes, FieldID id) {
    serialize_num(bytes, static_cast<size_t>(id));
  }

  static void serialize_size(std::vector<uint8_t>& bytes, size_t sz) {
    serialize_num(bytes, sz);
  }

  // We write indices as differences from the previous index.  This
  // encoding appears to produce byte streams that compress better
  // under both gzip and xz compression.  For example, xz compresses
  // a 35MB test circuit to 2MB without delta encoding, and to 100KB
  // with delta encoding.  We have no real theory to explain this
  // phenomenon, but at least part of the reason is that the deltas
  // are usually smaller than the indices.
  //
  static void serialize_index(std::vector<uint8_t>& bytes, QuadCorner ind0,
                              QuadCorner prev_ind0) {
    size_t ind = static_cast<size_t>(ind0);
    size_t prev_ind = static_cast<size_t>(prev_ind0);

    // Encode the delta IND - PREV_IND.  Since the delta can be
    // negative, and the rest of the code is unsigned only,
    // use the LSB as sign bit.
    if (ind >= prev_ind) {
      serialize_num(bytes, 2u * (ind - prev_ind));
    } else {
      serialize_num(bytes, 2u * (prev_ind - ind) + 1u);
    }
  }

  static void serialize_num(std::vector<uint8_t>& bytes, size_t g) {
    check(g < kMaxValue, "Violating small wire-label assumption");
    uint8_t tmp[kBytesWritten];
    for (size_t i = 0; i < kBytesWritten; ++i) {
      tmp[i] = static_cast<uint8_t>(g & 0xff);
      g >>= 8;
    }
    bytes.insert(bytes.end(), tmp, tmp + kBytesWritten);
  }

  // These routine reads bytes written by serialize_* methods, and thus
  // only needs to handle values expressed in kBytesWritten.
  // On 32b platforms, some large circuits may fail; this method
  // causes a failure in that case.

  // Do not cast to FieldID, since the input is untrusted and the
  // cast may fail.
  static size_t read_field_id(ReadBuffer& buf) { return read_num(buf); }

  static size_t read_size(ReadBuffer& buf) { return read_num(buf); }

  static size_t read_index(ReadBuffer& buf, size_t prev_ind) {
    size_t delta = read_num(buf);
    if (delta & 1) {
      return prev_ind - (delta >> 1);
    } else {
      return prev_ind + (delta >> 1);
    }
  }

  static size_t read_num(ReadBuffer& buf) {
    uint64_t r = 0;
    const uint8_t* p = buf.next(kBytesWritten);
    for (size_t i = 0; i < kBytesWritten; ++i) {
      r |= (p[i] << (i * 8));
    }

    // SIZE_MAX is system defined as max value for size_t.
    // This check fails if a large circuit is loaded on a 32b machine.
    check(r < SIZE_MAX, "Violating small wire-label assumption");
    return static_cast<size_t>(r);
  }

  // Class that defines the hash function for Elt.
  class EHash {
   public:
    const Field& f_;
    explicit EHash(const Field& f) : f_(f) {}
    size_t operator()(const Elt& k) const { return elt_hash(k, f_); }
  };

  // This structure encapsulates the hash used by the compiler.
  class EltHash {
   public:
    std::vector<Elt> constants_;

    explicit EltHash(const Field& f) : f_(f), table_(1000, EHash(f)) {}

    size_t kstore(const Elt& k) {
      if (auto search = table_.find(k); search != table_.end()) {
        return search->second;
      }

      size_t ki = constants_.size();
      constants_.push_back(k);
      table_[k] = ki;
      return ki;
    }

   private:
    const Field& f_;
    std::unordered_map<Elt, size_t, EHash> table_;
  };

  const Field& f_;
  FieldID field_id_;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_PROTO_CIRCUIT_H_
