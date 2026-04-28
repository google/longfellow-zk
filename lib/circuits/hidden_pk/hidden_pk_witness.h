#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HIDDEN_PK_HIDDEN_PK_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HIDDEN_PK_HIDDEN_PK_WITNESS_H_

// Witness computation for HiddenPKCircuit.
//
// Given (pkx, pky, e, r, s) in the secp256k1 scalar/base fields, this class
// computes all private witness values needed by the circuit and fills a
// DenseFiller for use with ZkProver.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "arrays/dense.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_witness.h"
#include "ec/p256k1.h"

namespace proofs {

class HiddenPKWitness {
 public:
  using Field  = Fp256k1Base;
  using EC     = P256k1;
  using Scalar = Fp256k1Scalar;
  using Elt    = typename Field::Elt;
  using Nat    = typename Field::N;

  static constexpr size_t kBits      = EC::kBits;
  static constexpr size_t kShaBlocks = 2;

  // Field elements (Montgomery-encoded).
  Elt pkx_;
  Elt pky_;

  // SHA-256 block witnesses (2 blocks for 64-byte input).
  FlatSHA256Witness::BlockWitness sha_bw_[kShaBlocks];

  // ECDSA verify witness.
  VerifyWitness3<EC, Scalar> ecdsa_;

  explicit HiddenPKWitness()
      : ecdsa_(p256k1_scalar, p256k1) {}

  // Compute all witness values.
  // Returns false if the ECDSA witness computation fails (bad signature).
  bool compute(const Elt& pkx, const Elt& pky,
               const Nat& e, const Nat& r, const Nat& s) {
    pkx_ = pkx;
    pky_ = pky;

    const Field& F = p256k1_base;

    // 1. Compute ECDSA witnesses.
    if (!ecdsa_.compute_witness(pkx, pky, e, r, s)) {
      return false;
    }

    // 2. Build the 64-byte SHA-256 message: pkx_bytes || pky_bytes.
    //    Both coordinates are encoded big-endian (MSB byte first).
    uint8_t msg[64] = {};
    Nat nx = F.from_montgomery(pkx);
    Nat ny = F.from_montgomery(pky);

    for (size_t i = 0; i < 32; ++i) {
      uint8_t bx = 0, by = 0;
      for (int j = 0; j < 8; ++j) {
        if (nx.bit(255 - (i * 8 + j))) bx |= (1u << (7 - j));
        if (ny.bit(255 - (i * 8 + j))) by |= (1u << (7 - j));
      }
      msg[i]      = bx;
      msg[32 + i] = by;
    }

    // 3. Compute SHA-256 witnesses (with standard padding).
    uint8_t nb = 0;
    std::vector<uint8_t> padded(64 * kShaBlocks, 0);
    FlatSHA256Witness::transform_and_witness_message(
        sizeof(msg), msg, kShaBlocks, nb, padded.data(), sha_bw_);
    // nb must be kShaBlocks; verify for debugging.
    (void)nb;  // nb should equal kShaBlocks

    return true;
  }

  // Return pkHash = SHA256(pkx_bytes || pky_bytes) as a 32-byte array
  // (big-endian, i.e., sha_bw_[1].h1[0] is the most significant word).
  std::vector<uint8_t> pk_hash_bytes() const {
    std::vector<uint8_t> out(32);
    for (int i = 0; i < 8; ++i) {
      uint32_t w = sha_bw_[kShaBlocks - 1].h1[i];
      out[4 * i + 0] = (w >> 24) & 0xFF;
      out[4 * i + 1] = (w >> 16) & 0xFF;
      out[4 * i + 2] = (w >>  8) & 0xFF;
      out[4 * i + 3] = (w      ) & 0xFF;
    }
    return out;
  }

  // Fill a DenseFiller with all private witness values.
  // The public inputs must be filled by the caller before calling this.
  void fill_witness(DenseFiller<Field>& filler) const {
    const Field& F = p256k1_base;

    // pk_x and pk_y as field elements.
    filler.push_back(pkx_);
    filler.push_back(pky_);

    // Bit decompositions: LSB-first (bit 0 = LSB of the integer).
    Nat nx = F.from_montgomery(pkx_);
    Nat ny = F.from_montgomery(pky_);
    for (size_t i = 0; i < kBits; ++i)
      filler.push_back(F.of_scalar(nx.bit(i)));
    for (size_t i = 0; i < kBits; ++i)
      filler.push_back(F.of_scalar(ny.bit(i)));

    // SHA-256 block witnesses (packed format, kShaPluckerSize = 2).
    BitPluckerEncoder<Field, 2> enc(F);
    auto push_packed = [&](uint32_t val) {
      auto packed = enc.mkpacked_v32(val);
      for (const auto& x : packed) filler.push_back(x);
    };

    for (size_t blk = 0; blk < kShaBlocks; ++blk) {
      const auto& bw = sha_bw_[blk];
      for (int k = 0; k < 48; ++k) push_packed(bw.outw[k]);
      for (int k = 0; k < 64; ++k) {
        push_packed(bw.oute[k]);
        push_packed(bw.outa[k]);
      }
      for (int k = 0; k < 8; ++k) push_packed(bw.h1[k]);
    }

    // ECDSA verify witnesses.
    ecdsa_.fill_witness(filler);
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HIDDEN_PK_HIDDEN_PK_WITNESS_H_
