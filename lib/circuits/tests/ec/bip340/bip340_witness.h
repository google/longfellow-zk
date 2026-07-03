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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_BIP340_BIP340_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_BIP340_BIP340_WITNESS_H_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "arrays/dense.h"
#include "ec/p256k1.h"

// OpenSSL for SHA-256 (already a project dependency).
#include <openssl/sha.h>

namespace proofs {

/// Computes witnesses for the Bip340Verify circuit.
///
/// Holds field elements representing bits of s and e,
/// intermediate points for the double-and-add loops, and py.
class Bip340Witness {
  using Field = Fp256k1Base;
  using Elt = typename Field::Elt;
  using Nat = typename Field::N;
  using EC = P256k1;

 public:
  static constexpr size_t kBits = EC::kBits;  // 256

  const EC& ec_;

  // s-bit decomposition and s·G intermediate points.
  Elt bits_s_[kBits];
  Elt int_sx_[kBits];
  Elt int_sy_[kBits];
  Elt int_sz_[kBits];

  // e-bit decomposition and e·P intermediate points.
  Elt bits_e_[kBits];
  Elt int_ex_[kBits];
  Elt int_ey_[kBits];
  Elt int_ez_[kBits];

  // P.y (the even square root of px³ + b).
  Elt py_;

  // Challenge e as a base-field element (Montgomery form).
  Elt e_;
  // Challenge e as a Nat (for native verification).
  Nat e_nat_;

  explicit Bip340Witness(const EC& ec) : ec_(ec) {}

  /// Compute witness directly from known scalars (s, e) and key material.
  /// This avoids BIP-340 signature parsing; useful for circuit testing.
  bool compute_from_scalars(const Nat& s_nat, const Nat& e_nat,
                            const Elt& px, const Elt& py) {
    const Field& F = ec_.f_;
    e_ = F.to_montgomery(e_nat);
    e_nat_ = e_nat;
    py_ = py;

    auto G = ec_.generator();
    compute_scalar_mult_witness(bits_s_, int_sx_, int_sy_, int_sz_, G,
                                s_nat);

    typename EC::ECPoint P = {px, py, F.one()};
    compute_scalar_mult_witness(bits_e_, int_ex_, int_ey_, int_ez_, P,
                                e_nat);
    return true;
  }

  /// Compute the full witness from signature and key bytes.
  ///
  /// sig_bytes: 64-byte BIP-340 signature (r[0:32] || s[32:64])
  /// pk_bytes:  32-byte x-only public key
  /// msg:        message bytes
  /// msg_len:    length of message in bytes
  ///
  /// Returns true on success.
  bool compute(const uint8_t sig_bytes[64], const uint8_t pk_bytes[32],
               const uint8_t* msg, size_t msg_len) {
    const Field& F = ec_.f_;
    const Elt one = F.one();
    const Elt zero = F.zero();

    // -- Parse r, s, P.x (BIP-340 uses big-endian) ----------------------
    Nat rx_nat = nat_from_be_bytes(sig_bytes);
    Nat s_nat  = nat_from_be_bytes(sig_bytes + 32);
    Nat px_nat = nat_from_be_bytes(pk_bytes);

    // Convert to Montgomery form.
    Elt px = F.to_montgomery(px_nat);

    // -- Lift P.x: compute py = sqrt(px³ + 7), choosing the even root ----
    Elt x2 = F.mulf(px, px);
    Elt x3 = F.mulf(x2, px);
    Elt y2 = F.addf(x3, ec_.b_);  // b = 7
    py_ = sqrt_even(y2, F);

    // -- Compute challenge e = tagged_hash("BIP0340/challenge",
    //    R.x || P.x || msg) mod n ---------------------------------------
    uint8_t hash[32];
    compute_tagged_hash(hash, sig_bytes, pk_bytes, msg, msg_len);
    Nat e_nat = nat_from_be_bytes(hash);

    // Reduce mod n if needed.
    Nat n_order = scalar_order_nat();
    if (!(e_nat < n_order)) {
      e_nat.sub(n_order);
    }

    // Store challenge as field element and Nat.
    e_ = F.to_montgomery(e_nat);
    e_nat_ = e_nat;

    // -- Compute s·G witness ---------------------------------------------
    auto G = ec_.generator();
    compute_scalar_mult_witness(bits_s_, int_sx_, int_sy_, int_sz_, G,
                                s_nat);

    // -- Compute e·P witness ---------------------------------------------
    typename EC::ECPoint P = {px, py_, one};
    compute_scalar_mult_witness(bits_e_, int_ex_, int_ey_, int_ez_, P,
                                e_nat);

    return true;
  }

  /// Convert 32 big-endian bytes to a Nat (BIP-340 uses big-endian).
  static Nat nat_from_be_bytes(const uint8_t bytes[32]) {
    uint8_t le[32];
    for (int i = 0; i < 32; ++i) {
      le[i] = bytes[31 - i];
    }
    return Nat::of_bytes(le, 256);
  }

  /// Fill a Dense array from this witness (for the prover).
  void fill_witness(DenseFiller<Field>& filler) const {
    // s·G: bits + intermediates (all but last for intermediates)
    for (size_t i = 0; i < kBits; ++i) {
      filler.push_back(bits_s_[i]);
      if (i < kBits - 1) {
        filler.push_back(int_sx_[i]);
        filler.push_back(int_sy_[i]);
        filler.push_back(int_sz_[i]);
      }
    }
    // e·P: bits + intermediates (all but last for intermediates)
    for (size_t i = 0; i < kBits; ++i) {
      filler.push_back(bits_e_[i]);
      if (i < kBits - 1) {
        filler.push_back(int_ex_[i]);
        filler.push_back(int_ey_[i]);
        filler.push_back(int_ez_[i]);
      }
    }
    // P.y
    filler.push_back(py_);
  }

 private:
  /// BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || R.x || P.x || msg).
  static void compute_tagged_hash(uint8_t hash[32],
                                  const uint8_t r_bytes[32],
                                  const uint8_t pk_bytes[32],
                                  const uint8_t* msg, size_t msg_len) {
    const char tag[] = "BIP0340/challenge";
    size_t tag_len = std::strlen(tag);

    // Pre-hash the tag (BIP-340 tagged hash convention).
    uint8_t tag_hash[32];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, tag, tag_len);
    SHA256_Final(tag_hash, &ctx);

    // SHA256(tag_hash || tag_hash || R.x || P.x || msg)
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, tag_hash, 32);
    SHA256_Update(&ctx, tag_hash, 32);
    SHA256_Update(&ctx, r_bytes, 32);
    SHA256_Update(&ctx, pk_bytes, 32);
    SHA256_Update(&ctx, msg, msg_len);
    SHA256_Final(hash, &ctx);
  }

  /// Compute sqrt(y2) mod p, choosing the even root.
  /// For secp256k1, p ≡ 3 mod 4, so sqrt = y2^((p+1)/4).
  Elt sqrt_even(const Elt& y2, const Field& F) const {
    // (p+1)/4 for p = 2^256 - 2^32 - 977.
    Nat exp(
        "0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c");
    Elt root = F.one();
    Elt base = y2;
    for (int i = 255; i >= 0; --i) {
      root = F.mulf(root, root);
      if (exp.bit(i)) {
        root = F.mulf(root, base);
      }
    }
    // Pick the even root: convert both candidates to normal form, check LSB.
    Nat r0 = F.from_montgomery(root);
    if ((r0.bit(0)) == 0) {
      return root;
    } else {
      return F.negf(root);
    }
  }

  /// Compute intermediate points for scalar multiplication Q = k * P.
  void compute_scalar_mult_witness(
      Elt bits[kBits], Elt int_x[kBits], Elt int_y[kBits], Elt int_z[kBits],
      const typename EC::ECPoint& P, const Nat& k) const {
    const Field& F = ec_.f_;
    const Elt one = F.one();
    const Elt zero = F.zero();

    Elt aX = zero, aY = one, aZ = zero;

    for (size_t i = 0; i < kBits; ++i) {
      // MSB to LSB (same convention as pk_circuit.h).
      size_t bit_idx = kBits - 1 - i;
      int bit = k.bit(bit_idx);
      bits[i] = F.of_scalar(bit);

      ec_.doubleE(aX, aY, aZ, aX, aY, aZ);

      if (bit == 1) {
        ec_.addE(aX, aY, aZ, aX, aY, aZ, P.x, P.y, P.z);
      } else {
        ec_.addE(aX, aY, aZ, aX, aY, aZ, zero, one, zero);
      }

      int_x[i] = aX;
      int_y[i] = aY;
      int_z[i] = aZ;
    }
  }

  /// Return the secp256k1 curve order as a Nat.
  static Nat scalar_order_nat() {
    return Nat(
        "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
  }

};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_BIP340_BIP340_WITNESS_H_
