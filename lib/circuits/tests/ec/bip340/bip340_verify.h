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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_BIP340_BIP340_VERIFY_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_BIP340_BIP340_VERIFY_H_

#include <stddef.h>

namespace proofs {

/// Verifies the BIP-340 / Schnorr signature relation over secp256k1:
///
///   s·G = R + e·P
///
/// where G is the secp256k1 generator, P = (px, py) with py² = px³ + 7,
/// e is the Fiat-Shamir challenge, and R is a curve point whose
/// x-coordinate equals the public input rx.
///
/// The circuit uses the same double-and-add pattern as Ecpk, with
/// witnessed intermediate points to keep the multiplicative depth low.
///
/// Public inputs:  rx (R.x), px (P.x), e (challenge scalar)
/// Witness inputs: bits_s[256], int_s_{x,y,z}[255] for s·G,
///                 bits_e[256], int_e_{x,y,z}[255] for e·P,
///                 py (P.y, the even square root)
///
/// NOTE: The even-y check on R is not yet enforced in-circuit.
///       The circuit only checks x-coordinate equality. Full BIP-340
///       compliance requires additionally verifying that the normalized
///       y-coordinate of R is even.
template <class LogicCircuit, class Field, class EC>
class Bip340Verify {
  using EltW = typename LogicCircuit::EltW;
  using Elt = typename LogicCircuit::Elt;
  static constexpr size_t kBits = EC::kBits;

 public:
  struct Witness {
    EltW bits_s[kBits];
    EltW int_sx[kBits];
    EltW int_sy[kBits];
    EltW int_sz[kBits];

    EltW bits_e[kBits];
    EltW int_ex[kBits];
    EltW int_ey[kBits];
    EltW int_ez[kBits];

    EltW py;

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < kBits; ++i) {
        bits_s[i] = lc.eltw_input();
        if (i < kBits - 1) {
          int_sx[i] = lc.eltw_input();
          int_sy[i] = lc.eltw_input();
          int_sz[i] = lc.eltw_input();
        }
      }
      for (size_t i = 0; i < kBits; ++i) {
        bits_e[i] = lc.eltw_input();
        if (i < kBits - 1) {
          int_ex[i] = lc.eltw_input();
          int_ey[i] = lc.eltw_input();
          int_ez[i] = lc.eltw_input();
        }
      }
      py = lc.eltw_input();
    }
  };

  Bip340Verify(const LogicCircuit& lc, const EC& ec) : lc_(lc), ec_(ec) {}

  /// Verify the BIP-340 relation: s·G - e·P = R, with R.x == rx.
  ///
  /// rx: x-coordinate of R (public, x-only)
  /// px: x-coordinate of P (public, x-only public key)
  /// e:  Fiat-Shamir challenge (public scalar, field element)
  /// w:  witness containing bits of s and e, intermediate points, and py
  void assert_verify(EltW rx, EltW px, EltW e, const Witness& w) const {
    EltW zero = lc_.konst(lc_.zero());
    EltW one = lc_.konst(lc_.one());

    // -- 0. Verify e matches bits_e decomposition ------------------------
    // e must equal Σ bits_e[i] * 2^(kBits-1-i), i.e., the scalar
    // represented by the bits in MSB-first order.
    {
      EltW check = lc_.konst(lc_.zero());
      EltW pow = lc_.konst(lc_.one());  // 2^0
      for (int i = static_cast<int>(kBits) - 1; i >= 0; --i) {
        check = lc_.add(check, lc_.mul(w.bits_e[i], pow));
        pow = lc_.add(pow, pow);  // pow *= 2
      }
      lc_.assert_eq(check, e);
    }

    // -- 1. Lift P: verify py² = px³ + b (secp256k1: b = 7) --------------
    assert_point_on_curve(px, w.py);

    // -- 2. Compute s·G ---------------------------------------------------
    EltW gx = lc_.konst(ec_.gx_);
    EltW gy = lc_.konst(ec_.gy_);
    EltW sgx = zero, sgy = one, sgz = zero;
    scalar_mult(sgx, sgy, sgz, gx, gy, one, w.bits_s, w.int_sx, w.int_sy,
                w.int_sz);

    // -- 3. Compute e·P  (P = (px, py, 1)) -------------------------------
    EltW epx = zero, epy = one, epz = zero;
    scalar_mult(epx, epy, epz, px, w.py, one, w.bits_e, w.int_ex, w.int_ey,
                w.int_ez);

    // -- 4. Compute R = sG - eP = sG + (-eP) ------------------------------
    EltW neg_epy = lc_.sub(zero, epy);
    EltW rpx, rpy, rpz;
    addE(rpx, rpy, rpz, sgx, sgy, sgz, epx, neg_epy, epz);

    // -- 5. Check R.x == rx (projective equality) -------------------------
    // R.x / R.z == rx / 1  ⟺  R.x * 1 == rx * R.z
    EltW lhs = rpx;                       // rpx * 1
    EltW rhs = lc_.mul(rx, rpz);          // rx * rpz
    lc_.assert_eq(lhs, rhs);
  }

 private:
  /// Verify that (x, y) is on the curve: y² = x³ + a·x + b.
  /// For secp256k1, a = 0, b = 7.
  void assert_point_on_curve(EltW x, EltW y) const {
    auto y2 = lc_.mul(y, y);
    auto x2 = lc_.mul(x, x);
    auto x3 = lc_.mul(x, x2);
    auto ax = lc_.mul(lc_.konst(ec_.a_), x);
    auto b = lc_.konst(ec_.b_);
    auto rhs = lc_.add(lc_.add(x3, ax), b);
    lc_.assert_eq(y2, rhs);
  }

  /// Double-and-add scalar multiplication with witnessed intermediate
  /// points.  Same pattern as Ecpk::assert_public_key.
  void scalar_mult(EltW& rx, EltW& ry, EltW& rz, EltW px, EltW py, EltW pz,
                   const EltW bits[kBits], const EltW int_x[kBits],
                   const EltW int_y[kBits],
                   const EltW int_z[kBits]) const {
    EltW zero = lc_.konst(lc_.zero());
    EltW one = lc_.konst(lc_.one());

    // Accumulator starts at point at infinity (0, 1, 0).
    EltW ax = zero, ay = one, az = zero;

    for (size_t i = 0; i < kBits; ++i) {
      typename LogicCircuit::BitW b_bit(bits[i], lc_.f_);
      lc_.assert_is_bit(b_bit);

      // Select point to add: if bit == 1 → P, else → infinity.
      EltW tx = lc_.mux(b_bit, px, zero);
      EltW ty = lc_.mux(b_bit, py, one);
      EltW tz = lc_.mux(b_bit, pz, zero);

      // Double accumulator.
      doubleE(ax, ay, az, ax, ay, az);

      // Add selected point.
      addE(ax, ay, az, ax, ay, az, tx, ty, tz);

      // Check against intermediate witness (except last iteration).
      if (i < kBits - 1) {
        lc_.assert_eq(ax, int_x[i]);
        lc_.assert_eq(ay, int_y[i]);
        lc_.assert_eq(az, int_z[i]);

        ax = int_x[i];
        ay = int_y[i];
        az = int_z[i];
      }
    }

    rx = ax;
    ry = ay;
    rz = az;
  }

  // -- Elliptic curve group law (projective, complete) --------------------

  void addE(EltW& X3, EltW& Y3, EltW& Z3, EltW X1, EltW Y1, EltW Z1, EltW X2,
            EltW Y2, EltW Z2) const {
    EltW t0 = lc_.mul(X1, X2);
    EltW t1 = lc_.mul(Y1, Y2);
    EltW t2 = lc_.mul(Z1, Z2);
    EltW t3 = lc_.add(X1, Y1);
    EltW t4 = lc_.add(X2, Y2);
    t3 = lc_.mul(t3, t4);
    t4 = lc_.add(t0, t1);
    t3 = lc_.sub(t3, t4);
    t4 = lc_.add(X1, Z1);
    EltW t5 = lc_.add(X2, Z2);
    t4 = lc_.mul(t4, t5);
    t5 = lc_.add(t0, t2);
    t4 = lc_.sub(t4, t5);
    t5 = lc_.add(Y1, Z1);
    EltW X3t = lc_.add(Y2, Z2);
    t5 = lc_.mul(t5, X3t);
    X3t = lc_.add(t1, t2);
    t5 = lc_.sub(t5, X3t);
    auto a = lc_.konst(ec_.a_);
    EltW Z3t = lc_.mul(a, t4);
    auto k3b = lc_.konst(ec_.k3b);
    X3t = lc_.mul(k3b, t2);
    Z3t = lc_.add(X3t, Z3t);
    X3t = lc_.sub(t1, Z3t);
    Z3t = lc_.add(t1, Z3t);
    EltW Y3t = lc_.mul(X3t, Z3t);
    t1 = lc_.add(t0, t0);
    t1 = lc_.add(t1, t0);
    t2 = lc_.mul(a, t2);
    t4 = lc_.mul(k3b, t4);
    t1 = lc_.add(t1, t2);
    t2 = lc_.sub(t0, t2);
    t2 = lc_.mul(a, t2);
    t4 = lc_.add(t4, t2);
    t0 = lc_.mul(t1, t4);
    Y3t = lc_.add(Y3t, t0);
    t0 = lc_.mul(t5, t4);
    X3t = lc_.mul(t3, X3t);
    X3t = lc_.sub(X3t, t0);
    t0 = lc_.mul(t3, t1);
    Z3t = lc_.mul(t5, Z3t);
    Z3t = lc_.add(Z3t, t0);

    X3 = X3t;
    Y3 = Y3t;
    Z3 = Z3t;
  }

  void doubleE(EltW& X3, EltW& Y3, EltW& Z3, EltW X, EltW Y, EltW Z) const {
    EltW t0 = lc_.mul(X, X);
    EltW t1 = lc_.mul(Y, Y);
    EltW t2 = lc_.mul(Z, Z);
    EltW t3 = lc_.mul(X, Y);
    t3 = lc_.add(t3, t3);
    EltW Z3t = lc_.mul(X, Z);
    Z3t = lc_.add(Z3t, Z3t);
    auto a = lc_.konst(ec_.a_);
    auto k3b = lc_.konst(ec_.k3b);
    EltW X3t = lc_.mul(a, Z3t);
    EltW Y3t = lc_.mul(k3b, t2);
    Y3t = lc_.add(X3t, Y3t);
    X3t = lc_.sub(t1, Y3t);
    Y3t = lc_.add(t1, Y3t);
    Y3t = lc_.mul(X3t, Y3t);
    X3t = lc_.mul(t3, X3t);
    Z3t = lc_.mul(k3b, Z3t);
    t2 = lc_.mul(a, t2);
    t3 = lc_.sub(t0, t2);
    t3 = lc_.mul(a, t3);
    t3 = lc_.add(t3, Z3t);
    Z3t = lc_.add(t0, t0);
    t0 = lc_.add(Z3t, t0);
    t0 = lc_.add(t0, t2);
    t0 = lc_.mul(t0, t3);
    Y3t = lc_.add(Y3t, t0);
    t2 = lc_.mul(Y, Z);
    t2 = lc_.add(t2, t2);
    t0 = lc_.mul(t2, t3);
    X3t = lc_.sub(X3t, t0);
    Z3t = lc_.mul(t2, t1);
    Z3t = lc_.add(Z3t, Z3t);
    Z3t = lc_.add(Z3t, Z3t);

    X3 = X3t;
    Y3 = Y3t;
    Z3 = Z3t;
  }

  const LogicCircuit& lc_;
  const EC& ec_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_BIP340_BIP340_VERIFY_H_
