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

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

// This test is meant to run once for 10^k repetitions to "fuzz" for any
// possible error in completeness or soundness for our ecdsa verification
// circuit. The test works by generating a random key, message, and signature
// using openssl, and then verifying the signature using our circuit. Next, we
// maul the signature by twiddling a single hex digit in the original 5-tuple,
// and ensure that the resulting signature fails.  Although this only checks
// that single edit distance changes cause failures, it is a basic test.
//
// $ blaze-bin/ecdsa/verify_external_test \
//     --gunit_repeat 10000

#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"
#include "util/log.h"
#include "gtest/gtest.h"

#include "openssl/bn.h"
#include "openssl/ec.h"

#include "openssl/ecdsa.h"


#include "openssl/rand.h"

namespace proofs {
namespace {

// This test is specific to P256 via the external openssl dependencies.
// Therefore the types are globally defined for convenience.
using Field = Fp256Base;
using Nat = Field::N;
using Elt = Field::Elt;
using EvalBackend = EvaluationBackend<Field>;
using Logic = Logic<Field, EvalBackend>;
using Verc = VerifyCircuit<Logic, Field, P256>;
using Verw = VerifyWitness3<P256, Fp256Scalar>;

struct signature_tuple {
  char pkx[67];
  char pky[67];
  char e[67];
  char r[67];
  char s[67];
};

struct circuit_params {
  Elt pkx, pky, e;
  typename Verc::Witness vwc;
};

class ecdsa_params {
 public:
  EC_KEY* eckey_;
  EC_GROUP* group_;

  ecdsa_params() : eckey_(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)),
      group_(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) { }

  ~ecdsa_params() {
    EC_KEY_free(eckey_);
    EC_GROUP_free(group_);
  }
};

// Generates a random key (pkx,pky) and a signature (r,s) on a random message e
// using the openssl ECDSA implementation. These values are written as
// null-terminated strings in hex format to the buffers passed in. The caller
// must ensure that the buffers are at least 67 bytes long.
// The goal is to produce an externally verified testing tuple for our own
// implementation.
bool gensig(signature_tuple& st, const ecdsa_params& params) {
  if (!EC_KEY_generate_key(params.eckey_)) {
    return false;
  }

  // Random message
  unsigned char hash[32];
  RAND_bytes(hash, sizeof(hash));

  ECDSA_SIG* sig = ECDSA_do_sign(hash, sizeof(hash), params.eckey_);
  if (!sig) {
    return false;
  }

  // Get the signature components (r and s)
  const BIGNUM* br = ECDSA_SIG_get0_r(sig);
  const BIGNUM* bs = ECDSA_SIG_get0_s(sig);
  char* r_hex = BN_bn2hex(br);
  char* s_hex = BN_bn2hex(bs);

  // Get the public key
  const EC_POINT* pub_key = EC_KEY_get0_public_key(params.eckey_);
  uint8_t buf[200];
  EC_POINT_point2oct(params.group_, pub_key, POINT_CONVERSION_UNCOMPRESSED, buf,
                     sizeof(buf), nullptr);

  // Easiest interface to our circuit library is via hex-formatted strings.
  // NOLINTBEGIN(runtime/printf)
  snprintf(st.pkx, 3, "0x");
  snprintf(st.pky, 3, "0x");
  snprintf(st.e, 3, "0x");
  for (size_t i = 0; i < 32; ++i) {
    snprintf(&st.pkx[2 + i * 2], 3, "%02x", buf[i + 1]);
    snprintf(&st.pky[2 + i * 2], 3, "%02x", buf[i + 33]);
    snprintf(&st.e[2 + i * 2], 3, "%02x", hash[i]);
  }
  // NOLINTEND(runtime/printf)

  snprintf(st.r, sizeof(st.r), "0x%.64s", r_hex);
  snprintf(st.s, sizeof(st.s), "0x%.64s", s_hex);

  // Clean up
  ECDSA_SIG_free(sig);
  OPENSSL_free(r_hex);
  OPENSSL_free(s_hex);

  return true;
}

char twiddle(char in) {
  char d[] = "0123456789abcdef";
  static size_t cnt = 5;
  while (tolower(in) == d[cnt]) {
    cnt = (cnt + 1) % 16;
  }
  return d[cnt];
}

void maulSignature(const signature_tuple& in, signature_tuple& out) {
  out = in;

  // Pick a (biased) random spot to twiddle.
  uint8_t pos[2];
  RAND_bytes(pos, 2);
  char* fields[] = {out.r, out.s, out.e, out.pkx, out.pky};
  size_t fi = pos[0] % 5;
  size_t ind = (pos[1] % 62) + 2;
  fields[fi][ind] = twiddle(fields[fi][ind]);
}

void prepare_witness(const signature_tuple& st, circuit_params& in,
                     const Logic& l, const Field& F) {
  Verw vw(p256_scalar, p256);

  in.pkx = F.of_string(st.pkx);
  in.pky = F.of_string(st.pky);
  Nat e = Nat(st.e);
  Nat r = Nat(st.r);
  Nat s = Nat(st.s);
  in.e = F.to_montgomery(e);

  vw.compute_witness(in.pkx, in.pky, e, r, s);

  in.vwc.rx = l.konst(vw.rx_);
  in.vwc.ry = l.konst(vw.ry_);
  in.vwc.rx_inv = l.konst(vw.rx_inv_);
  in.vwc.s_inv = l.konst(vw.s_inv_);
  in.vwc.pk_inv = l.konst(vw.pk_inv_);
  for (size_t j = 0; j < 8; ++j) {
    in.vwc.pre[j] = l.konst(vw.pre_[j]);
  }
  for (size_t j = 0; j < p256.kBits; j++) {
    in.vwc.bi[j] = l.konst(vw.bi_[j]);
    if (j < p256.kBits - 1) {
      in.vwc.int_x[j] = l.konst(vw.int_x_[j]);
      in.vwc.int_y[j] = l.konst(vw.int_y_[j]);
      in.vwc.int_z[j] = l.konst(vw.int_z_[j]);
    }
  }
}

// This test verifies our ecdsa signature verification circuit against an
// external implementation over randomly generated keys and messages.
TEST(ECDSA, VerifyExternalP256) {
  const Nat order =
      Nat("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

  const Field& F = p256.f_;
  const EvalBackend ebk(F, false);
  const Logic l(&ebk, F);

  Verc verc(l, p256, order);

  ecdsa_params params;

  for (size_t i = 0; i < 100; ++i) {
    if (i % 10 == 0) {
      log(INFO, "Iteration %zu", i);
    }
    signature_tuple st;
    circuit_params in;
    bool ok = gensig(st, params);
    EXPECT_TRUE(ok);

    prepare_witness(st, in, l, F);

    verc.verify_signature3(l.konst(in.pkx), l.konst(in.pky), l.konst(in.e),
                           in.vwc);

    bool failed = ebk.assertion_failed();
    if (failed) {
      log(ERROR,
          "Failed verification on:\npkx:%s\npky:%s\n  e:%s\n  r:%s\n  s:%s",
          st.pkx, st.pky, st.e, st.r, st.s);
    }
    EXPECT_FALSE(failed);

    // Modify one byte of the signature and ensure that it fails.
    signature_tuple maul_st;
    circuit_params maul_in;
    for (size_t j = 0; j < 100; ++j) {
      maulSignature(st, maul_st);
      prepare_witness(maul_st, maul_in, l, F);
      verc.verify_signature3(l.konst(maul_in.pkx), l.konst(maul_in.pky),
                             l.konst(maul_in.e), maul_in.vwc);
      failed = ebk.assertion_failed();
      EXPECT_TRUE(failed);
    }
  }
}

}  // namespace
}  // namespace proofs
