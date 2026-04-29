

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HIDDEN_PK_HIDDEN_PK_CIRCUIT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HIDDEN_PK_HIDDEN_PK_CIRCUIT_H_

// Hidden-PK circuit for secp256k1 ECDSA signatures.
//
// Proves the relation:
//   R = { (pkHash, msg) ; (pk, sig) :
//           SHA256(pkx_bytes || pky_bytes) == pkHash
//       AND ECDSA_verify_secp256k1(pk, sig, msg) == true }

#include <algorithm>
#include <cstddef>

#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_io.h"
#include "ec/p256k1.h"

namespace proofs {
template <class LogicCircuit>
class HiddenPKCircuit {
 public:
  using Field = Fp256k1Base;
  using EC    = P256k1;
  using Nat   = typename Field::N;
  using Elt   = typename Field::Elt;
  using EltW  = typename LogicCircuit::EltW;
  using v8    = typename LogicCircuit::v8;
  using v32   = typename LogicCircuit::v32;
  using v256  = typename LogicCircuit::v256;

  static constexpr size_t kBits      = EC::kBits;   // 256
  static constexpr size_t kShaBlocks = 2;            // 64-byte input -> 2 blocks
  static constexpr size_t kPKBytes   = 32;           // bytes per coordinate

  using EcdsaVerc      = VerifyCircuit<LogicCircuit, Field, EC>;
  using ShaCircuit     = FlatSHA256Circuit<LogicCircuit,
                                           BitPlucker<LogicCircuit,
                                                      kShaPluckerSize>>;
  using ShaBlockWitness = typename ShaCircuit::BlockWitness;

  struct Witness {
    EltW pk_x;
    EltW pk_y;
    // Bit decompositions: bit[0] = LSB, bit[255] = MSB.
    typename LogicCircuit::template bitvec<kBits> pk_x_bits;
    typename LogicCircuit::template bitvec<kBits> pk_y_bits;
    // SHA-256 intermediate witnesses for 2 blocks.
    ShaBlockWitness sha_bw[kShaBlocks];
    // ECDSA verify witness.
    typename EcdsaVerc::Witness ecdsa;
    void input(const LogicCircuit& lc) {
      pk_x = lc.eltw_input();
      pk_y = lc.eltw_input();
      pk_x_bits = lc.template vinput<kBits>();
      pk_y_bits = lc.template vinput<kBits>();
      for (size_t j = 0; j < kShaBlocks; ++j) {
        sha_bw[j].input(lc);
      }
      ecdsa.input(lc);
    }
  };

  explicit HiddenPKCircuit(const LogicCircuit& lc)
      : lc_(lc), sha_(lc), verc_(lc, p256k1, n256k1_order) {}

  void assert_hidden_pk(const v256& pkHash, EltW e, const Witness& w) const {
    // verify_signature3 checks: identity == g*e + pk*r + (rx,ry)*(-s)
    verc_.verify_signature3(w.pk_x, w.pk_y, e, w.ecdsa);

    // ---- 2. Verify bit decompositions of pk coordinates -------------------
    // Ensures the SHA-256 input bytes faithfully encode the ECDSA public key.
    lc_.assert_eq(w.pk_x, as_scalar_large(w.pk_x_bits));
    lc_.assert_eq(w.pk_y, as_scalar_large(w.pk_y_bits));

    // ---- 3. Build SHA-256 input: pkx_bytes || pky_bytes || padding ---------
    // The 64-byte message (two 32-byte coordinates in big-endian) is hashed
    // in two SHA-256 blocks (64 bytes of data + 64 bytes of padding).
    v8 sha_in[kShaBlocks * 64];
    std::fill(sha_in, sha_in + kShaBlocks * 64, lc_.template vbit<8>(0));

    // Block 1 bytes 0-31: pkx in big-endian byte order.
    // pk_x_bits[0] = LSB = bit 0 of pkx integer.
    // sha_in[0]    = MSB byte = bits 255..248.
    for (size_t i = 0; i < kPKBytes; ++i) {
      size_t byte_idx = kPKBytes - 1 - i;  // 31, 30, …, 0
      for (size_t b = 0; b < 8; ++b) {
        sha_in[i][b] = w.pk_x_bits[byte_idx * 8 + b];
      }
    }

    // Block 1 bytes 32-63: pky in big-endian byte order.
    for (size_t i = 0; i < kPKBytes; ++i) {
      size_t byte_idx = kPKBytes - 1 - i;
      for (size_t b = 0; b < 8; ++b) {
        sha_in[kPKBytes + i][b] = w.pk_y_bits[byte_idx * 8 + b];
      }
    }

    // Block 2: SHA-256 padding for a 64-byte (512-bit) message.
    //   byte 64 : 0x80
    //   bytes 65-119 : 0x00 (already zeroed by std::fill above)
    //   bytes 120-127: big-endian 64-bit message length = 512 = 0x0200
    sha_in[64] = lc_.template vbit<8>(0x80);
    sha_in[126] = lc_.template vbit<8>(0x02);
    sha_in[127] = lc_.template vbit<8>(0x00);

    // nb = 2: we always hash exactly 64 bytes (= 2 SHA-256 blocks).
    v8 nb = lc_.template vbit<8>(kShaBlocks);

    // ---- 4. Assert SHA-256(pkx_bytes || pky_bytes) == pkHash ---------------
    sha_.assert_message_hash(kShaBlocks, nb, sha_in, pkHash, w.sha_bw);
  }

 private:
  // Convert a bitvec<N> (LSB-first) to a field element.
  // Equivalent to the integer value sum(v[i] * 2^i) in the field.
  // Adapted from BitaddrCircuit::as_scalar_large in circuits/tests/pq/bitaddr.
  template <size_t N>
  EltW as_scalar_large(
      const typename LogicCircuit::template bitvec<N>& v) const {
    EltW r   = lc_.konst(lc_.f_.zero());
    Elt  p   = lc_.f_.one();
    Elt  two = lc_.f_.two();
    for (size_t i = 0; i < N; ++i) {
      EltW vi = lc_.eval(v[i]);
      r = lc_.axpy(r, p, vi);
      p = lc_.f_.mulf(p, two);
    }
    return r;
  }

  const LogicCircuit&    lc_;
  ShaCircuit             sha_;
  EcdsaVerc              verc_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HIDDEN_PK_HIDDEN_PK_CIRCUIT_H_
