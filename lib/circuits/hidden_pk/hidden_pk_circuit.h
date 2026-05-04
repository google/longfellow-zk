
#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HIDDEN_PK_HIDDEN_PK_CIRCUIT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HIDDEN_PK_HIDDEN_PK_CIRCUIT_H_

// Hidden-PK circuit for secp256k1 ECDSA signatures.
//
// Proves the relation:
//   R = { (eth_addr, msg) ; (pk, sig) :
//           keccak256(pkx_bytes || pky_bytes)[12:32] == eth_addr
//       AND ECDSA_verify_secp256k1(pk, sig, msg) == true }

#include <cstddef>
#include <vector>

#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/tests/sha3/sha3_circuit.h"
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
  using v256  = typename LogicCircuit::v256;

  static constexpr size_t kBits         = EC::kBits;  // 256
  static constexpr size_t kKeccakBlocks = 1;           // 64-byte input < rate=136
  static constexpr size_t kPKBytes      = 32;          // bytes per coordinate

  using EcdsaVerc        = VerifyCircuit<LogicCircuit, Field, EC>;
  using KeccakCircuit    = Sha3Circuit<LogicCircuit>;
  using KeccakBlockWitness = typename KeccakCircuit::BlockWitness;

  struct Witness {
    EltW pk_x;
    EltW pk_y;
    // Bit decompositions: bit[0] = LSB, bit[255] = MSB.
    typename LogicCircuit::template bitvec<kBits> pk_x_bits;
    typename LogicCircuit::template bitvec<kBits> pk_y_bits;
    // Keccak-256 block witnesses (1 block for 64-byte input).
    std::vector<KeccakBlockWitness> keccak_bw;
    // ECDSA verify witness.
    typename EcdsaVerc::Witness ecdsa;

    void input(const LogicCircuit& lc) {
      pk_x = lc.eltw_input();
      pk_y = lc.eltw_input();
      pk_x_bits = lc.template vinput<kBits>();
      pk_y_bits = lc.template vinput<kBits>();
      keccak_bw.resize(kKeccakBlocks);
      for (size_t j = 0; j < kKeccakBlocks; ++j) {
        keccak_bw[j].input(lc);
      }
      ecdsa.input(lc);
    }
  };

  explicit HiddenPKCircuit(const LogicCircuit& lc)
      : lc_(lc), sha_(lc), verc_(lc, p256k1, n256k1_order) {}

  // Asserts:
  //   ECDSA_verify(pk, sig, msg) == true
  //   keccak256(pkx_bytes || pky_bytes)[12:32] == eth_addr
  //
  // eth_addr must be a 20-element vector of v8 (the Ethereum address).
  void assert_hidden_pk(const std::vector<v8>& eth_addr, EltW e,
                        const Witness& w) const {
    // 1. Verify ECDSA signature.
    verc_.verify_signature3(w.pk_x, w.pk_y, e, w.ecdsa);

    // 2. Verify bit decompositions of pk coordinates.
    // Ensures the Keccak input bytes faithfully encode the ECDSA public key.
    lc_.assert_eq(w.pk_x, as_scalar_large(w.pk_x_bits));
    lc_.assert_eq(w.pk_y, as_scalar_large(w.pk_y_bits));

    // 3. Build 64-byte Keccak-256 input: pkx_bytes || pky_bytes (big-endian).
    // pk_x_bits[0] = LSB; seed[0] = MSB byte of pkx = bits 255..248.
    std::vector<v8> seed(64);
    for (size_t i = 0; i < 64; ++i) seed[i] = lc_.template vbit<8>(0);

    // Bytes 0-31: pkx in big-endian byte order.
    for (size_t i = 0; i < kPKBytes; ++i) {
      size_t byte_idx = kPKBytes - 1 - i;  // 31, 30, …, 0
      for (size_t b = 0; b < 8; ++b) {
        seed[i][b] = w.pk_x_bits[byte_idx * 8 + b];
      }
    }
    // Bytes 32-63: pky in big-endian byte order.
    for (size_t i = 0; i < kPKBytes; ++i) {
      size_t byte_idx = kPKBytes - 1 - i;
      for (size_t b = 0; b < 8; ++b) {
        seed[kPKBytes + i][b] = w.pk_y_bits[byte_idx * 8 + b];
      }
    }

    // 4. Assert keccak256(pkx || pky) and check bytes [12..31] == eth_addr.
    std::vector<v8> hash_out;
    sha_.assert_keccak256(seed, hash_out, w.keccak_bw);

    for (size_t i = 0; i < 20; ++i) {
      lc_.vassert_eq(hash_out[12 + i], eth_addr[i]);
    }
  }

 private:
  // Convert a bitvec<N> (LSB-first) to a field element.
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

  const LogicCircuit&   lc_;
  mutable KeccakCircuit sha_;
  EcdsaVerc             verc_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HIDDEN_PK_HIDDEN_PK_CIRCUIT_H_
