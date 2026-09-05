# BIP-340 Schnorr verification circuit

This directory contains a contributed Longfellow circuit for the algebraic
part of BIP-340 Schnorr verification over secp256k1. It is a reusable building
block for zero-knowledge applications that need to prove a valid Schnorr
relation without revealing the response scalar `s` or the lifted points.

At a glance:

| Property | Selection |
| --- | --- |
| Signature relation | `s*G - e*P = R` |
| Circuit field | secp256k1 base field `Fp256k1Base` |
| EC arithmetic | Complete projective formulas, fixed 256-step double-and-add |
| Proof system | Longfellow Sumcheck + Ligero |
| Witness commitment | Salted SHA-256 Merkle tree over RS-extended columns |
| Reed-Solomon backend | Multi-prime CRT convolution |
| Ligero test parameters | `rateinv = 4`, `nreq = 128` |
| Trusted setup | None |

The proof stack is:

```text
BIP-340 constraints -> QuadCircuit -> Sumcheck -> Ligero
    -> Reed-Solomon encoding through CRT convolution
    -> salted SHA-256 Merkle commitment and compressed openings
```

## Statement and witness

The circuit proves

```text
s*G - e*P = R
```

where `P` and `R` are represented from x-only inputs. The application supplies
three public field elements:

- `rx`: the x-coordinate of the signature nonce commitment `R`;
- `px`: the x-only public key;
- `e`: the BIP-340 challenge scalar.

The compiler also reserves public input zero for the constant one, so the
compiled circuit reports four public inputs in total.

The 2,301 private inputs contain:

- the 256 bits of `s` and 255 witnessed projective accumulator points for
  `s*G`;
- the 256 bits of `e` and 255 witnessed projective accumulator points for
  `e*P`;
- the lifted affine coordinates `py` and `ry`;
- `rz_inv`, which proves that the computed `R` is not the point at infinity;
- the 256 bits of `ry`, used to reconstruct it and enforce even parity.

The circuit constrains the scalar-multiplication traces, bitness, `s < n`,
curve membership for `P` and `R`, projective equality with the public `rx`,
finiteness of `R`, and the BIP-340 even-y convention for `R`.

## Design decisions

### Native secp256k1 field

The circuit is compiled over the secp256k1 base field. Curve coordinates are
therefore native field elements, avoiding non-native coordinate arithmetic.
The group order `n` is different from the base-field modulus `p`, so the
response is represented by 256 bits and explicitly constrained to `s < n`.
This range check is necessary even when the group equation holds, because
`s + n` represents the same group scalar but is not a canonical BIP-340
encoding.

### Projective, fixed-shape scalar multiplication

Both `s*G` and `e*P` use a fixed 256-iteration, MSB-first double-and-add trace.
Every bit is constrained, and each intermediate accumulator is supplied as a
witness and checked before it becomes the input to the next step.

Projective coordinates and complete group-law formulas were selected to avoid
a field inversion or exceptional-case branch at every addition. The circuit
performs one fixed sequence independent of the scalar bits: a bit-controlled
multiplexer selects either the input point or the point at infinity. This gives
the compiler a regular constraint shape and keeps the circuit depth small at
the cost of a larger witness.

### X-only points and the nonce commitment `R`

In BIP-340, `R` is the Schnorr nonce commitment carried by its x-coordinate.
The circuit computes `R = s*G - e*P`, proves it is finite and on-curve, and
matches its projective x-coordinate to public `rx`. A witnessed affine `ry` is
reconstructed from 256 constrained bits and required to be even, selecting the
canonical BIP-340 lift.

Similarly, `py` is private and constrained by `py^2 = px^3 + 7`. The supplied
witness generator chooses the even lift of `px`, but the current circuit does
not decompose `py` or constrain its parity. Consequently, the standalone
circuit relation permits either lift of `P`; a protocol that requires strict
BIP-340 x-only public-key semantics must additionally bind `py` to the even
lift. The verifier must also reject a non-canonical external x encoding before
mapping it into a field element.

### Tagged SHA-256 remains outside the circuit

The circuit proves the algebraic relation for a public `e`; it does not prove
SHA-256. The application must parse the signature and public key canonically,
reject `rx >= p`, `s >= n`, and `px >= p`, lift `px`, and compute

```text
e = SHA256_tagged("BIP0340/challenge", rx || px || message) mod n
```

before verification. Keeping SHA-256 outside avoids adding a large bit-oriented
hash circuit to an otherwise field-native EC circuit. The trade-off is an
important API boundary: the verifier is responsible for binding public `e` to
the message, public key, and signature bytes. `bip340_witness.h` implements
this parsing and hashing for the supplied witness path.

### Proof-system commitment

The Schnorr nonce commitment `R` and the proof-system witness commitment are
different objects. BIP-340 does not introduce a special Pedersen or KZG
commitment here. The ZK proof inherits Longfellow's transparent Ligero
commitment:

1. The witness and constraint data are arranged in a blinded Ligero tableau.
2. Each row is Reed-Solomon extended.
3. Each extension column becomes a Merkle leaf
   `SHA256(fresh_32_byte_nonce || encoded_column)`.
4. Inner nodes are `SHA256(left || right)`.
5. The Merkle root enters the Fiat-Shamir transcript before challenges are
   sampled.
6. The prover opens 128 distinct challenged columns and sends a compressed
   multi-opening containing only sibling nodes that cannot be reconstructed.

The random Ligero rows provide the zero-knowledge blinding; the per-leaf
nonces are part of the Merkle commitment construction. The query count and
Reed-Solomon rate are proof-system parameters controlling the soundness,
proof-size, and work trade-off. They are not BIP-340-specific primitives.

### CRT Reed-Solomon encoding

Native secp256k1 proving uses:

```cpp
ReedSolomonFactory<
    Fp256k1Base,
    CrtConvolutionFactory<CRT256<Fp256k1Base>, Fp256k1Base>>
```

The P-256 `Fp2` extension strategy is not suitable here because the
secp256k1 base field has insufficient 2-adicity for the required practical
power-of-two FFT domains. The CRT backend performs the convolution over
auxiliary FFT-friendly primes and reconstructs the result in the native
field.

The auxiliary primes support FFT order `2^22`. `check_crt_block_enc()` rejects
a configuration when the next power-of-two padding for `block_enc` exceeds
that limit, producing a clear parameter error before the FFT implementation is
entered.

## Size and performance

Compiler-reported metrics for one verification circuit are:

| Metric | Value |
| --- | ---: |
| Wires | 26,802 |
| Quadratic terms | 41,443 |
| Circuit depth | 9 |
| Application public field inputs | 3 |
| Compiled public inputs, including constant one | 4 |
| Private witness elements | 2,301 |
| Total compiled inputs | 2,305 |
| Approximate `block_enc` | 43,745 |
| CRT convolution padding | 65,536 |

`Bip340ParamTest.ReportCircuitParams` derives these values from the compiled
circuit. The 65,536-point transform is 64 times smaller than the CRT backend's
`2^22` maximum transform order, leaving capacity for larger composed circuits;
composition still needs to check the guard because padding grows in powers of
two.

An illustrative Release-mode smoke test on a 12th Gen Intel Core i9-12900HK,
using GCC 14.2 and one process, produced the following ranges over five runs:

| Measurement | Observed range |
| --- | ---: |
| Ligero commit + prove | 42.8-43.7 ms |
| Verify | 26.1-27.3 ms |
| End-to-end test process | 0.10 s |
| Peak resident memory | 20.1-20.5 MiB |

These figures are a development snapshot, not a portable benchmark. They
exclude application I/O and do not report serialized proof size. Compiler,
CPU, allocator, proof parameters, and circuit composition can materially
change the result. The dominant prover work is the Merkle/RS commitment and
sumcheck; verifier work is driven mainly by the challenged Ligero columns and
their Merkle openings rather than by replaying all 41,443 quadratic terms.

## Files

| File | Purpose |
| --- | --- |
| `bip340_verify.h` | Circuit constraints for the algebraic verification relation |
| `bip340_witness.h` | Canonical parsing, tagged hashing, point lifting, and witness generation |
| `bip340_guard.h` | CRT transform-capacity validation |
| `bip340_test.cc` | Evaluation, vectors, soundness, mutation, ZK, parameter, and scale tests |
| `specs/code/bip340.py` | Independent affine Sage reference |

## Sage reference

`specs/code/bip340.py` validates all 19 Bitcoin Core vectors and computes
semantic golden facts that are compared with the C++ implementation. It is an
independent affine reference, not a clone of the optimized projective circuit.

The runner adds `docs/specs/sage` to `PYTHONPATH`, so shared Sage modules can
be imported rather than duplicated. BIP-340 type checks use that directory's
mypy configuration and stubs as well.

## Tests

```bash
cmake -S lib -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target bip340_test -j$(nproc)
ctest --test-dir build -R 'Bip340' --output-on-failure
./lib/circuits/tests/contrib/bip340/specs/code/run_bip340_sage_tests.sh
```

The C++ suite includes valid and invalid upstream vectors, real Ligero
prover/verifier runs, canonical-scalar and even-y soundness tests, private and
public mutation tests, proof tampering, CRT boundary checks, and a two-instance
composition smoke test.

## Acknowledgements

This circuit is designed, written, and maintained by Denis Roio
<jaromil@dyne.org>. The most up-to-date implementation is available in the
[Dyne Longfellow ZK repository](https://github.com/dyne/longfellow-zk).

The circuit is used by [Zenroom](https://zenroom.org) through the zkcc circuit
compiler DSL as an optimized implementation of *Improved Concurrent-Secure
Blind Schnorr Signatures* by Pierpaolo Della Monica and Ivan Visconti
([ePrint 2025/1992](https://eprint.iacr.org/2025/1992)).
