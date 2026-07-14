# BIP-340 Schnorr verification circuit

This directory contains the production Longfellow circuit for the algebraic
part of BIP-340 Schnorr verification over secp256k1. It is intended as a
reusable building block for zero-knowledge protocols that need to prove
knowledge of a Schnorr response without revealing it.

## Statement

The circuit proves `s*G - e*P = R`, where `P` and `R` use BIP-340 x-only
encodings. The explicit public field inputs are `rx`, `px`, and `e`. The
compiler also reserves input zero for the constant one.

The 2,301 private inputs contain the 256-bit decompositions and 255 witnessed
projective intermediate points for each of `s*G` and `e*P`, plus `py`, `ry`,
`rz_inv`, and the 256-bit decomposition of `ry`.

The circuit checks the two scalar-multiplication traces, `s < n`, curve
membership for `P` and `R`, projective equality with `rx` and `ry`, that `R`
is finite, and the even-y requirement for `R`.

## Application boundary

Tagged SHA-256 is deliberately outside this circuit. The application must
parse the signature and x-only public key canonically, reject `rx >= p`,
`s >= n`, and `px >= p`, lift `px` to the BIP-340 even-y point, and compute
`e = tagged_hash("BIP0340/challenge", rx || px || message) mod n` before
verification.

`bip340_witness.h` performs these operations for the provided witness path.
The verifier remains responsible for binding the public `e` to the message,
public key, and signature bytes used by the application.

## Proving backend

Native secp256k1 proving uses
`ReedSolomonFactory<Fp256k1Base,
CrtConvolutionFactory<CRT256<Fp256k1Base>, Fp256k1Base>>`.
The P-256 `Fp2` extension path is not suitable for secp256k1.

The CRT auxiliary primes support FFT order `2^22`. The
`check_crt_block_enc()` guard rejects circuit configurations whose
power-of-two padding exceeds that limit.

## Circuit metrics

For one verification circuit:

| Metric | Value |
| --- | ---: |
| Wires | 26,802 |
| Quadratic terms | 41,443 |
| Depth | 9 |
| Explicit public field inputs | 3 |
| Private witness elements | 2,301 |
| Approximate `block_enc` | 43,745 |
| CRT convolution padding | 65,536 |

`Bip340ParamTest.ReportCircuitParams` reports these values from the compiled
circuit.

## Sage reference

`docs/specs/code/bip340.py` is an independent affine Sage reference for
BIP-340 verification. It validates all 19 Bitcoin Core vectors and computes
semantic golden facts that are compared with the C++ implementation.

It is not a Sage clone of the optimized C++ circuit. This follows the
repository convention: Sage models the proof-system primitives and provides
mathematical reference computations, while production application circuits
such as MDOC are implemented in C++.

## Tests

```bash
cmake -S lib -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target bip340_test -j$(nproc)
ctest --test-dir build -R 'Bip340' --output-on-failure
./docs/specs/code/run_bip340_sage_tests.sh
```
