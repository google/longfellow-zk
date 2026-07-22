# Longfellow ZK Reference Implementation

This directory contains the authoritative reference implementation of
the Longfellow Zero-Knowledge Proof System (prover and verifier),
written in Rust. It formally specifies the proof wire format,
Fiat-Shamir transcript derivation, and the exact verification
algorithm.  In addition, it specifies a not yet deployed circuit
representation (`LFC2` circuit files).

The Longfellow zero-knowledge proof system implements the protocol
introduced in [Anonymous Credentials from ECDSA](https://cic.iacr.org/p/3/1/7)
(IACR Communications in Cryptology).

This codebase is a specification and reference implementation designed
for clarity, mathematical correctness, and authoritative specification
compliance. It is slow and not intended for performance benchmarking.
The reference prover implementation is not space-efficient and uses an
O(n log n) algorithm. An O(n) space and time prover implementation is
possible.  Lagrange polynomial interpolation in this reference
implementation is computed in O(n^2) time via explicit evaluation
matrices. An O(n log n) algorithm via FFT variants is possible.
See the paper for details.

Zero-knowledge blinding requires a trusted source of random bits.  We
do not specify how this source should be implemented.  For testing
purposes, we provide a deterministic pseudo-random source so that one
can compare another implementation against the reference
implementation.  Do not use this source in any real application.

## Repository Layout

The codebase is organized into several key modules under `src/`:

`src/algebra/` implements finite field arithmetic for GF(2^128) and
P-256, BLAS vector operations, and Lagrange interpolation matrices.

`src/circuit/` defines circuit structures, layer layouts, terms, and
the parser for the LFC2 Longfellow circuit format.

`src/ligero/` implements the Ligero polynomial commitment scheme,
including Reed-Solomon encoding, Merkle heap commitments, low-degree
testing, and linear and quadratic constraint verification.

`src/sumcheck/` implements masked multilinear sumcheck proving and
layer evaluation routines.

`src/zk/` provides top-level prover (`ZkProver`), verifier
(`ZkVerifier`), and symbolic sumcheck verification logic.

`src/transcript.rs` implements Fiat-Shamir transcript state tracking
and AES-256 PRF challenge generation.

`src/merkle.rs` implements SHA-256 Merkle heap tree commitments and
inclusion proof verification.

`src/error.rs` defines the unified crate-level `ZkError` type.

The `tests/` directory contains all test suites, including integration
test vectors (`test_reference.rs`), verifier negative soundness tests
(`verifier_negative_tests.rs`), zero-layer circuit tests
(`empty_circuit_tests.rs`), and unit tests (`unit_tests.rs`).

## Running Tests

To run the complete reference test suite:

```bash
cargo test --release
```

To run individual test modules:

```bash
cargo test --test test_reference
cargo test --test verifier_negative_tests
cargo test --test empty_circuit_tests
cargo test --test unit_tests
```
