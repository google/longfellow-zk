# Formal Verification of Zero-Knowledge Circuits

This directory contains the Lean 4 formalizations and mathematical proofs of
soundness and completeness for the Elliptic Curve (EC) and ECDSA Zero-Knowledge
(ZK) circuits.

## Directory Structure

-   `circuits/ECDSA/`: Contains the core elliptic curve arithmetic (`EC.lean`,
    `Curves.lean`, `Nat.lean`), the ECDSA signature verification spec
    (`EcdsaSpec.lean`), circuit constraints (`EcdsaCircuit.lean`), algebraic
    bridging lemmas (`Ecdsa.lean`), completeness (`EcdsaComplete.lean`), and
    soundness (`EcdsaSound.lean`) formalizations and proofs.
-   `circuits/tests/ec/`: Contains the projective public key validation circuit
    constraint logic (`PkCircuit.lean`) and its symbolic polynomial evaluation
    model (`PkCircuitPoly.lean`).
-   `lakefile.toml` / `lake-manifest.json` / `lean-toolchain`: Standard Lean
    package configuration files.

## How to Compile & Verify

### 1. Using Blaze (Bazel)

To compile and mathematically verify all formalizations and proofs in the
package using Google's Blaze build system:

```bash
# Compile all targets
blaze build //privacy/proofs/zk/formal/...

# Run all tests
blaze test //privacy/proofs/zk/formal:ecdsa_lean_test //privacy/proofs/zk/formal:pk_lean_test
```

This will invoke the Lean compiler hermetically, resolving and checking all
proofs.

### 2. Using Lake (Lean's Package Manager)

To compile the project locally using Lake:

```bash
# Navigate to the formal/ package directory
cd privacy/proofs/zk/formal/

# Build the targets
lake build
```
