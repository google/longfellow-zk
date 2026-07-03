# AGENTS.md — Longfellow ZK Implementation Guide for LLMs

## Project Overview

Longfellow ZK is a C++17 library for zero-knowledge proofs, implementing the
protocol from [Anonymous Credentials from ECDSA](https://eprint.iacr.org/2024/2010)
and the [libzk IETF draft](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/).
It targets ECDSA-based anonymous credentials over ISO MDOC, JWTs, and W3C Verifiable
Credentials.

- **License:** Apache 2.0
- **Compilers:** Clang (primary), GCC (supported)
- **Build system:** CMake 3.13+ with Ninja generator
- **Testing:** Google Test + Google Benchmark, discovered via CTest
- **Dependencies:** OpenSSL, zstd, GTest, Google Benchmark

## Architecture

The library uses a layered architecture built around three core abstractions:

### 1. Field Arithmetic (`lib/algebra/`)
Finite field implementations for crypto-native and generic fields:
- `fp.h` — Generic N-word prime field `Fp<N, montgomery>` (template)
- `fp_p256k1.h` — **secp256k1 base field** `Fp256k1<true>` (the native proving target)
- `fp_p256.h` — P-256 base field
- `fp_p384.h` / `fp_p521.h` — P-384 / P-521 fields
- `fp2.h` — Quadratic field extension `Fp2<Field>` (for non-native RS roots)
- `crt.h` — **CRT256<Field>**: Chinese Remainder Theorem over 17 auxiliary 64-bit
  primes. Used for convolution when the native field lacks suitable FFT roots.
  `kOmegaOrder = 2^22 = 4,194,304`.
- `crt_convolution.h` — `CrtConvolutionFactory<CRT, Field>` — convolution via CRT
- `fft.h` — Standard FFT over fields with native roots of unity
- `reed_solomon.h` — `ReedSolomonFactory<Field, ConvolutionFactory>` — RS encoding

**Critical architectural decision:** For secp256k1, you MUST use the CRT RS path:
```
ReedSolomonFactory<Fp256k1Base, CrtConvolutionFactory<CRT256<Fp256k1Base>, Fp256k1Base>>
```
Do NOT use the Fp2 extension path — secp256k1's low 2-adicity prevents practical
FFT domains. The Fp2 root path works for P-256 but silently fails for secp256k1.

### 2. Proof Protocol Stack

The ZK proving pipeline goes through these layers:

```
ZkProver/ZkVerifier   (zk/)
  └─ Sumcheck          (sumcheck/)
       └─ Ligero        (ligero/)
            └─ Merkle   (merkle/)
            └─ Reed-Solomon  (algebra/)
                 └─ CRT or FFT convolution (algebra/)
```

Key types:
- `Circuit<Field>` — Compiled sumcheck circuit (from `sumcheck/circuit.h`)
- `QuadCircuit<Field>` — Circuit builder; collects gates, then `mkcircuit()` finalizes
- `LigeroParam<Field>` — Parameters: `nw` (witnesses), `nq` (quadratic constraints),
  `rateinv` (RS rate inverse), `nreq` (queries), optionally `block_enc`
- `ZkProof<Field>` — Serializes proof data (Ligero commitment + sumcheck layers)
- `ZkProver<Field, RSFactory>` — Proves a circuit witness via Ligero + Sumcheck
- `ZkVerifier<Field, RSFactory>` — Verifies a ZkProof against public inputs

### 3. Circuit DSL (`lib/circuits/`)

Circuits are built via a frontend/backend pattern:

**Frontends** (what circuit authors use):
- `Logic<Field, Backend>` — High-level circuit API: `konst()`, `mul()`, `add()`,
  `sub()`, `mux()`, `assert_eq()`, `assert_is_bit()`
- `EltW` — Wire type (reference to a circuit gate output)
- `BitW` — Bit wire (with value-checking semantics)

**Backends** (how circuits are executed):
- `EvaluationBackend<Field>` — Direct evaluation (for testing: checks constraints
  on concrete inputs)
- `CompilerBackend<Field>` — Compiles operations into `QuadCircuit<Field>` gates

**Production circuits** (in `lib/circuits/`):
- `ecdsa/verify_circuit.h` — ECDSA signature verification
- `mac/mac_circuit.h` — MAC verification
- `sha/flatsha256_circuit.h` — Flat SHA-256 circuit
- `mdoc/` — ISO MDOC credential handling
- `logic/` — Bit pluckers, adders, counters, unary encoders, memcmp, routing

**Experimental circuits** (in `lib/circuits/tests/` — NOT production-vetted):
- `anoncred/` — Anonymous credentials with P-256
- `ec/pk_circuit.h` — Public key derivation (sk × G → PK) with typed tests for
  both P-256 and **secp256k1**
- `pq/bitaddr/` — Bitcoin address derivation via SHA-256 + RIPEMD-160 over secp256k1
- `sha3/` — SHA-3/Keccak circuits
- `base64/` — Base64 decoding circuits
- `jwt/` — JWT verification
- `ripemd/` — RIPEMD-160 circuit
- `mdoc/` — MDOC 1f / revocation circuits
- `pq/ml_dsa/` — ML-DSA (post-quantum) circuits

### 4. Elliptic Curves (`lib/ec/`)

- `elliptic_curve.h` — `EllipticCurve<Field, NWords, Bits>` template
- `p256k1.h` / `p256k1.cc` — **secp256k1** (a=0, b=7), base field Fp256k1Base,
  scalar field Fp256k1Scalar
- `p256.h` — P-256 (a=-3)

The EC library provides projective-coordinate point arithmetic, scalar multiplication,
and normalization. Compiled as an OBJECT library `ec`.

## Build System

### Root CMakeLists.txt (`lib/CMakeLists.txt`)
- Project name: `proofs`, C++17, includes `CMake/proofs.cmake`
- Auto-detects architecture and adds flags: `-mpclmul` (x86_64), `-march=armv8-a+crypto` (aarch64), `-mcpu=apple-m1` (Mac ARM)
- `include_directories(${proofs_SOURCE_DIR})` — all code uses paths relative to `lib/`

### CMake Macros (`lib/CMake/proofs.cmake`)
- `proofs_add_test(PROG)` — Creates executable from `PROG.cc`, auto-links `ec`,
  `algebra`, `util`, `testing_main`, `GTest::gtest`, `pthread`, `benchmark::benchmark`.
  Calls `gtest_discover_tests(PROG)` for CTest integration.
- `proofs_add_tests(PROG1 PROG2...)` — Calls `proofs_add_test` for each.
- Finds `zstd` via `find_path`/`find_library`, imports as `zstd` target.

### Adding a new test directory
1. Create `CMakeLists.txt` in the directory:
   ```cmake
   # For a single test file new_test.cc:
   proofs_add_tests(new_test)
   # Add extra libraries if needed:
   target_link_libraries(new_test flatsha ripemd)
   ```
2. Add `add_subdirectory(circuits/tests/your_dir)` to root `lib/CMakeLists.txt`
   under the `# experiments and tests` section.

### Building
```bash
# Configure
cmake -S lib -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
# Build
cmake --build build -j$(nproc)
# Test
ctest --test-dir build --output-on-failure -j$(nproc)
# Run specific tests
ctest --test-dir build -R 'P256K1|Bitaddr|Ecpk' --output-on-failure
```

### Dependencies
```bash
# Ubuntu/Debian
sudo apt install -y build-essential clang cmake libssl-dev libzstd-dev libgtest-dev libbenchmark-dev zlib1g-dev
```

## Current State (2026-07-03)

- **280/280 CTest tests pass** on main
- **secp256k1 field inversion and EC multi-exponentiation tests pass** (tests 53, 129)
- **Native secp256k1 ZK proof code EXISTS but is NOT wired to CTest:**
  - `lib/circuits/tests/ec/pk_circuit_test.cc` — typed tests for P256 + P256K1
    including `ZkProverVerifier` using CRT backend + benchmarks. **No CMakeLists.txt.**
  - `lib/circuits/tests/pq/bitaddr/bitaddr_test.cc` — Bitcoin address derivation ZK
    proofs using `Fp256k1Base` + `CRT256<Fp256k1Base>`. **No CMakeLists.txt.**
- **Neither directory has `add_subdirectory` in root CMakeLists.txt**

## secp256k1 Proving Architecture

### The CRT Reed-Solomon path (correct for secp256k1)
```cpp
using Field = Fp256k1Base;
using Crt = CRT256<Field>;
using ConvolutionFactory = CrtConvolutionFactory<Crt, Field>;
using RSFactory = ReedSolomonFactory<Field, ConvolutionFactory>;

ConvolutionFactory factory(field);
RSFactory rsf(factory, field);
ZkProver<Field, RSFactory> prover(circuit, field, rsf);
```

### The Fp2 FFT extension path (WRONG for secp256k1)
```cpp
// This only works for P-256, NOT secp256k1!
using Field2 = Fp2<Field>;
using ConvolutionFactory = FFTExtConvolutionFactory<Field, Field2>;
```
secp256k1's base field `p = 2^256 - 2^32 - 977` has very low 2-adicity (p-1 has few
powers of 2), making it impossible to find practical FFT roots in `Fp2`. The CRT
backend solves this by working over 17 auxiliary 64-bit primes with `omega_order = 2^22`.

### CRT capacity limit
`kOmegaOrder = 1ull << 22 = 4,194,304`. The RS convolution padding is the next
power of two at least `block_enc`. If `block_enc` padding exceeds `2^22`, proving
will fail inside FFT/twiddle logic — catch this early with an assertion.

## BIP-340 / Schnorr on secp256k1

BIP-340 defines Schnorr signatures with specific conventions:
- **x-only public keys** (32 bytes, implicit even-y coordinate)
- **lift_x()** — Recover full point from x-only (y = sqrt(x³+7), choose even y)
- **Tagged hashing:** `SHA256("BIP0340/challenge" || "BIP0340/challenge" || R.x || P.x || m)`
- **Schnorr equation:** `s·G = R + e·P` where `e = tagged_hash(R.x || P.x || msg)`
- **Verification:** `s·G - e·P = R` with x-only comparison

The existing Longfellow circuits for ECDSA verification (`circuits/ecdsa/`) and
SHA-256 (`circuits/sha/`) provide patterns for implementing BIP-340 circuits.
The `ec/pk_circuit.h` double-and-add pattern with intermediate witness checking
is directly applicable to the Schnorr multi-scalar multiplication.

## Plan: `secp256k1-native-proving.org`

Active development plan in `.gestalt/plans/secp256k1-native-proving.org`:
1. **[#A]** Wire existing secp256k1 proof tests into CMake + CTest
2. **[#A]** Implement RPBSch/BIP-340 verification as a vertical slice
3. **[#B]** Validate CRT parameter scalability (guard `block_enc ≤ 2^22`)
4. **[#C]** Clean up build integration and documentation

### BIP-340 implementation conventions
- Keep all new files in a subdirectory separated from existing Longfellow code
  (e.g., `circuits/tests/ec/bip340/`)
- Create a small **reusable tagged-hash wrapper** for BIP-340's `SHA256(tag||tag||msg)`
- Follow the vertical slice pattern: circuit, witness, test, prover/verifier test
- Use the CRT RS backend (not Fp2) for native secp256k1 proving

## Common Pitfalls

1. **Don't use `Fp2`-based FFT extension factories for secp256k1.** Always use
   `CrtConvolutionFactory<CRT256<Fp256k1Base>, Fp256k1Base>`.

2. **`block_enc` padding must not exceed `2^22`** for CRT-backed proofs. The
   `choose_padding()` in `crt_convolution.h` computes the next power of 2 ≥
   `block_enc`; if `block_enc > 2^22 + 1`, the FFT twiddle factors will fail.

3. **`proofs_add_test` only auto-links `ec`, `algebra`, `util`.** If your test
   needs `circuits/compiler`, `circuits/logic`, `zk`, `sumcheck`, `random`,
   or circuit libraries like `flatsha`/`ripemd`/`base64`, add explicit
   `target_link_libraries`.

4. **The `include_directories(${proofs_SOURCE_DIR})` in root CMakeLists.txt**
   means all `#include` paths are relative to `lib/`. Use `#include
   "circuits/tests/ec/pk_circuit.h"`, not relative paths.

5. **The anonymous-credential circuit tests (`circuits/tests/anoncred/`) use P-256
   (Fp2 extension path).** Don't copy their RS factory pattern for secp256k1 work.

6. **Test execution is slow.** ZK proof tests (ZkProverVerifier, BitaddrTest) are
   heavyweight — each generates and verifies actual Ligero proofs. Run focused
   test sets with `ctest -R` during development, full suite only at milestones.

## Key File Map

```
lib/
├── CMakeLists.txt                    # Root build; add_subdirectory here for new tests
├── CMake/proofs.cmake                # proofs_add_test macro, gtest integration
├── algebra/
│   ├── crt.h                         # CRT<VS, Field>: kOmegaOrder = 2^22
│   ├── crt_convolution.h             # CrtConvolutionFactory<CRT, Field>
│   ├── fp_p256k1.h                   # Fp256k1<true> = secp256k1 base field
│   ├── reed_solomon.h                # ReedSolomonFactory<Field, ConvFactory>
│   └── fft.h                         # Standard FFT (native roots)
├── ec/
│   ├── p256k1.h / p256k1.cc          # secp256k1 curve: P256k1, Fp256k1Base, Fp256k1Scalar
│   └── p256.h                        # P-256 curve
├── circuits/
│   ├── ecdsa/verify_circuit.h        # ECDSA verification pattern
│   ├── sha/flatsha256_circuit.h      # SHA-256 circuit
│   ├── logic/logic.h                 # Logic<EltW> circuit DSL
│   ├── compiler/compiler.h           # QuadCircuit builder, mkcircuit()
│   └── tests/
│       ├── ec/pk_circuit_test.cc     # P256 + P256K1 typed ZK proof tests (NEEDS CMake)
│       ├── ec/pk_circuit.h           # Ecpk circuit: proves PK = sk × G
│       ├── ec/pk_witness.h           # PkWitness: computes bits + intermediates
│       ├── pq/bitaddr/bitaddr_test.cc # Bitcoin addr ZK proofs (NEEDS CMake)
│       └── ...
├── zk/
│   ├── zk_proof.h                    # ZkProof<Field>: serialization
│   ├── zk_prover.h                   # ZkProver<Field, RSFactory>
│   ├── zk_verifier.h                 # ZkVerifier<Field, RSFactory>
│   └── zk_testing.h                  # run_test_zk() helpers, kLigeroRate=7, kLigeroNreq=132
├── ligero/
│   └── ligero_param.h               # LigeroParam: nw, nq, rateinv, nreq, block_enc
├── sumcheck/
│   └── circuit.h                     # Circuit<Field>
└── testing/
    └── CMakeLists.txt                # testing_main library
```

## Working with the Plan

The `.gestalt/plans/secp256k1-native-proving.org` plan follows a structured workflow:
- Each L1 is a major work unit, each L2 is a sub-task
- L1/L2 have TODO status, marked WIP when active, DONE when complete
- Each L2 that changes files requires a conventional commit
- Tests are run after each L2 (touched tests only) and after each L1 (full suite)

**Current branch:** `secp256k1-native-proving`

## BIP-340 / Schnorr Verification (2026-07-03)

A vertical slice for BIP-340 Schnorr signature verification over native
secp256k1 is in `lib/circuits/tests/ec/bip340/`:

| File | Purpose |
|------|---------|
| `bip340_verify.h` | Circuit: `s·G - e·P = R` with x-only keys, double-and-add |
| `bip340_witness.h` | Witness generator: `compute_from_scalars()` for testing, `compute()` for real sigs |
| `bip340_guard.h` | CRT capacity guard: rejects `block_enc` exceeding `2^22` FFT order |
| `bip340_test.cc` | 12 tests: eval, circuit size, ZK prover/verifier, guard, scale |

**Circuit metrics (single BIP-340 verify):**
wires=25,544, quad_terms=39,599, depth=8, block_enc≈41,646, padding=65,536

**Proving backend:** Always use `CrtConvolutionFactory<CRT256<Fp256k1Base>, Fp256k1Base>`.
The `bip340_guard.h` provides `check_crt_block_enc<CRT>()` to catch oversized
configurations before they fail inside FFT twiddle-factor computation.
