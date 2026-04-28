<p align="center">
  <a href="https://soundness.xyz" target="_blank">
    <img src="https://soundness-xyz.notion.site/image/attachment%3Aa4df3045-521c-41da-a0ef-ad89d7b2852e%3Abacf94a6-5284-4794-b5ec-5a8844affca7.png?table=block&id=262cb720-3e2b-80ee-af44-e4101aab1819&spaceId=2b0fa06f-b360-4628-a423-b7731e622496&width=1420&userId=&cache=v2" alt="Soundness Labs Logo" width="400">
  </a>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/status-Work_In_Progress-yellow" alt="Status: WIP"></a>
  <a href="#"><img src="https://img.shields.io/badge/build-success-green" alt="Build"></a>
  <a href="https://soundness.xyz"><img src="https://img.shields.io/badge/Website-soundness.xyz-purple" alt="Website"></a>
</p>

# Hidden-PK Wallet Circuit

**By [Soundness Labs](https://soundness.xyz)** — built on [Longfellow-ZK](https://github.com/google/longfellow-zk) (Google)

> **Work in Progress**: This is an active research prototype and is not production-ready. APIs, circuit design, and parameters may change. Do not use this to secure real assets until a stable release is announced.

This repo extends the Longfellow-ZK library with a `hidden_pk` circuit that proves ECDSA signature validity over secp256k1 without revealing the public key or the signature. The circuit is the cryptographic core of [ERC-XXXX: Hidden-PK Wallet](./ERC-DRAFT.md), a quantum-resistant smart contract wallet standard that works with today's Ethereum infrastructure.

The public key and signature never appear onchain. Hash preimage resistance survives quantum attacks. The account stays quantum-safe regardless of how many transactions it processes.

---

## Table of Contents

- [What We Built](#what-we-built)
- [Circuit Relation](#circuit-relation)
- [Prerequisites](#prerequisites)
- [Build](#build)
- [Running the Tests](#running-the-tests)
- [Benchmarks](#benchmarks)
- [Repository Structure](#repository-structure)
- [Acknowledgements](#acknowledgements)
- [About Soundness Labs](#about-soundness-labs)

---

## What We Built

Longfellow-ZK is a Google-developed ZK library for anonymous credentials: proving statements about ECDSA signatures without revealing them. It uses a Ligero-based proof system with a CRT Reed-Solomon construction that handles secp256k1's FFT-unfriendly field (secp256k1's base field has `v_2(p^2−1) = 5`, making standard NTT-based RS unusable).

We contributed a `hidden_pk` circuit on top of this library that proves the following:

1. A valid secp256k1 ECDSA signature exists under some public key `pk`
2. `SHA256(pkx_bytes || pky_bytes) == pkHash`

Both `pk` and `(r, s)` stay as private witnesses. This is the core primitive for a quantum-resistant wallet: the onchain contract stores only `pkHash` and validates transactions via this ZK proof.

---

## Circuit Relation

```
R = { (pkHash, e) ; (pk, sig) :
        SHA256(pkx_bytes || pky_bytes) == pkHash
    AND ECDSA_verify_secp256k1(pk, sig, e) == true }
```

`e` is the transaction hash (public). `pk = (pkx, pky)` and `sig = (r, s)` are private witnesses. Revealing `(r, s)` alongside `e` is enough to recover `pk` via `ecrecover`: this is why both must stay hidden.

---

## Prerequisites

### macOS

```bash
brew install googletest google-benchmark zstd
```

Ensure Xcode command line tools (clang, cmake) are installed.

### Ubuntu / Debian

```bash
sudo apt install -y clang cmake libssl-dev libzstd-dev libgtest-dev libbenchmark-dev zlib1g-dev
```

### Fedora / RedHat

```bash
yum install -y clang libzstd-devel openssl-devel git cmake google-benchmark-devel gtest-devel
```

---

## Build

```bash
git clone https://github.com/SoundnessLabs/longfellow-zk-hiddenpk.git
cd longfellow-zk-hiddenpk

CXX=clang++ cmake -DCMAKE_BUILD_TYPE=Release -S lib -B clang-build-release
make -C clang-build-release hidden_pk_test -j16
```

OR
```bash
make -C clang-build-release hidden_pk_test -j$(nproc)
```
---

## Running the Tests

All commands run from the repo root.

```bash
# Full test suite (circuit size + ZK prove/verify)
./clang-build-release/circuits/hidden_pk/hidden_pk_test

# Circuit size only (~300ms, mostly compilation)
./clang-build-release/circuits/hidden_pk/hidden_pk_test --gtest_filter=HiddenPK.CircuitSize

# Full ZK prove + verify with timing breakdown
./clang-build-release/circuits/hidden_pk/hidden_pk_test --gtest_filter=HiddenPK.ZkProverVerifier

# Prover benchmark (circuit compiled outside the loop)
./clang-build-release/circuits/hidden_pk/hidden_pk_test --benchmark_filter=BM_HiddenPKProver
```

---

## Benchmarks

Measured on Apple M1 (single core, Release build). Circuit parameters: `kLigeroRate=7`, `kLigeroNreq=132`.

| Metric | Value |
|---|---|
| Circuit inputs | 7,694 |
| Public inputs | 258 (256 pkHash bits + e) |
| Circuit layers | 11 |
| Circuit compilation (one-time) | ~370ms |
| RS commitment | ~40ms |
| Sumcheck | ~42ms |
| **Total prove time** | **~87ms** |
| **Verification time** | **~65ms** |
| **Proof size** | **226 KB (231,532 bytes)** |

Circuit compilation is a one-time cost per session. On mobile hardware expect 2–4× the proving time.

### Proof size breakdown

| Component | Size |
|---|---|
| Commitment (Merkle root) | 32 B |
| Sumcheck proof | 17.6 KB |
| Column opening proofs (132 columns) | 213.9 KB |

Column openings dominate. Reducing `kLigeroNreq` to 64 cuts proof size roughly in half while keeping soundness above 100 bits.

### On-chain cost estimate (mainnet)

The verifier is hash-only — no pairings, no elliptic curve ops. Gas breaks down as:

| Item | Gas |
|---|---|
| Calldata (226 KB, ~70% non-zero bytes) | ~2.5M |
| Keccak256 Fiat-Shamir (~200 calls) | ~50K |
| Merkle path verification (132 paths) | ~330K |
| Linear combination over public inputs | ~50K |
| **Total** | **~3M gas** |

---

## Repository Structure

Files added to the Longfellow-ZK base:

```
lib/circuits/hidden_pk/
├── CMakeLists.txt          Build target for hidden_pk_test
├── hidden_pk_circuit.h     Circuit: ECDSA verify + SHA256(pk) commitment
├── hidden_pk_witness.h     Witness computation from (sk, e, r, s)
└── hidden_pk_test.cc       Tests and Google Benchmark
```

---

## Acknowledgements

This work builds on:

- [Longfellow-ZK](https://github.com/google/longfellow-zk) by Google — the ZK library and Ligero/sumcheck proving backend
- [Anonymous Credentials from ECDSA](https://eprint.iacr.org/2024/2010) — Frigo and Shelat, the paper this library implements


## About Soundness Labs

<p align="center">
  <a href="https://soundness.xyz" target="_blank">
    <img src="https://soundness-xyz.notion.site/image/attachment%3Aa4df3045-521c-41da-a0ef-ad89d7b2852e%3Abacf94a6-5284-4794-b5ec-5a8844affca7.png?table=block&id=262cb720-3e2b-80ee-af44-e4101aab1819&spaceId=2b0fa06f-b360-4628-a423-b7731e622496&width=1420&userId=&cache=v2" alt="Soundness Labs Logo" width="400">
  </a>
</p>

**[Soundness Labs](https://soundness.xyz)** builds quantum-ready cryptographic infrastructure for blockchains, replacing fragile trust with verifiable security.

- **Website**: [soundness.xyz](https://soundness.xyz)
- **GitHub**: [github.com/SoundnessLabs](https://github.com/SoundnessLabs)
- **X**: [@SoundnessLabs](https://twitter.com/SoundnessLabs)

---

<p align="center">
  <b>By Soundness Labs</b><br>
  <i>Towards building a Sound Internet.</i>
</p>
