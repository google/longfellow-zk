# Longfellow ZK


[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE) [![eprint](https://img.shields.io/badge/eprint-2024%2F2010-blue)](https://eprint.iacr.org/2024/2010)
[![IETF Draft](https://img.shields.io/badge/IETF%20Draft-draft--google--cfrg--libzk-lightgrey)](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)
## Overview

The Longfellow library enables the construction of  zero-knowledge protocols concerning legacy identity verification standards such as the ISO MDOC standard, the JWT standard, and W3 Verifiable Credentials.  This implementation is described in:

* [Anonymous credentials from ECDSA](https://eprint.iacr.org/2024/2010)
* [libzk: A C++ Library for Zero-Knowledge Proofs](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)
* [Project documentation](https://google.github.io/longfellow-zk/)

It is named after the bridge outside the Google Cambridge office.

# Security Reviews

This project is currently undergoing two independent security reviews by panels of academic and industry experts in the field. Their reports are available in the [Project documentation/Reviews](https://google.github.io/longfellow-zk/docs/reviews/) page.

# Specifications
This repository contains [the working files](https://github.com/google/longfellow-zk/tree/main/docs/specs) for a specification of Longfellow and its components.
If you are interested in contributing, please create an Issue or a Pull Request. Our discussions occur under Issues.

# Testing via devcontainer
You can quickly test our library by using the associated devcontainer to create its environment. Simply click on `Code`-->`Codespaces`-->`Create codespace on master` above to get started.  This creates a docker container on a Github server that includes all of the dependencies and provides a web-based VScode interface to our current codebase.  You can compile and run our benchmarks in this environment, but some of them may be slower than our reported values due to the VM.

# Instructions to build

## Requirements

This package depends on cmake, openssl, zstd, clang, googletest and
googlebenchmark.

### Ubuntu, debian

```
$ sudo apt install -y clang cmake libssl-dev libzstd-dev libgtest-dev libbenchmark-dev zlib1g-dev
```

### Fedora, redhat

```
$ yum install -y clang libzstd-devel openssl-devel git cmake google-benchmark-devel gtest-devel
```


### MacOS
Ensure that Xcode command line tools such as `clang` and `cmake` are installed.

```
$ brew install googletest google-benchmark zstd
```

## Building manually

First run the cmake initialization step

```
$ CXX=clang++ cmake -D CMAKE_BUILD_TYPE=Release -S lib -B clang-build-release --install-prefix ${PWD}/install
```

Next:

```
$ cd clang-build-release && make -j 16 && ctest -j 16
```

# Running benchmarks

We have defined several unit, sumcheck, and zk benchmarks. Here are some of
them:

```
$ ./algebra/fft_test --benchmark_filter='BM_*'
$ ./circuits/sha/flatsha256_circuit_test --benchmark_filter=BM_ShaZK_fp2_128
```
