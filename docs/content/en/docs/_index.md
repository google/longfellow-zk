---
title: Documentation
linkTitle: Docs
menu: {main: {weight: 20}}
---


## Testing via devcontainer
You can quickly test our library by using the associated devcontainer to create its environment. Simply click on `Code`-->`Codespaces`-->`Create codespace on master` above to get started.  This creates a docker container on a Github server that includes all of the dependencies and provides a web-based VScode interface to our current codebase.  You can compile and run our benchmarks in this environment, but some of them may be slower than our reported values due to the VM.

## Instructions to build

This package depends on `cmake`, `openssl`, `zstd`, `clang`, `googletest` and
`googlebenchmark`.

### Ubuntu, debian

```
$ sudo apt install libssl-dev libzstd-dev libgtest-dev libbenchmark-dev zlib1g-dev
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
