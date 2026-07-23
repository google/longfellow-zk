# Longfellow ZK (Rust Implementation)

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../LICENSE)
[![IETF Draft](https://img.shields.io/badge/IETF%20Draft-draft--google--cfrg--libzk-lightgrey)](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)

This directory contains the next-generation implementation of the
Longfellow Zero-Knowledge (ZK) proof system.  It is still under
development, but our (Google) goal is to switch to this implementation
in production.

The major problem with the C++ implementation was the confusing
organization of circuits.  We believe that this implementation is a
major improvement on this front.  We have reworked all circuits in
units with cleanly defined interfaces and extensive tests.  The Rust
type system helps with keeping circuits well-structured and organized,
as opposed to the old C++ templates.  The new compiler supports
rudimentary debug symbols so that one can assert that an invalid input
triggers the exact assertion that is expected to catch that case (as
opposed to a generic "some assertion has failed" of the old system).

All circuits, but especially the mdoc-zk circuits, have been reworked
to be much more stringent.  They perform paranoid checks on all
inputs, irrespective of whether they are necessary or not.  We have
organized the code to maximize local auditability as opposed to
circuit size.

We have a new compiler that generates better circuits than the C++
one.  Consequently, the circuits for the full mdoc-zk application
decreased in size by about 10% despite performing more checks.

We have also rewritten the runtime portion (the prover and verifier)
in Rust.  Performance is about the same as the old implementation, and
even a bit faster.  We have paid specific attention to memory usage:
the new prover produces a proof of the full mdoc-zk circuits in
less than 100MB of memory.  The latest C++ prover was about 170MB,
and the initial prover from 2025 took about 600MB.

We have defined a new circuit format called LFC2 that is much more
compact than the C++ format (retroactively named LFC1).  mdoc-zk
LFC2 circuits consume about 1MB before zstd compression, versus
about 100MB for LFC1.

Despite these improvements, the implementation is 100% backward
compatible with the C++ one.  It can read LFC1 circuits and produce
bit-by-bit equal proofs as the C++ prover.

We are also switching to a new development model.  In the past, the
source of truth was an internal Google repository, with periodic
pushes to github from us (Google).  Going forward, the source of truth
will be github and Google will periodically import github as needed.
This switch will make it easier for us to accept third-party
contributions.

We do not ship a C++ runtime for now, expecting the Rust
implementation to be sufficient for all use cases.  Should this
assumption not be accurate, please let us know and we'll work
out a plan.

---

## Building and Testing

### Requirements
Rust toolchain (1.75 or newer recommended).

### Build the Workspace
```bash
cargo build --release
```

### Run Tests
To run all unit and integration tests across all workspace crates in release mode:
```bash
cargo test -r
```

### Run Benchmarks
To run the end-to-end mDOC ZK performance benchmarks:
```bash
cargo bench -p mdoc-zk-runtime
```

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for details.
