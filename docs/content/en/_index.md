---
title: Longfellow ZK
linkTitle: Home
menu: {main: {weight: 1}}
weight: 1
cascade:
  - type: blog
    # Comment this to make blog appear in the main sidebar nav.
    # It shows all blog posts expanded, and is too long.
    toc_root: true
    _target:
      path: /blog/**
  - type: docs
    _target:
      path: /**
---

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE) [![eprint](https://img.shields.io/badge/eprint-2024%2F2010-blue)](https://eprint.iacr.org/2024/2010)
[![IETF Draft](https://img.shields.io/badge/IETF%20Draft-draft--google--cfrg--libzk-lightgrey)](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)


## Overview

The Longfellow library enables the construction of  zero-knowledge protocols concerning legacy identity verification standards such as the ISO MDOC standard, the JWT standard, and W3 Verifiable Credentials.  This implementation is described in:

* [Anonymous credentials from ECDSA](https://eprint.iacr.org/2024/2010)
* [libzk: A C++ Library for Zero-Knowledge Proofs](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)

It is named after the bridge outside the Google Cambridge office.

## Ongoing Security Reviews

This project is currently undergoing two independent security reviews by panels of academic and industry experts in the field. See [reviews](docs/reviews) for the latest.

