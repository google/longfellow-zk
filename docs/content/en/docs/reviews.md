---
title: Reviews
date: 2025-09-01
weight: 3
---


This page documents the security reviews of Longfellow that have been completed by external organizations.

## Trail of Bits
Trail of Bits has reviewed our system and produced a 
[report](../../reviews/Longfellow_report_2025_08_18.pdf). All of the issues have been addressed in the latest release.  To briefly comment on the issues marked "High" severity:

1. Issue #1: The report noted that our library does not read each circuit to verify its hash.  Because our library is intended to be used in a high-performance server, our library provides these methods, but does not perform the check in *each* call to the verifier method. Instead, we expect a proper verifier implementation to perform this costly check once upon start and then cache the circuits in memory.  Our reference verifier implementation illustrates how this can be done.

10. Issue #10: Indeed, this report identified one under-constrained check in a circuit.  The check used a private (witness) variable to determine the length of a string, when instead, it should have used the public (available to the verifier) version of that length.  This issue has been resolved in the mdoc circuit.

