---
title: Benchmarks
date: 2025-07-05
weight: 3
---

This page documents the results of some of our benchmark suite on different hardware.  All of our code runs _single threaded_ for deployment purposes. It is important not to consume a user's battery if it is not necessary for the performance.

## Mac M1 Pro

### FFT
Because Longfellow uses the Ligero proof system as a component, the FFT may be a bottleneck (without other measures). This benchmark measures the FFT time over different fields. Note that we have another, more realistic _interpolation_ benchmark that measures the Reed-Solomon encoding time. However, this benchmark provides a good method to compare against other implementations.  The Fp2 field is the quadratic extension over the P256 prime.  The Fp128 and Fp64 fields are prime fields of size 128- and 64- bits respectively, and the Fp64_2 field is the quadratic extension of the later.

```
---------------------------------------------------------------
Benchmark                     Time             CPU   Iterations
---------------------------------------------------------------
BM_FFTFp2/1024           345846 ns       345830 ns         2022
BM_FFTFp2/4096          1722630 ns      1722512 ns          406
BM_FFTFp2/16384         8240364 ns      8238690 ns           84
BM_FFTFp2/65536        38528907 ns     38528444 ns           18
BM_FFTFp2/262144      180210719 ns    180202250 ns            4
BM_FFTFp2/1048576     956945375 ns    955722000 ns            1
BM_FFTFp2/4194304    4542839834 ns   4542118000 ns            1
BM_FFT_Fp128/1024         45011 ns        44977 ns        15556
BM_FFT_Fp128/4096        214200 ns       214028 ns         3185
BM_FFT_Fp128/16384      1029625 ns      1029134 ns          681
BM_FFT_Fp128/65536      4926617 ns      4925845 ns          142
BM_FFT_Fp128/262144    23055945 ns     23055548 ns           31
BM_FFT_Fp128/1048576  109355229 ns    109348833 ns            6
BM_FFT_Fp128/4194304 1208500000 ns   1207654000 ns            1
BM_FFT_F64_2/1024         41783 ns        41772 ns        16781
BM_FFT_F64_2/4096        196549 ns       196534 ns         3580
BM_FFT_F64_2/16384       946212 ns       945961 ns          740
BM_FFT_F64_2/65536      4487724 ns      4486645 ns          155
BM_FFT_F64_2/262144    21032507 ns     21026265 ns           34
BM_FFT_F64_2/1048576   99776280 ns     99709429 ns            7
BM_FFT_F64_2/4194304  693080000 ns    692987000 ns            1
BM_FFT_F64/1024           15322 ns        15313 ns        45659
BM_FFT_F64/4096           69367 ns        69331 ns         9974
BM_FFT_F64/16384         318503 ns       318209 ns         2187
BM_FFT_F64/65536        1634509 ns      1633562 ns          429
BM_FFT_F64/262144       7574086 ns      7573554 ns           92
BM_FFT_F64/1048576     36999544 ns     36945000 ns           19
BM_FFT_F64/4194304    283367917 ns    283366500 ns            2
```

### SHA
This benchmark measures the time to prove in zero-knowledge the knowledge of a pre-image of size at most N blocks for a given 256-bit string.

```
--------------------------------------------------------------
Benchmark                    Time             CPU   Iterations
--------------------------------------------------------------
BM_ShaZK_fp2_128/1    10297168 ns     10278104 ns           67
BM_ShaZK_fp2_128/2    18023463 ns     18005205 ns           39
BM_ShaZK_fp2_128/4    32431939 ns     32431682 ns           22
BM_ShaZK_fp2_128/8    63686246 ns     63621364 ns           11
BM_ShaZK_fp2_128/16  118868445 ns    118868500 ns            6
BM_ShaZK_fp2_128/32  241311667 ns    241294000 ns            3
BM_ShaZK_fp2_128/33  244478070 ns    244476667 ns            3
```