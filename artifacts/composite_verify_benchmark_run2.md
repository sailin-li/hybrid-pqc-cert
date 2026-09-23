# Composite Verification Benchmark

- CPU: 13th Gen Intel(R) Core(TM) i5-13500H
- OS: Linux 5.19.0-50-generic (x86_64)
- Compiler: GCC 11.4.0
- Build type: Release
- OpenSSL: OpenSSL 3.2.0 23 Nov 2023
- Message size: 1024 bytes
- Warm-up iterations: 1000
- Timed iterations: 10000

| Algorithm | Count | Mean (ms) | P50 (ms) | P95 (ms) | P99 (ms) | Min (ms) | Max (ms) | Relative to P-256 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| ECDSA-P256-SHA256 | 10000 | 0.142686 | 0.125657 | 0.233158 | 0.284012 | 0.117612 | 1.917002 | 1.000x |
| SM2-SM3 | 10000 | 0.449316 | 0.410646 | 0.675480 | 0.800249 | 0.368930 | 3.903339 | 3.149x |
| CRYSTALS-Dilithium2 | 10000 | 0.154022 | 0.132136 | 0.260321 | 0.302707 | 0.126161 | 2.570768 | 1.079x |
| SM2+Dilithium2 Composite | 10000 | 0.619916 | 0.560506 | 0.948925 | 1.103870 | 0.490726 | 4.464461 | 4.345x |

Requirement: Composite verify mean < 50.000 ms

Result: **PASS**

ECDSA-P256-SHA256 is the performance baseline only. The primary metric is the public `composite_verify()` call.
