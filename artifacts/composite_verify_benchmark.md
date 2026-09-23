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
| ECDSA-P256-SHA256 | 10000 | 0.146935 | 0.126471 | 0.244210 | 0.293020 | 0.117970 | 2.441859 | 1.000x |
| SM2-SM3 | 10000 | 0.450297 | 0.407537 | 0.694585 | 0.830873 | 0.362441 | 3.831052 | 3.065x |
| CRYSTALS-Dilithium2 | 10000 | 0.152167 | 0.132172 | 0.254146 | 0.301508 | 0.126123 | 1.796041 | 1.036x |
| SM2+Dilithium2 Composite | 10000 | 0.602109 | 0.549894 | 0.919743 | 1.067118 | 0.489690 | 1.812155 | 4.098x |

Requirement: Composite verify mean < 50.000 ms

Result: **PASS**

ECDSA-P256-SHA256 is the performance baseline only. The primary metric is the public `composite_verify()` call.
