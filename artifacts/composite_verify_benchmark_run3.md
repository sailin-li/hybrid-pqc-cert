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
| ECDSA-P256-SHA256 | 10000 | 0.143413 | 0.126284 | 0.232816 | 0.289901 | 0.117616 | 1.069960 | 1.000x |
| SM2-SM3 | 10000 | 0.455318 | 0.407863 | 0.719204 | 0.820804 | 0.357451 | 3.391074 | 3.175x |
| CRYSTALS-Dilithium2 | 10000 | 0.146207 | 0.131484 | 0.230711 | 0.281546 | 0.126178 | 1.000603 | 1.019x |
| SM2+Dilithium2 Composite | 10000 | 0.609202 | 0.555351 | 0.930277 | 1.081598 | 0.495855 | 3.443893 | 4.248x |

Requirement: Composite verify mean < 50.000 ms

Result: **PASS**

ECDSA-P256-SHA256 is the performance baseline only. The primary metric is the public `composite_verify()` call.
