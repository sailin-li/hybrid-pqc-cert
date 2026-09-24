# Composite verification benchmark

## Target 与验收指标

`benchmark_composite_verify` 测量公开 `composite_verify()`，项目验收指标是其
mean verification time 严格小于 `50 ms`。ECDSA-P256-SHA256 只是性能 baseline，
不会替代实际使用的 SM2 + CRYSTALS-Dilithium2。

同一 executable、同一 1024-byte deterministic raw message 测量：

1. ECDSA-P256-SHA256 Verify；
2. SM2-SM3 Verify；
3. CRYSTALS-Dilithium2 Verify；
4. SM2 + Dilithium2 Composite Verify。

message 固定为 `message[i] = i & 0xff`，避免四条路径输入不一致。

## Composite scope

Composite timed region 直接调用完整 `composite_verify()`，包含：

- Composite signature parsing；
- `composite_build_message()`；
- SM3 pre-hash；
- Dilithium2 verify；
- SM2 verify；
- strict AND result。

timed region 不包含：

- key generation 或 signing；
- certificate generation、ASN.1 certificate parse 或 path validation；
- key store、disk I/O 或随机数生成；
- benchmark 初始化或 OpenSSL provider/library 初始化；
- TLCP/TLS handshake。

## 正式运行

性能结果必须来自 Release build，不得使用 ASan、UBSan、Debug 或 `-O0` build：

```sh
cmake -S . -B build-bench -DCMAKE_BUILD_TYPE=Release
cmake --build build-bench -j
taskset -c 2 \
  ./build-bench/benchmark_composite_verify \
    --warmup 1000 \
    --iterations 10000 \
    --csv artifacts/composite_verify_benchmark.csv
```

`taskset` 可选；指定 CPU 能降低 scheduler noise。每次正式报告应记录 CPU、OS、
compiler、OpenSSL version、build type、message size、warm-up 与 timed iterations。

建议连续运行至少三次，并预先约定使用代表运行或三次统计汇总，不能事后只选择
最快结果。CPU topology 可用 `lscpu` 留档。

## 输出与统计

每个算法输出：

- count；
- mean；
- p50 / median；
- p95；
- p99；
- min / max；
- relative to ECDSA-P256-SHA256。

工具还报告 Composite 与 baseline 的时间差，以及近似 framework overhead：

```text
Composite mean - SM2 mean - Dilithium2 mean
```

该差值只用于观察 glue、pre-hash 与 parsing 的合计成本，不是独立 microbenchmark。
指定 `--csv` 时，会同时在相同 basename 生成 Markdown 汇总。

## 当前 artifact

仓库的代表 Release 结果在
[`artifacts/composite_verify_benchmark.md`](../artifacts/composite_verify_benchmark.md)：

```text
ECDSA-P256-SHA256 mean:             0.146935 ms
SM2-SM3 mean:                       0.450297 ms
CRYSTALS-Dilithium2 mean:           0.152167 ms
SM2+Dilithium2 Composite mean:      0.602109 ms
Requirement:                       < 50.000 ms
```

这些数值是特定 Intel Core i5-13500H / Linux / GCC 11.4.0 环境的实验结果，不是
跨平台保证。`artifacts/` 另保留重复运行结果。

## CTest smoke

普通 CTest 中的 `benchmark_smoke` 只使用 1 次 warm-up、10 次 timed iterations，
用于确认 executable 和四条 verify 路径能工作。它不执行跨机器 `50 ms` hard gate，
也不能替代正式 Release benchmark。
