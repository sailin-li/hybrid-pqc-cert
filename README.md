# hybrid-pqc-cert

*Experimental hybrid post-quantum certificates for Chinese commercial cryptography.*

`hybrid-pqc-cert` 是“国密证书支持抗量子算法方案设计”的实验项目。项目以
SM2/SM3 与官方 `pq-crystals/dilithium` reference implementation 的
CRYSTALS-Dilithium2 构造 Composite Signature 和两级 X.509 证书链；相互隔离的
模块另验证 ML-KEM-768 primitive、TLCP capability/证书接入与 TLS 1.3 external
PSK 实验方案。

> Experimental SM2 + CRYSTALS-Dilithium adaptation based on
> draft-ietf-lamps-pq-composite-sigs-19.

该 draft 不定义 SM2 + CRYSTALS-Dilithium。本项目只参考其 Composite 架构、消息
组合与序列化思想，不声称符合该 draft，也不使用 ML-DSA 替代 Dilithium2。

## Features

- **SM2 + CRYSTALS-Dilithium2 Composite Signature**：统一 core 构造消息并执行
  双组件签名与严格 `DilithiumValid && SM2Valid` 验证。
- **Hybrid X.509 Certificate**：Root CA 与 Server signing certificate 使用
  Composite SPKI 和 Composite issuer signature，支持两级链与负向验证。
- **FIPS 203 ML-KEM-768**：基于固定 liboqs 的独立 KeyGen、Encaps、Decaps
  primitive，包含 implicit rejection 与 NIST ACVP KAT。
- **TLCP PQKEX capability**：通过 GmSSL 补丁在 ClientHello 发布 KEM capability，
  服务端按客户端偏好选择 KEM；尚未执行 ML-KEM key establishment。
- **TLCP Hybrid Certificate Verification**：signing certificate 使用 Composite
  SPKI；encryption certificate 保持 ordinary SM2 SPKI，其 CA signature 为
  Composite。
- **TLS 1.3 `post_quantum_pre_shared_key`**：私有 `0xFF03` flag 复用标准 external
  PSK binder 与 PSK-DHE，同时保留 Certificate 和 CertificateVerify。
- **Performance benchmark**：以 ECDSA-P256-SHA256 为 baseline 测量完整公开
  `composite_verify()` 路径。
- **Security / negative testing**：覆盖严格解析、downgrade、证书篡改、ML-KEM
  错误输入、协议负向场景，以及 ASan/UBSan 回归。

## Architecture

```text
Authentication                              Key Establishment
SM2/SM3 + CRYSTALS-Dilithium2               FIPS 203 ML-KEM-768
                |                                      |
       Composite Signature                    standalone primitive
                |                                      |
       Composite Certificate                  future TLCP Hybrid KEX
                |
   TLCP certificate-chain verification

TLS 1.3 0xFF03: separately provisioned external PSK + ECDHE + certificate auth
```

ML-KEM 不进入 Composite Certificate SPKI；当前也未接入 TLCP master secret、
PRF/KDF 或完整 SM2 + ML-KEM Hybrid KEX。`0xFF02` PQKEX 与 `0xFF03` PQ-PSK
是彼此独立的实验。


## Quick Start

构建要求支持 C11 的编译器、CMake 3.16+、Git，以及仓库固定的 submodule：

```sh
git submodule update --init --recursive
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

CMake 默认将 `OPENSSL_ROOT_DIR` 指向仓库中的 OpenSSL 3.2.0，并要求精确版本；
liboqs 只构建 ML-KEM-768，不启用旧 Kyber fallback。

## Basic Usage

首次生成证书时会在 `keys/` 创建加密 key store；口令必须通过环境变量提供：

```sh
HYBRID_KEY_PASSPHRASE='use-a-strong-local-secret' \
  ./build/generate_demo_chain \
  certs/root_hybrid.crt certs/root_hybrid.der \
  certs/server_hybrid.crt certs/server_hybrid.der
```

```sh
./build/verify_chain certs/root_hybrid.crt certs/server_hybrid.crt
./build/inspect_hybrid_cert certs/server_hybrid.crt
./build/mlkem_demo
```

`mlkem_demo` 不输出 decapsulation key 或 shared secret。TLCP encryption
certificate 的生成参数、GmSSL patch 应用与集成测试见专题文档。

## Performance

正式测量必须使用 Release build：

```sh
cmake -S . -B build-bench -DCMAKE_BUILD_TYPE=Release
cmake --build build-bench -j
./build-bench/benchmark_composite_verify \
  --warmup 1000 --iterations 10000 \
  --csv artifacts/composite_verify_benchmark.csv
```

Composite Verify 以 ECDSA-P256-SHA256 为性能 baseline，项目验收目标为公开
`composite_verify()` mean `< 50 ms`。方法、统计口径与现有结果见
[Benchmark](docs/benchmark.md)。

## Repository Layout

```text
include/       public headers
src/           Composite、X.509、key store、ML-KEM 与 adapter 实现
tests/         primitive、证书、KAT 与负向测试
patches/gmssl/ 固定 GmSSL 的增量实验补丁
scripts/       补丁应用与 TLCP 集成测试脚本
docs/          设计、协议、测试与安全文档
third_party/   固定版本的 OpenSSL、GmSSL、liboqs、Dilithium
```

## Documentation

- [文档导航](docs/README.md)
- [总体架构与模块边界](docs/architecture.md)
- [Composite Signature](docs/composite-signature.md)
- [Composite X.509 与证书链](docs/composite-x509.md)
- [FIPS 203 ML-KEM-768](docs/mlkem.md)
- [TLCP PQKEX capability](docs/tlcp-pqkex.md)
- [TLCP PQKEX ClientHello 抓包](docs/pqkex-capture.md)
- [TLCP Hybrid Certificate](docs/tlcp-hybrid-certificate.md)
- [TLS 1.3 PQ-PSK](docs/tls13-pq-psk.md)
- [Benchmark 方法](docs/benchmark.md)
- [测试与 GmSSL patch workflow](docs/testing.md)
- [安全模型与未完成工作](docs/security.md)

## Experimental Notice

这是 research / experimental project，不用于 production deployment：

- Composite OID `1.3.6.1.4.1.32473.1.1` 是基于 RFC 5612 documentation
  PEN 的实验值，不是 IETF、IANA 或 GM/T 标准化的 SM2-Dilithium OID。
- `1.3.6.1.4.1.2.267.7` 是课题指定的 PQC marker，不是 Composite 算法 OID
  或 IETF generic PQC OID。
- `0xFF02`（TLCP PQKEX）与 `0xFF03`（TLS 1.3 PQ-PSK）均为 project-private
  experimental identifier，未获 GM/T 或 IANA 正式分配。
- 使用 FIPS 203 算法和 ACVP vector 不表示 liboqs 或本项目获得 FIPS 140/CMVP
  module validation。
- QROM security argument 与经典/量子侧信道防护仍未完成；当前实现不是经过
  hardened 评估的生产密码模块。

## References

- [draft-ietf-lamps-pq-composite-sigs-19](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-19)
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [RFC 9973](https://www.rfc-editor.org/rfc/rfc9973.html)
- [RFC 5612 documentation enterprise number](https://www.rfc-editor.org/rfc/rfc5612.html)
- GM/T 0024-2014
- [IANA TLS ExtensionType registry](https://www.iana.org/assignments/tls-extensiontype-values/)
