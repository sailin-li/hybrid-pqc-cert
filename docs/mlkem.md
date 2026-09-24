# FIPS 203 ML-KEM-768

## 实现范围

`include/mlkem.h` 与 `src/mlkem.c` 提供独立的 ML-KEM-768 wrapper：

- `mlkem768_keygen()`；
- `mlkem768_encaps()`；
- `mlkem768_decaps()`；
- keypair 与 shared-secret cleanup。

它是单独的 CMake `mlkem` target，只链接 liboqs，不被 `hybrid_pqc`、Composite
Signature 或 X.509 target 链接。

## Provider 与固定版本

项目使用固定 liboqs source commit：

```text
c27c88b76473f67a8072ce5b66874d172287ff96
```

算法 identifier 为 `OQS_KEM_alg_ml_kem_768` / `ML-KEM-768`，provider 报告
`alg_version = "FIPS203"`，底层为 liboqs 收录的 `mlkem-native`。CMake 强制：

```cmake
OQS_MINIMAL_BUILD=KEM_ml_kem_768
```

源码树内即使存在旧 Kyber，也不启用、链接或作为 fallback。生成的
`oqsconfig.h` 应定义 `OQS_ENABLE_KEM_ml_kem_768`，且不定义
`OQS_ENABLE_KEM_kyber_768`。

## 固定长度

| Object | Length |
|---|---:|
| Encapsulation key (`ek`) | 1184 bytes |
| Decapsulation key (`dk`) | 2400 bytes |
| Ciphertext | 1088 bytes |
| Shared secret | 32 bytes |

wrapper 通过 `_Static_assert` 核对编译期常量，并在每次操作前检查 provider 可用性、
正式算法名、`FIPS203` version marker 和全部 runtime length。API 还检查 NULL、
精确输入长度和输出容量。

## Validation 与 implicit rejection

FIPS 203 encapsulation-key modulus check 与 decapsulation-key embedded public-key
hash check 委托正式 `mlkem-native` provider；项目不另写不完整的多项式检查。

长度正确但内容被篡改的 ciphertext 遵循 implicit rejection：Decaps 可以返回成功
并产生一个 32-byte secret，但该 secret 应与合法 encapsulation 的 shared secret
不同。API success 不能解释为 ciphertext 已认证。错误 key、篡改 ciphertext 和
全零 ciphertext 的测试均按这一语义处理。

## KAT

生产 API 只提供随机化 KeyGen、Encaps、Decaps，不暴露 deterministic `d`、`z`
或 `m`。确定性入口只由 `tests/test_mlkem_kat.c` 直接调用 liboqs test API。

KAT 来自
[NIST ACVP-Server `v1.1.0.42`](https://github.com/usnistgov/ACVP-Server/tree/v1.1.0.42/gen-val/json-files)
的 FIPS203 vectors：

- ML-KEM-768 KeyGen：tgId 2 / tcId 26；
- ML-KEM-768 Encaps/Decaps：tgId 2 / tcId 26。

测试逐字节比较 `ek`、`dk`、ciphertext 与 shared secret。

## Demo

```sh
./build/mlkem_demo
```

demo 输出 provider、参数长度和 PASS/FAIL，不打印 decapsulation key 或 shared
secret。ML-KEM keys 当前只存在于内存，不持久化。

## 协议隔离

ML-KEM-768 尚未进入：

- Composite Certificate SPKI；
- TLCP ClientHello `0xFF02` payload；
- ServerKeyExchange 或 ClientKeyExchange；
- SM2 + ML-KEM Hybrid Secret；
- TLCP master secret、PRF/KDF、Finished 或 record layer；
- TLS 1.3 `0xFF03` external PSK provisioning。

因此“PQKEX capability negotiated”不表示 ML-KEM keypair、ciphertext 或 shared
secret 已经存在。未来 TLCP KEX 方向见 [TLCP PQKEX](tlcp-pqkex.md)。

使用 FIPS 203 算法和 ACVP vectors 也不表示 liboqs 或本项目获得 FIPS 140/CMVP
module validation。
