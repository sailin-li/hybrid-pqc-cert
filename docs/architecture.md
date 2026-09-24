# 总体架构

## 目标与分层

项目验证两个相互分离的方向：

```text
Authentication                              Key Establishment

SM2/SM3       CRYSTALS-Dilithium2            FIPS 203 ML-KEM-768
   \                 /                                |
    \ strict AND    /                         standalone primitive
     Composite Signature                              |
              |                               future TLCP Hybrid KEX
     Composite X.509
              |
  Root CA -> Server certificate
              |
  TLCP Certificate verification
```

Authentication 使用 SM2/SM3 + CRYSTALS-Dilithium2。Key Establishment 当前只有
独立 ML-KEM-768 primitive 和 PQKEX capability negotiation；二者尚未连接。ML-KEM
key 不持久化，也不进入 Composite SPKI。

另有一条独立 TLS 1.3 实验路径：私有 `0xFF03` 表示使用预配置 external PSK、
ECDHE 与证书认证的组合。它不调用 ML-KEM，也不复用 TLCP `0xFF02`。

## 模块关系

```text
dilithium_ref ----\
                   +--> hybrid_pqc --> tools / certificate tests
OpenSSL::Crypto ---/        |
                            +--> TLCP raw-DER adapter
                                     |
                                     +--> patched GmSSL callback

liboqs (ML-KEM-768 only) --> mlkem --> mlkem_demo / ML-KEM tests

third_party/GmSSL + patches/gmssl/0001..0004
    --> TLCP PQKEX capability
    --> TLCP Certificate receive-path integration
    --> TLS 1.3 PQ-PSK
```

`hybrid_pqc` 链接 `OpenSSL::Crypto` 与 Dilithium reference code；CMake 默认把
`OPENSSL_ROOT_DIR` 指向仓库固定的 OpenSSL 3.2.0，并要求精确版本。该 target
不链接 GmSSL 或 liboqs。`mlkem` 是独立 target，只链接 minimal liboqs。GmSSL
保留为固定、干净的 submodule；协议改动只以补丁保存。

## Authentication 路径

1. `composite_build_message()` 对 raw message 做统一 pre-hash 与 domain
   separation。
2. `composite_sign()` 使用 Dilithium2 和 SM2 private component 签名。
3. Composite public key 与 signature 使用 raw concatenation。
4. X.509 层只负责取得 `DER(TBSCertificate)`、调用 core 和装配证书。
5. Root、Server signing certificate 与 TLCP encryption certificate 都由严格
   `DilithiumValid && SM2Valid` 验证 issuer signature。

TLCP signing certificate 的 subject key 是 Composite；encryption certificate
的 subject key 是普通 SM2。subject key type 与 issuer signature algorithm 是两个
独立维度。

## Key Establishment 路径

`include/mlkem.h` / `src/mlkem.c` 提供 ML-KEM-768 KeyGen、Encaps、Decaps。
GmSSL `0001` 补丁只在 TLCP ClientHello 中发布 `0xFF02` capability，并在服务端
选择共同 KEM。当前没有：

- ML-KEM encapsulation key 或 ciphertext 的握手传输；
- SM2 + ML-KEM secret combination；
- TLCP master secret、PRF/KDF、Finished 或 record layer 改动；
- 完整 GM/T 0024 Hybrid KEX。

## TLS 1.3 实验路径

GmSSL `0004` 补丁加入空 flag `0xFF03`。标准 `pre_shared_key` 仍承载 identity、
binder 与 selected_identity；external PSK 进入 Early Secret，ECDHE 进入 Handshake
Secret。即使选中 PSK，Certificate 与 CertificateVerify 仍必须发送和验证，所以
这不是 PSK-only authentication。

## 固定依赖

| Dependency | Commit | 用途 |
|---|---|---|
| OpenSSL 3.2.0 | `cf2877791ce7508684109664f467c9e40987692f` | SM2/SM3、ASN.1、X.509、key store |
| GmSSL | `24ae482701a7b124826c382fffc55c19f76d475d` | TLCP 与 TLS 1.3 实验补丁基线 |
| liboqs 0.16.0 tree | `c27c88b76473f67a8072ce5b66874d172287ff96` | ML-KEM-768 provider |
| pq-crystals/dilithium | `d35ba3fe5449bee3e6d43e1f296c3ca818bd36be` | reference Dilithium2 |

版本变更会影响编码、KAT、补丁可应用性和实验可复现性，必须连同全部测试重新验证。

## 当前边界

已完成的是证书层、TLCP Certificate 接收路径、独立 KEM primitive、PQKEX
capability、TLS 1.3 PQ-PSK 和验证性能实验。未来工作包括完整 TLCP Hybrid KEX、
协议定义的 Composite proof-of-possession、QROM security argument 与侧信道防护
分析。参见 [安全说明](security.md)。
