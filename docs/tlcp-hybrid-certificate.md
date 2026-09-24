# TLCP Hybrid Certificate

## 双证书模型

TLCP server 使用 signing certificate 与 encryption certificate。项目的实验 profile
有意分离 subject key type 与 issuer certificate signature：

| Role | Subject public key | CA signature |
|---|---|---|
| cert[0] signing | Composite `Dilithium2PK || SM2PK` | Composite |
| cert[1] encryption | ordinary SM2 | Composite |

两张实体证书都由 Root Hybrid CA 签发，CA signature 都必须满足
`DilithiumValid && SM2Valid`。cert[1] 不因为使用 Composite CA signature 就拥有
Composite subject key。

## 增量补丁与 adapter

```text
0001 add PQKEX capability
  |
0002 integrate Composite signing-certificate verification
  |
0003 recognize Composite-signed encryption certificate
```

- `0002-integrate-tlcp-composite-certificate-verification.patch` 接入 TLCP
  Certificate receive path、downgrade policy、SM2 component import 和实验 server
  loader。
- `0003-verify-composite-signed-tlcp-encryption-certificate.patch` 只让 GmSSL
  语法层识别实验 Composite certificate signature OID，并让 loader 通过 raw index
  取得 cert[1]；它不在 GmSSL 内实现 Composite 密码学。

主项目中的窄适配层为：

```text
include/tlcp_hybrid_cert_adapter.h
src/tlcp_hybrid_cert_adapter.c
```

它直接接收 raw DER，不创建临时 PEM 文件。GmSSL 通过 callback 获得三态结果：

```text
VALID          recognized and all required checks passed
INVALID        recognized but malformed or verification failed
NOT_APPLICABLE not a Composite signing-certificate flow
```

## Certificate receive flow

```text
tlcp_recv_server_certificate
        |
        +-- Composite -> raw-DER adapter
        |                  |
        |                  +-- cert[0] issuer signature:
        |                  |      Dilithium2 AND SM2
        |                  |
        |                  +-- cert[1] ordinary SM2 SPKI
        |                  |      + Composite CA signature:
        |                  |        Dilithium2 AND SM2
        |                  |
        |                  +-- VALID -> import verified SM2 keys
        |                  +-- INVALID -> fatal bad_certificate
        |
        +-- non-Composite + compatible policy
                           -> original GmSSL verifier
```

## Strict 与 compatible policy

- **Strict expected-hybrid**：普通 SM2 signing certificate 被视为 downgrade；
  `NOT_APPLICABLE` 也映射为 fatal `bad_certificate`。
- **Compatible**：只有 `NOT_APPLICABLE` 可以 fallback 到原 GmSSL certificate
  verifier。
- **两种模式共同规则**：`INVALID` 永不 fallback；已识别 Composite 证书的任一
  格式、profile 或组件验证失败都必须关闭连接。

该 compatible policy 只允许未使用实验 profile 的传统双 SM2 TLCP 走原路径，
不是对损坏 Hybrid certificate 的宽松验证。

## ServerKeyExchange

验证 cert[0] 后，adapter 通过现有 `composite_parse_public_key()` 取得已验证的
65-byte SM2 component public key。GmSSL 经公开 import 路径将其转换为 `SM2_KEY`，
继续验证原 TLCP ServerKeyExchange signature。

当前安全语义是：

```text
Certificate-chain authentication:
    SM2 + Dilithium2 strict Composite verification

ServerKeyExchange proof-of-possession:
    existing TLCP SM2 signature
```

因此不能描述为“TLCP 所有签名流程已 Composite 化”。Certificate message 的
issuer authentication 是 Hybrid；ServerKeyExchange proof-of-possession 仍为 SM2。

## 验证覆盖

主项目和 patched GmSSL integration test 覆盖：

- cert[0] Composite SPKI、cert[1] ordinary SM2 SPKI；
- cert[1] Composite inner/outer signature OID 与 PQC marker；
- 两张证书的双组件 strict AND；
- cert[0]/cert[1] 任一无效导致整个 Certificate message 失败；
- Dilithium 或 SM2 signature tamper；
- marker 缺失、inner/outer OID 不一致、错误 CA component；
- ordinary SM2 CA-signed cert[1] downgrade；
- encryption private key 与 cert[1] SPKI 不匹配；
- Certificate 后进入现有 SM2 ServerKeyExchange 状态。

PQKEX capability 与 Hybrid Certificate 是独立开关。本流程不传输 ML-KEM 数据，
也不修改 master secret、PRF/KDF、Finished 或 record layer。
