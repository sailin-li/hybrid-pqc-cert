# Composite X.509 与证书链

## AlgorithmIdentifier 与 OID

Composite Signature 实验 OID：

```text
1.3.6.1.4.1.32473.1.1
```

它使用 RFC 5612 documentation PEN，只能用于实验和演示：

> This OID is experimental and is not an IETF/GM/T standardized
> SM2-Dilithium composite signature OID.

它不是 IETF、IANA 或 GM/T 正式分配的算法标识。AlgorithmIdentifier 的
`parameters` 必须 ABSENT，不能编码为 ASN.1 NULL。

## Composite subject key 与 issuer signature

X.509 中两件事必须分开理解：

- SubjectPublicKeyInfo 描述证书 subject 自己的 public key type；
- `TBSCertificate.signature`、outer `signatureAlgorithm` 与 `signatureValue`
  描述 issuer 如何签发该证书。

因此，一个普通 SM2 subject key 可以由 Composite CA signature 保护。TLCP
encryption certificate 正是这种有意解耦。

## 三类证书

| Certificate | Subject SPKI | Issuer signature |
|---|---|---|
| Root Hybrid CA | Composite | Composite self-signature |
| Server signing certificate | Composite | Root Composite signature |
| TLCP encryption certificate | ordinary `id-ecPublicKey + sm2p256v1` | Root Composite signature |

对 Root 和 Server signing certificate，以下三个位置都是 Composite OID 且
parameters ABSENT：

```text
TBSCertificate.signature.algorithm
Certificate.signatureAlgorithm.algorithm
SubjectPublicKeyInfo.algorithm.algorithm
```

对 encryption certificate，只有前两个位置使用 Composite OID；SPKI 保持普通
SM2。三类证书的 `signatureValue` 都是单一 BIT STRING，内容为
`Dilithium2Signature || DER(SM2Signature)`。

## Root 与 Server profile

```text
Root Hybrid CA
├── Composite SPKI: Dilithium_CA_PK || SM2_CA_PK
├── BasicConstraints: critical, CA:TRUE
├── KeyUsage: critical, keyCertSign, cRLSign
├── SubjectKeyIdentifier
├── PQC marker
└── Composite self-signature
        |
        | CA Hybrid SK signs DER(Server TBSCertificate)
        v
Server signing certificate
├── Composite SPKI: Dilithium_Server_PK || SM2_Server_PK
├── BasicConstraints: critical, CA:FALSE
├── KeyUsage: critical, digitalSignature
├── ExtendedKeyUsage: serverAuth
├── SubjectAltName: DNS:server.local
├── SubjectKeyIdentifier / AuthorityKeyIdentifier
├── PQC marker
└── Composite CA signature
```

Encryption certificate 具有 `CA:FALSE`、critical `keyEncipherment` 与
`keyAgreement`、SKI/AKI、PQC marker、普通 SM2 SPKI 和 Composite CA signature；
它没有 Dilithium subject key。

## PQC marker

课题指定 X.509v3 marker OID：

```text
1.3.6.1.4.1.2.267.7
```

它与 Composite algorithm OID 不同，不是 IETF generic PQC OID。extension value
固定为 DER `NULL`；其中不保存 Dilithium public key 或 signature。Root、Server
signing certificate 和 encryption certificate 均带有该 marker，验证时缺失即失败。

## Chain validation

`hybrid_verify_chain()` 验证 Root -> Server 两级链，包括：

- Root 已由调用者显式配置为 trust anchor；
- Root self-signature 的 Composite 密码学有效性；
- issuer / subject name link 与证书有效期；
- BasicConstraints、KeyUsage、server EKU 与 SAN；
- SKI / AKI link；
- marker、AlgorithmIdentifier 和 SPKI 编码；
- 使用 Root SPKI 中的 CA Dilithium2/SM2 keys 验证 Server issuer signature；
- 两个签名组件严格 AND。

Root 的 self-signature PASS 只证明自签名在密码学上有效。Root 之所以受信任，是
因为它被 out-of-band 配置为 trust anchor，而不是因为它能够自签。

Server issuer signature 绝不能用 Server 自己的 public key 验证。Encryption
certificate 也必须使用 Root Composite SPKI 验证，并另外检查其 ordinary SM2
subject key 与 encryption profile。

## 生成与检查

Root 和 Server signing certificate：

```sh
HYBRID_KEY_PASSPHRASE='use-a-strong-local-secret' \
  ./build/generate_demo_chain \
  certs/root_hybrid.crt certs/root_hybrid.der \
  certs/server_hybrid.crt certs/server_hybrid.der
```

额外生成 TLCP encryption certificate：

```sh
HYBRID_KEY_PASSPHRASE='use-a-strong-local-secret' \
  ./build/generate_demo_chain \
  certs/root_hybrid.crt certs/root_hybrid.der \
  certs/server_hybrid.crt certs/server_hybrid.der \
  certs/server_encryption.crt certs/server_encryption.der
```

最后一个可选参数可指定 key root，默认 `keys/`。仓库当前提交的 `certs/` 只含
Root 与 Server signing certificate；encryption certificate 需按需生成。

```sh
./build/verify_chain certs/root_hybrid.crt certs/server_hybrid.crt
./build/inspect_hybrid_cert certs/server_hybrid.crt

env LD_LIBRARY_PATH=third_party/openssl \
  third_party/openssl/apps/openssl asn1parse \
  -inform DER -in certs/server_hybrid.der -i
```

OpenSSL 3.2.0 不认识该实验 Composite OID，`openssl verify` 不能替代项目的严格
双组件验证。编码规则详见 [Composite Signature](composite-signature.md)，key
store 见 [安全说明](security.md)。
