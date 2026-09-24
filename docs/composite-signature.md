# Composite Signature

## 实验定位

本项目实现 SM2/SM3 + CRYSTALS-Dilithium2 的实验性 Composite Signature，使用
官方 `pq-crystals/dilithium/ref` 并定义 `DILITHIUM_MODE=2`。这不是 ML-DSA，
也不是 draft-ietf-lamps-pq-composite-sigs-19 定义的算法组合。

项目参考该 draft 的 Composite 架构、pre-hash、domain separation 和 raw concat
思路，但不声称标准兼容或得到 IETF/GM/T 分配。

## 唯一 Core

唯一实现位于：

```text
include/composite_key.h   src/composite_key.c
include/composite_sig.h   src/composite_sig.c
```

只有 `src/composite_sig.c` 同时调用 SM2 和 Dilithium primitive。上层均提交 raw
message `M`：

- `composite_sign()` 产生双组件签名；
- `composite_verify()` 返回 Composite 结果；
- `composite_verify_detailed()` 另外报告格式、Dilithium 与 SM2 分量结果；
- 旧 `hybrid_sign()` / `hybrid_verify()` 只是委托 core 的兼容 adapter。

不存在 OR、classical fallback 或第二套组合签名流程。

## Composite message construction

`composite_build_message()` 固定构造：

```text
PH(M)   = SM3(M)
Prefix  = ASCII("CompositeAlgorithmSignatures2025")
Label   = ASCII("COMPSIG-DILITHIUM2-SM2-SM3")
len(ctx)= one unsigned byte
M'      = Prefix || Label || len(ctx) || ctx || SM3(M)
```

当前普通消息和 X.509 都使用空 `ctx`。API 接受 0..255 bytes，供未来协议规范定义
context；当前没有虚构 TLS 或 GM/T context。

`M'` 分别交给 CRYSTALS-Dilithium2 与 SM2-with-SM3。Composite 层的 `SM3(M)`
和 SM2 内部 `ZA` / `SM3(ZA || M')` 是两层不同处理，任何一层都没有省略。SM2
user ID 固定为：

```text
1234567812345678
```

固定单元测试使用 `M="abc"`、`ctx=01 02 03`，逐字节比较 94-byte `M'`。

## Public key encoding

```text
CompositePublicKey = Dilithium2PublicKey || SM2PublicKey
                   = 1312 bytes          || 65 bytes
```

SM2 public key 固定为 sm2p256v1 未压缩点：

```text
04 || X (32 bytes) || Y (32 bytes)
```

`composite_parse_public_key()` 要求精确总长度、首字节 `0x04`、正确曲线，并通过
OpenSSL EVP public check 验证点在曲线上。组件顺序不可交换。

## Signature encoding

```text
CompositeSignature = Dilithium2Signature || DER(SM2Signature)
                   = 2420 bytes           || variable length

SM2Signature ::= SEQUENCE {
    r INTEGER,
    s INTEGER
}
```

Composite signature 不增加外层 SEQUENCE、OCTET STRING 或 BIT STRING。X.509
只把这段 raw concatenation 直接放入一个 `signatureValue` BIT STRING。

SM2 DER parser fail closed：

- 输入必须至少能容纳固定 Dilithium2 signature 与合法 DER；
- DER 必须消耗全部剩余输入，拒绝 trailing garbage；
- `r`、`s` 必须为正且非零；
- canonical re-encode 必须逐字节等于输入。

## Strict AND semantics

验证结果定义为：

```text
CompositeValid = FormatValid && DilithiumValid && SM2Valid
```

即使一个组件验证通过，另一个组件失败也必须整体失败。详细结果只用于诊断，不得
被上层解释为兼容模式。证书验证同样只能经过该 core。

## Key roles

每次 demo 至少使用四个互不复用的组件私钥：CA SM2、CA Dilithium2、Server
SM2、Server Dilithium2。可选 TLCP encryption certificate 另用独立 SM2 key。

```text
Root self-sign:       CA Hybrid SK signs DER(root TBS)
Server certificate:  CA Hybrid SK signs DER(server TBS)
Server message:      Server Hybrid SK signs raw application message
Future handshake:    protocol-defined data and context, not yet implemented
```

X.509 层签的是精确 `DER(TBSCertificate)`，不是整个 Certificate、PEM 文本或上层
预先计算的 SM3 digest。证书结构见 [Composite X.509](composite-x509.md)。
