# AGENTS.md

## 项目背景与当前阶段

项目名：`hybrid-pqc-cert`，课题 5“国密证书支持抗量子算法方案设计”。

当前已完成证书层和独立 KEM primitive：实验性 SM2 +
CRYSTALS-Dilithium2 Composite Signature、Root Hybrid CA、Root 签发 Server、
两级链与严格双验证，以及 FIPS 203 ML-KEM-768 KeyGen/Encaps/Decaps。不要把
ML-KEM 接入 SM2 Hybrid KEX、Hybrid KDF、完整 GM/T 0024/TLCP 握手、TLS
握手或 `post-quantum_pre_shared_key`，除非后续任务明确要求。当前 PQKEX 只
实现 ClientHello capability extension 编解码和 KEM 选择。

不要把总体课题目标和当前实现进度混为一谈。

## 当前已实现

- OpenSSL 3.2.0 EVP SM2/SM3 keygen、sign、verify primitive。
- 官方 `pq-crystals/dilithium` reference implementation、
  `DILITHIUM_MODE=2`（CRYSTALS-Dilithium2）。
- 唯一 Composite Signature Core：
  - `include/composite_key.h`, `src/composite_key.c`
  - `include/composite_sig.h`, `src/composite_sig.c`
- `CompositePublicKey = Dilithium2PK || SM2PublicKey`。
- `CompositeSignature = Dilithium2Signature || DER(SM2Signature)`。
- 自签 Root Hybrid CA 和 Root → Server 两级证书链。
- Root/Server Composite SPKI 与 Certificate signatureValue。
- CA/Server Hybrid private key 的加密持久化和加载。
- 严格 `DilithiumValid && SM2Valid`；没有兼容模式和 fallback。
- Root/Server 角色、BasicConstraints、KeyUsage、EKU、SAN、SKI/AKI、有效期、
  issuer/subject link、课题 Dilithium/PQC 标识扩展、Composite OID 验证。
- primitive、Composite key/signature、X.509 集成和 12 个链负向测试。
- 证书生成、检查、详细链验证及 OpenSSL ASN.1 parse artifact。
- 独立 `include/mlkem.h`、`src/mlkem.c` FIPS 203 ML-KEM-768 wrapper。
- ML-KEM-768 正向、12 类要求的负向/implicit-rejection 测试和 NIST ACVP KAT。
- `mlkem_demo`，不输出 decapsulation key 或 shared secret。
- `patches/gmssl/0001-add-experimental-tlcp-pqkex-capability.patch` 将 capability
  接入固定 GmSSL 的真实 TLCP ClientHello 发送与服务端解析路径；submodule 本身
  保持干净。
- PQKEX 固定 wire vector、严格解析、未知 KEM、协商、duplicate extension 测试和
  `gmssl pqkex_demo` 均包含在该补丁内；主仓库不保留第二套 PQKEX 实现。

## ML-KEM primitive 边界

ML-KEM 使用固定 liboqs 0.16.0 commit
`c27c88b76473f67a8072ce5b66874d172287ff96` 的
`OQS_KEM_alg_ml_kem_768`。CMake 必须维持 minimal build
`KEM_ml_kem_768`；liboqs 源码中虽存在旧 Kyber，`OQS_KEM_alg_kyber_768` 不得
启用、链接或 fallback。

```text
ek:            1184 bytes
dk:            2400 bytes
ciphertext:    1088 bytes
shared secret:   32 bytes
```

wrapper 必须同时做编译期和 runtime length/provider 检查。Encapsulation-key
modulus check 与 decapsulation-key embedded hash check 委托正式
`mlkem-native` provider。篡改但长度正确的 ciphertext 遵循 implicit rejection：
Decaps 可成功产生不同 secret，不能把该返回值解释为 ciphertext 已认证。

生产 API 不得暴露 deterministic `d`、`z`、`m`；它们只允许在 KAT test 中通过
liboqs test API 使用。当前 KAT 是 NIST ACVP-Server v1.1.0.42 FIPS203：
ML-KEM-768 KeyGen tgId 2/tcId 26、Encaps/Decaps tgId 2/tcId 26，逐字节比较
ek/dk/ciphertext/shared secret。

ML-KEM key 仅在内存中使用，不持久化，不进入 Composite Certificate SPKI。
`mlkem` target 与 `hybrid_pqc` target 保持独立。当前证书编码和 Composite 签名
流程不得因 ML-KEM 集成而改变。

## PQKEX capability 边界

主项目自身没有另写 GM/T 0024/TLCP 协议栈；固定的 `third_party/GmSSL` 已有
真实 TLCP ClientHello、通用 TLS Extension 编解码和握手状态机。PQKEX 的
extension_data/完整 Extension 编解码、ClientHello 接入和 capability negotiation
只在 GmSSL 补丁中实现；改动以
`patches/gmssl/0001-add-experimental-tlcp-pqkex-capability.patch` 保存，禁止直接
提交修改后的 submodule 工作树。

```text
PQKEX_EXTENSION_TYPE = 0xFF02  // project-private experimental
PQKEX_KEM_MLKEM768   = 0x0001  // ML-KEM-768 / FIPS 203
```

`0xFF02` 不是 GM/T 或 IANA 正式分配值。wire format 固定为 big-endian：

```text
uint16 extension_type
uint16 extension_length
uint16 kem_list_length
uint16 kem_ids[kem_list_length / 2]
```

单一 ML-KEM-768 的完整字节必须是 `FF02000400020001`。Parser 必须拒绝空列表、
奇数长度、声明长度不一致、截断、trailing garbage、超过 8 个 KEM 和 duplicate
`0xFF02` extension。未知 KEM ID 是 syntactically valid，但不得自动映射成已知
KEM。选择策略是 client preference order，并只集中在
`tls_pqkex_select_kem()`。

PQKEX 补丁不得 include/link/call `mlkem`、Composite 或 X.509。ClientHello 不携带
ML-KEM key；本阶段不定义 ServerHello echo。当前 selected KEM 仅写入
`TLS_CONNECT.pqkex_selected_kem`，供未来 ServerKeyExchange 阶段使用；
`TLS_CONNECT.pqkex_negotiated` 不表示 keypair、ciphertext 或 shared secret 已存在。

GmSSL 补丁只允许在 TLCP ClientHello 加入 capability，并在 server 解析后写入
`TLS_CONNECT.pqkex_selected_kem`。不得调用 GmSSL Kyber、本项目 ML-KEM primitive、
修改 ServerHello 或提前实现 ServerKeyExchange/ClientKeyExchange。补丁必须在
临时 worktree/副本应用、编译和测试，最终 `third_party/GmSSL` 保持 clean。

该分层只参考 expired Internet-Draft
`draft-campagna-tls-bike-sike-hybrid-07`，不得声称符合该 draft，也不得声称为
GM/T 正式 PQKEX。

## 当前验证基线

本阶段完成后的基线结果：

```text
normal clean build:        PASS
normal CTest:              10/10 PASS
ASan + UBSan CTest:        10/10 PASS
mlkem_demo:                PASS
NIST ACVP ML-KEM-768 KAT: PASS
patched GmSSL pqkextest:   PASS (strict TLCP capability tests)
patched gmssl pqkex_demo:  PASS (capability only; no ML-KEM operation)
Root -> Server chain:      VALID
```

主项目原有 8 项 Composite/证书测试、`mlkem` 和 `mlkem_kat` 全部保持通过；
PQKEX 由 patched GmSSL 的 `pqkextest` 覆盖。后续修改 PQKEX、ML-KEM、构建配置
或依赖时，必须同时运行主项目全部 10 项测试和 GmSSL PQKEX 测试。生成的 liboqs
`oqsconfig.h` 还必须确认
`OQS_ENABLE_KEM_ml_kem_768` 已启用且 `OQS_ENABLE_KEM_kyber_768` 未启用。

## 实验性质与标准参考

本项目必须写作：

```text
Experimental SM2 + CRYSTALS-Dilithium adaptation
based on draft-ietf-lamps-pq-composite-sigs-19.
```

该草案定义 ML-DSA 与 ECDSA/RSA/EdDSA 组合，不定义本项目的 SM2 与原始
CRYSTALS-Dilithium2 组合。本项目参考其 Composite 架构、pre-hash、domain
separation 和 raw concat 编码思想，但不符合且不得声称符合该草案。

严禁把 CRYSTALS-Dilithium2 替换成 ML-DSA、ML-DSA-44/65/87 或 liboqs
ML-DSA。

## OID

```text
Composite 实验 OID：1.3.6.1.4.1.32473.1.1
课题 Dilithium/PQC X.509v3 标识扩展：1.3.6.1.4.1.2.267.7
SM2 ID：           1234567812345678
```

Composite OID 使用 RFC 5612 documentation PEN，只能作为实验/演示 OID：

```text
This OID is experimental and is not an IETF/GM/T standardized
SM2-Dilithium composite signature OID.
```

`1.3.6.1.4.1.2.267.7` 是课题指定的 Dilithium/PQC X.509v3 标识扩展，
不是 IETF generic PQC OID。其 extension value 是 DER `NULL`；不得把它作为
Composite 算法 OID，也不得再在该扩展内保存 Dilithium 公钥或签名。

## 不可破坏的证书设计

```asn1
Certificate ::= SEQUENCE {
    tbsCertificate       TBSCertificate,
    signatureAlgorithm   AlgorithmIdentifier,
    signatureValue       BIT STRING
}
```

以下三个 AlgorithmIdentifier 都必须是 `1.3.6.1.4.1.32473.1.1`，parameters
ABSENT，不能编码 NULL：

```text
TBSCertificate.signature.algorithm
Certificate.signatureAlgorithm.algorithm
SubjectPublicKeyInfo.algorithm.algorithm
```

SPKI 的单个 BIT STRING 直接包含：

```text
Dilithium2 public key (1312 bytes) || SM2 uncompressed point (65 bytes)
```

顺序不可交换。SM2 编码固定为 `0x04 || X(32) || Y(32)`，解析必须检查精确
长度、首字节及点在 sm2p256v1 曲线上。

Certificate 的单个 signatureValue BIT STRING 直接包含：

```text
Dilithium2 signature (2420 bytes) || DER SEQUENCE { r INTEGER, s INTEGER }
```

不得在 BIT STRING 内增加 SEQUENCE/OCTET STRING/BIT STRING 包装。SM2 DER
必须无 trailing garbage，r/s 正且非零，并通过 canonical re-encode 检查。

## Composite Core 唯一流程

上层只提交 raw message `M`，禁止先提交 `SM3(M)`：

```text
PH(M)   = SM3(M)
Prefix  = ASCII("CompositeAlgorithmSignatures2025")
Label   = ASCII("COMPSIG-DILITHIUM2-SM2-SM3")
M'      = Prefix || Label || one-byte len(ctx) || ctx || SM3(M)
```

普通消息和 X.509 当前使用 empty ctx。接口保留最多 255 字节 ctx，但不要在本
阶段虚构 TLS/GM/T context。

SM2 primitive 继续按 SM2-with-SM3 处理 `M'`，包括 SM2 ID、ZA 和内部 SM3。
Composite pre-hash 与 SM2 内部 hash 不是同一层，不能删除其中任何一层。

只有 `src/composite_sig.c` 可以同时调用 SM2 与 Dilithium sign/verify primitive。
所有双组件签名必须走 `composite_sign()`；所有双组件验证必须走
`composite_verify()`/`composite_verify_detailed()`，最终严格 AND。旧
`hybrid_sign()`/`hybrid_verify()` 只是 Composite Core 适配器，不得重新加入
primitive 调用。

X.509 层只负责精确取得 `DER(TBSCertificate)`、调用 Composite Core、放入或
读取 signatureValue。不得签整个 Certificate、PEM 文本或预先哈希的 TBS。

## 密钥角色

每次 demo 生成四个独立组件私钥：CA SM2、CA Dilithium2、Server SM2、Server
Dilithium2。CA 和 Server 不得复用任何组件 key。

```text
Root self-sign:       CA Hybrid SK signs DER(root TBS)
Server certificate:  CA Hybrid SK signs DER(server TBS)
Server message:      Server Hybrid SK signs raw application message
Future handshake:    Server Hybrid SK signs protocol-defined data
```

`generate_demo_chain` 首次运行生成并持久化 CA/Server Hybrid key，后续运行
加载。SM2 使用加密 PKCS#8；Dilithium2 使用 AES-256-GCM 认证加密容器，
PBKDF2-HMAC-SHA256 派生密钥，容器同时保存对应 public key，并在加载后执行
Composite sign/verify 自检。目录 `0700`、文件 `0600`，口令仅从
`HYBRID_KEY_PASSPHRASE` 读取，不得打印、提交或写日志。

加载后、重新签发前，必须逐字节验证 loaded Server Hybrid key 的
`Dilithium2PK || SM2PK` 与现有 `server_hybrid.crt` Composite SPKI 完全匹配；
CA key 同样与 Root SPKI 匹配。错误口令、认证失败、部分 key store 或 SPKI
失配必须失败关闭。

## Trust model

Root 是 out-of-band 配置的 trust anchor。Root self-signature PASS 只证明其
Composite 自签名密码学有效，不是 Root 获得信任的原因。

Server 证书必须用 Root SPKI 中的 CA Dilithium2/SM2 公钥验证，绝不能用 Server
自己的公钥验证 CA signature。

## 依赖与版本

第三方代码是固定 Git submodule，不直接修改其工作树：

```text
OpenSSL:   cf2877791ce7508684109664f467c9e40987692f (3.2.0)
GmSSL:     24ae482701a7b124826c382fffc55c19f76d475d
liboqs:    c27c88b76473f67a8072ce5b66874d172287ff96
Dilithium: d35ba3fe5449bee3e6d43e1f296c3ca818bd36be
```

- 核心显式链接 `third_party/openssl`，不能回退系统 OpenSSL。
- Dilithium 只用 `third_party/dilithium/ref` 和 mode 2。
- GmSSL 未链接核心。liboqs 仅链接独立 `mlkem` target，不链接 Composite/X.509
  的 `hybrid_pqc` target。
- 未经明确要求不修改 submodule；第三方补丁放 `patches/`。

## 构建、工具和测试

```sh
git submodule update --init --recursive
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

CTest 应包含并通过：

```text
dilithium
sm2
hybrid_sign
composite_key
composite_message
hybrid_key_store
hybrid_x509
hybrid_chain
mlkem
mlkem_kat
```

生成和验证：

```sh
HYBRID_KEY_PASSPHRASE='use-a-strong-local-secret' \
  ./build/generate_demo_chain \
  certs/root_hybrid.crt certs/root_hybrid.der \
  certs/server_hybrid.crt certs/server_hybrid.der
./build/verify_chain certs/root_hybrid.crt certs/server_hybrid.crt
./build/inspect_hybrid_cert certs/server_hybrid.crt
./build/mlkem_demo
```

OpenSSL 结构检查需要固定 3.2.0 动态库：

```sh
env LD_LIBRARY_PATH=third_party/openssl \
  third_party/openssl/apps/openssl asn1parse \
  -inform DER -in certs/server_hybrid.der -i
```

OpenSSL 不认识实验 Composite OID，`openssl verify` 不能替代本项目的严格双
验证。

Sanitizer：

```sh
cmake -S . -B build-sanitize -DHYBRID_ENABLE_SANITIZERS=ON
cmake --build build-sanitize -j
ASAN_OPTIONS=detect_leaks=0 \
  ctest --test-dir build-sanitize --output-on-failure
```

修改密码学、ASN.1、证书或构建后必须实际编译和运行相关测试。保持
`-Wall -Wextra -Wpedantic` 无项目代码警告。

## 工作规则

- 修改前阅读实现和测试，优先复用，不无意义重写。
- 检查 NULL、malloc/API 返回值、整数转换、长度、DER 尾随数据和错误清理。
- Composite verify fail closed；不提供 OR、silent fallback 或 classical compat。
- 及时清零私钥/敏感中间值；公钥、签名和证书可以记录。
- 不硬编码 `/home/...` 路径。
- 不提交 `build*`、Codex 元数据或 `keys/` 私钥内容。
- 保留用户已有改动；不使用破坏性 Git 命令。
- 实现状态、密码结构、OID、依赖、构建或密钥模型变化时同步更新本文件。
