# hybrid-pqc-cert

本项目实现一个两级实验 PKI：Root CA 和 Server 均使用单一 Composite
X.509 算法标识，组件为 SM2/SM3 与官方 reference
CRYSTALS-Dilithium2。项目另有一个完全独立的 FIPS 203 ML-KEM-768
primitive wrapper，用于验证 KeyGen、Encaps 和 Decaps；它尚未接入协议层。

> Experimental SM2 + CRYSTALS-Dilithium adaptation based on
> draft-ietf-lamps-pq-composite-sigs-19.

本实现只参考该草案的 Composite 架构、消息组合和序列化思想；草案定义的是
ML-DSA 与 ECDSA/RSA/EdDSA 的组合，不包含 SM2 或 CRYSTALS-Dilithium，因而
本项目**不符合且不声称符合**该草案。项目不使用 ML-DSA、liboqs ML-DSA 或
FIPS 204 参数集。

## 当前范围

已实现：

- OpenSSL 3.2.0 EVP SM2/SM3 primitive；
- 官方 `pq-crystals/dilithium/ref`、`DILITHIUM_MODE=2`；
- 唯一的 Composite Signature Core；
- Composite 公钥、签名的 raw concat 编解码与严格检查；
- 自签 Root Hybrid CA；
- Root CA 签发 Server Hybrid Certificate；
- Root → Server 两级链与严格 `DilithiumValid && SM2Valid` 验证；
- CA/Server Hybrid Private Key 加密持久化、加载及证书 SPKI 匹配检查；
- 正向、primitive 反向和 12 个证书链反向测试；
- PEM/DER 证书生成、检查和详细链验证工具；
- FIPS 203 ML-KEM-768 KeyGen、Encaps、Decaps wrapper；
- ML-KEM 正向、输入错误、implicit rejection 和 NIST ACVP 对照测试；
- 实验性 GM/T 0024 PQKEX ClientHello capability extension 编解码与协商；
- 面向固定 GmSSL submodule 的真实 TLCP ClientHello/服务端解析集成补丁。

当前不实现 SM2 + ML-KEM Hybrid KEX、Hybrid KDF、完整 GM/T 0024/TLCP
PQKEX 握手、TLS 握手或 `post-quantum_pre_shared_key`。目前的 PQKEX 仅完成
ClientHello capability advertisement 和 server-side KEM selection。

## 算法和编码

Composite 算法 OID：

```text
1.3.6.1.4.1.32473.1.1
```

这是基于 RFC 5612 documentation PEN 的**实验/演示 OID**。

> This OID is experimental and is not an IETF/GM/T standardized
> SM2-Dilithium composite signature OID.

它不能用于生产注册空间，不代表 IANA、IETF 或 GM/T 已分配该组合算法。
`1.3.6.1.4.1.2.267.7` 是课题指定的 Dilithium/PQC X.509v3 标识扩展，
不是 IETF generic PQC OID，也不等于 Composite 算法 OID。该扩展只保存 DER
`NULL` 标识值，不再保存第二公钥或第二签名。

三个 X.509 位置使用同一个 Composite OID，且 `parameters` 必须 ABSENT：

```text
TBSCertificate.signature.algorithm
Certificate.signatureAlgorithm.algorithm
SubjectPublicKeyInfo.algorithm.algorithm
```

公钥编码直接放在 SPKI 的单个 BIT STRING 中：

```text
CompositePublicKey = Dilithium2PublicKey || SM2PublicKey
                   = 1312 bytes          || 65 bytes
```

SM2 使用 sm2p256v1 未压缩点 `0x04 || X(32) || Y(32)`；解析时检查总长度、
`0x04`、曲线名，并通过 EVP public check 验证点在曲线上。

签名直接放在 Certificate 的单个 `signatureValue` BIT STRING 中：

```text
CompositeSignature = Dilithium2Signature || DER(SM2Signature)
                   = 2420 bytes           || variable DER SEQUENCE(r, s)
```

SM2 DER 解码必须消耗全部输入、无 trailing bytes、`r/s` 为正非零整数，并且
重新编码后必须逐字节等于原 DER。

## 唯一 Composite Signature Core

核心位于：

```text
include/composite_key.h   src/composite_key.c
include/composite_sig.h   src/composite_sig.c
```

调用者只提交 raw message `M`。`composite_build_message()` 统一构造：

```text
PH(M)   = SM3(M)
Prefix  = ASCII("CompositeAlgorithmSignatures2025")
Label   = ASCII("COMPSIG-DILITHIUM2-SM2-SM3")
len(ctx)= 一个无符号字节
M'      = Prefix || Label || len(ctx) || ctx || SM3(M)
```

当前普通消息和 X.509 证书均使用空 `ctx`。接口保留 0..255 字节 `ctx`，供未来
协议规范定义 domain separation；本阶段没有虚构 TLS/GM/T context。

`M'` 同时交给 CRYSTALS-Dilithium2 与现有 SM2-with-SM3 primitive。Composite
层的 `SM3(M)` 和 SM2 算法内部的 `ZA`/`SM3(ZA || M')` 是两个不同层次，后者
没有被删除。SM2 ID 集中为 `1234567812345678`。

所有双组件签名只在 `composite_sign()` 内调用两个 primitive；所有双组件验证
只在 `composite_verify_detailed()` 内调用两个 primitive并作严格 AND 判断。
`hybrid_sign()`/`hybrid_verify()` 仅是旧消息 API 的兼容适配器，内部委托
Composite Core，不包含第二套密码算法流程。

```text
                            Composite Signature Core
                 composite_build_message / sign / verify
                                  |
             +--------------------+--------------------+
             |                    |                    |
       Message tests       X.509 Certificate      Future protocol
         raw M             DER(TBSCertificate)    protocol-signed data
```

证书签发使用 CA Hybrid Private Key；普通 Server 消息及未来 CertificateVerify
使用 Server Hybrid Private Key。两者使用相同 core，只是 key、raw `M` 和未来
可能的 `ctx` 不同。

## PKI 和扩展

```text
Root Hybrid CA
├── SPKI: Dilithium_CA_PK || SM2_CA_PK
├── BasicConstraints: critical, CA:TRUE
├── KeyUsage: critical, keyCertSign, cRLSign
└── signatureValue: Dilithium_CA_SIG || DER(SM2_CA_SIG)
          |
          | signs DER(Server TBSCertificate) with CA Hybrid SK
          v
Server Hybrid Certificate
├── SPKI: Dilithium_Server_PK || SM2_Server_PK
├── BasicConstraints: critical, CA:FALSE
├── KeyUsage: critical, digitalSignature
├── ExtendedKeyUsage: serverAuth
├── SubjectAltName: DNS:server.local
├── SubjectKeyIdentifier / AuthorityKeyIdentifier
├── 课题 Dilithium/PQC 标识扩展: 1.3.6.1.4.1.2.267.7
└── signatureValue: Dilithium_CA_SIG || DER(SM2_CA_SIG)
```

Root 被显式配置为 trust anchor；自签名验证只证明其 Composite 自签名在密码学
上有效，不是 Root 获得信任的来源。

## FIPS 203 / ML-KEM-768

ML-KEM primitive 位于：

```text
include/mlkem.h
src/mlkem.c
```

它是独立的 `mlkem` library target，不依赖也不被 `hybrid_pqc`、Composite
Signature 或 X.509 模块依赖：

```text
Authentication                          Key Establishment
SM2 + CRYSTALS-Dilithium2               FIPS 203 ML-KEM-768
        |                                       |
Composite Signature Certificate         standalone primitive only
                                                |
                                                v
                                  future SM2 + ML-KEM-768 Hybrid KEX
                                                |
                                                v
                              future PQKEX key exchange messages
```

实现使用仓库固定的 liboqs 0.16.0（commit
`c27c88b76473f67a8072ce5b66874d172287ff96`），algorithm identifier 为
`OQS_KEM_alg_ml_kem_768` / `ML-KEM-768`，其 ML-KEM wrapper 标记
`alg_version = "FIPS203"`，底层是 liboqs 收录的 `mlkem-native`。CMake 使用
`OQS_MINIMAL_BUILD=KEM_ml_kem_768`，旧 `Kyber768`、`kyber_768` 等算法即使在
liboqs 源码树中存在，也不会被编译或作为 fallback。

固定参数为：

```text
encapsulation key (ek): 1184 bytes
decapsulation key (dk): 2400 bytes
ciphertext:             1088 bytes
shared secret:            32 bytes
```

wrapper 在每次操作前检查 provider 可用性、正式算法名、`FIPS203` 版本标记和
全部四个 runtime length，并对 API 输入作 NULL、精确输入长度和输出容量检查。
FIPS 203 的 encapsulation-key modulus check 与 decapsulation-key embedded
public-key-hash check 由 `mlkem-native` provider 在 Encaps/Decaps 内执行；本项目
不重复编写不完整的多项式检查。长度正确但内容被修改的 ciphertext 使用 FIPS
203 implicit rejection：Decaps 仍可输出 32-byte secret，测试判断它与原合法
shared secret 不同，而不把“API 返回成功”误写成 ciphertext 已认证。

生产 API 只暴露随机化的 KeyGen/Encaps/Decaps。确定性 `d`、`z`、`m` 入口只在
`tests/test_mlkem_kat.c` 使用，未进入 `include/mlkem.h`。KAT 来源是 NIST
ACVP-Server tag `v1.1.0.42` 的 FIPS203 vectors：ML-KEM-768 KeyGen tgId 2 / tcId
26，以及 Encaps/Decaps tgId 2 / tcId 26；测试逐字节比较 ek、dk、ciphertext 和
shared secret。

这表示项目集成的是 FIPS 203 定义的 ML-KEM-768 算法，不表示 liboqs 或本项目
本身获得了 CMVP/FIPS 140 module validation。ML-KEM key 目前仅在内存中存在，
不持久化，也不进入当前 Composite Certificate SPKI。

## Experimental GM/T 0024 PQKEX Extension

仓库固定的 `third_party/GmSSL` 已有 GM/T 0024/TLCP ClientHello、通用 TLS
Extension 编解码和握手状态机。为保持第三方 submodule 固定且干净，实际 TLCP
接入只实现一次，不在主仓库另设重复的 PQKEX parser；改动不直接提交到 GmSSL
工作树，而是保存在：

```text
patches/gmssl/0001-add-experimental-tlcp-pqkex-capability.patch
```

该补丁基于 GmSSL commit `24ae482701a7b124826c382fffc55c19f76d475d`，完成：

- TLCP client 按配置将 `0xFF02` 写入真实 ClientHello extensions；
- TLCP server 严格解析 capability，拒绝 duplicate，并按 client preference 选择；
- 将结果保存在 `pqkex_offered`、`pqkex_negotiated` 和
  `pqkex_selected_kem`，供下一阶段 ServerKeyExchange 使用；
- 增加 GmSSL 内部固定 wire vector、完整负向解析和 duplicate 测试；
- 提供 `gmssl pqkex_demo` capability-only 演示命令。

补丁不修改 ServerHello，不携带 ML-KEM public key/ciphertext，不调用 GmSSL 的
Kyber 或本项目 ML-KEM primitive，也不派生 shared secret。PQKEX wire parser、
KEM 选择和 TLCP 接入均由该补丁提供，项目中不存在第二套 PQKEX 实现。

实验 ExtensionType：

```text
PQKEX_EXTENSION_TYPE = 0xFF02 (decimal 65282)
```

`0xFF02` 是项目私有实验标识，不是 GM/T 或 IANA 正式分配的 PQKEX extension
identifier。当前唯一协议 KEM ID 为：

```text
0xFF02 is a project-private experimental extension identifier.
It is NOT an officially assigned GM/T or IANA PQKEX extension identifier.
```

```text
PQKEX_KEM_MLKEM768 = 0x0001  // ML-KEM-768 / FIPS 203
```

传统组件 SM2 由未来 GM/T 0024 key establishment 负责，不编码为
`SM2_MLKEM768`。PQKEX extension 当前只表示客户端支持哪些 PQ KEM：

```text
extension_data = uint16 kem_list_length || uint16 kem_ids[]
```

单一 ML-KEM-768 的固定编码为：

```text
FF 02 | 00 04 | 00 02 | 00 01
 type | extlen | listlen| KEM ID
```

即 `FF02000400020001`。未知 KEM ID 可以作为 syntactically valid capability
被解析，但只有 server 本地支持的 ID 才可能被选择；选择策略集中在
`tls_pqkex_select_kem()`，按客户端偏好顺序选择第一个共同 KEM。两个 `0xFF02`
extension 会被 ClientHello extension 扫描层拒绝，不采用 first-wins 或
last-wins。

本阶段不会在 ClientHello 发送 ML-KEM encapsulation key，也不会在 ServerHello
发送 encapsulation key 或 ciphertext。GmSSL PQKEX 补丁不链接 `mlkem` target，
不会调用 KeyGen、Encaps 或 Decaps。`TLS_CONNECT.pqkex_negotiated` 仅表示双方
存在共同 capability，不表示 shared secret 已建立。

后续计划的数据位置是：

```text
ServerKeyExchange: ML-KEM-768 encapsulation key + selected_kem
ClientKeyExchange: ML-KEM-768 ciphertext
```

该分层方式参考已过期的 TLS 1.2 hybrid PQ KEM Internet-Draft
`draft-campagna-tls-bike-sike-hybrid`，本项目不声称符合该 draft，也不声称这是
GM/T 正式定义的 PQKEX。

验证 GmSSL 补丁时应使用临时 worktree，不污染固定 submodule。例如：

```sh
gmssl_worktree="$(mktemp -d)"
git -C third_party/GmSSL worktree add --detach "$gmssl_worktree" \
  24ae482701a7b124826c382fffc55c19f76d475d
git -C "$gmssl_worktree" apply \
  "$PWD/patches/gmssl/0001-add-experimental-tlcp-pqkex-capability.patch"
cmake -S "$gmssl_worktree" -B "$gmssl_worktree/build" \
  -DBUILD_SHARED_LIBS=OFF -DENABLE_QUIC=OFF -DENABLE_KYBER=OFF
cmake --build "$gmssl_worktree/build" --target pqkextest gmssl-bin -j
"$gmssl_worktree/build/bin/pqkextest"
"$gmssl_worktree/build/bin/gmssl" pqkex_demo
git -C third_party/GmSSL worktree remove "$gmssl_worktree"
```

## 构建、生成和验证

依赖初始化：

```sh
git submodule update --init --recursive
```

标准构建与测试：

```sh
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

独立运行 ML-KEM demo：

```sh
./build/mlkem_demo
```

它只输出 provider、参数长度和 PASS/FAIL，不打印 dk 或 shared secret。

口令只从环境变量读取，不放在命令行或日志中。首次运行生成并持久化四组互不
复用的组件密钥；后续运行加载 key store，并在签发前验证 loaded CA/Server
Hybrid key 与已有 Root/Server 证书 Composite SPKI 完全匹配：

```sh
HYBRID_KEY_PASSPHRASE='use-a-strong-local-secret' \
  ./build/generate_demo_chain \
  certs/root_hybrid.crt certs/root_hybrid.der \
  certs/server_hybrid.crt certs/server_hybrid.der
```

可选第 5 个参数指定其他 key root；默认是 `keys/`。文件布局：

```text
keys/ca/sm2_private.pem
keys/ca/dilithium2_private.enc
keys/server/sm2_private.pem
keys/server/dilithium2_private.enc
```

SM2 使用 AES-256-CBC PBES2 加密 PKCS#8。Dilithium2 使用项目自描述的
AES-256-GCM 认证加密容器，PBKDF2-HMAC-SHA256（200000 次）派生密钥，随机
16-byte salt 和 12-byte IV；容器保存 Dilithium2 public/secret key，加载后通过
Composite sign/verify 自检其配对关系。目录权限要求 `0700`，文件 `0600`；
错误口令、容器篡改、部分 key store 或证书 SPKI 失配均失败关闭。

`composite_build_message()` 的固定测试向量使用 `M="abc"`、
`ctx=01 02 03`，对完整 94-byte `M'` 逐字节比较。

详细链验证：

```sh
./build/verify_chain certs/root_hybrid.crt certs/server_hybrid.crt
./build/inspect_hybrid_cert certs/server_hybrid.crt
```

使用仓库固定 OpenSSL 3.2.0 做结构检查：

```sh
env LD_LIBRARY_PATH=third_party/openssl \
  third_party/openssl/apps/openssl asn1parse \
  -inform DER -in certs/server_hybrid.der -i
```

OpenSSL 3.2.0 不认识该实验 Composite OID，因此 `openssl verify` 不能作为
Composite 密码学验收依据；`verify_chain` 才执行本项目的双组件严格验证。

Sanitizer 回归：

```sh
cmake -S . -B build-sanitize -DHYBRID_ENABLE_SANITIZERS=ON
cmake --build build-sanitize -j
ASAN_OPTIONS=detect_leaks=0 \
  ctest --test-dir build-sanitize --output-on-failure
```

## 参考

- [draft-ietf-lamps-pq-composite-sigs-19](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-19)
- [RFC 5612 documentation enterprise number](https://www.rfc-editor.org/rfc/rfc5612.html)
- [NIST FIPS 203 final](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST ACVP-Server v1.1.0.42](https://github.com/usnistgov/ACVP-Server/tree/v1.1.0.42/gen-val/json-files)
- [Expired draft-campagna-tls-bike-sike-hybrid-07](https://datatracker.ietf.org/doc/html/draft-campagna-tls-bike-sike-hybrid-07)
- [IANA TLS ExtensionType registry](https://www.iana.org/assignments/tls-extensiontype-values)
