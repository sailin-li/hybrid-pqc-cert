# 安全模型与实现边界

## 实验性质

本项目用于研究、教学和方案验证，不用于 production deployment，也不是经过认证的
密码模块。实验 Composite OID、TLCP `0xFF02` 与 TLS `0xFF03` 均为 private-use
设计，没有 IETF、IANA 或 GM/T 正式分配。

项目使用 FIPS 203 ML-KEM-768 算法和 NIST ACVP vectors，不表示 liboqs 或本项目
获得 FIPS 140/CMVP module validation。

## Trust model

Root Hybrid CA 由调用者 out-of-band 配置为 trust anchor。Root self-signature
验证只证明它的 Composite self-signature 在密码学上有效，不是信任来源。

Server 与 TLCP encryption certificate 必须使用 Root SPKI 中的 CA Dilithium2 / SM2
public keys 验证，绝不能使用 subject 自己的 key 验证 issuer signature。

## Private key roles

CA Hybrid、Server Hybrid 与可选 TLCP encryption key 彼此独立：

```text
CA Hybrid:          CA SM2 + CA Dilithium2
Server Hybrid:      Server SM2 + Server Dilithium2
TLCP encryption:    separate Server SM2
ML-KEM:             ephemeral/in-memory only in current primitive demo
```

CA key 只签发证书；Server Hybrid key 用于 message signing 和未来协议签名；TLCP
encryption private key 与 cert[1] ordinary SM2 SPKI 匹配。ML-KEM key 不持久化，
也不进入证书。

## Key store

口令只从 `HYBRID_KEY_PASSPHRASE` 读取，最少 12 bytes；不得打印、提交或写日志。

| Material | Storage protection |
|---|---|
| SM2 private key | encrypted PKCS#8 / PBES2, AES-256-CBC via OpenSSL |
| Dilithium2 private key | project container, AES-256-GCM |
| Dilithium2 KDF | PBKDF2-HMAC-SHA256, 200000 iterations |

Dilithium container 使用随机 16-byte salt、12-byte IV 和 16-byte GCM tag；header
作为 AAD，并同时保存对应 public key。解密后执行 Composite sign/verify 自检，
确认 component keys 配对。

key root 与角色目录要求 owner-only（创建为 `0700`，拒绝 group/other 权限），文件
创建为 `0600`，并拒绝 symlink、非 regular file 和异常 container size。写入使用
exclusive create，失败时删除不完整文件。

首次运行生成 CA/Server Hybrid keypairs；后续运行加载并逐字节比较：

- CA Hybrid public key 与现有 Root Composite SPKI；
- Server Hybrid public key 与现有 Server Composite SPKI；
- 可选 encryption SM2 public key 与 cert[1] ordinary SM2 SPKI。

错误口令、GCM authentication failure、部分 key store、权限不安全、证书无效或
SPKI mismatch 都失败关闭，不生成替代 key 继续运行。敏感中间值和 private key
buffer 在 cleanup 时使用 OpenSSL/liboqs secure-clear API。

命令行 `-psk_key` 只用于 patched GmSSL 测试/演示，因为 process list 与 shell
history 可能泄露参数。项目尚未实现 production external PSK provisioning。

## Fail-closed verification

Composite result 始终为：

```text
FormatValid && DilithiumValid && SM2Valid
```

不存在 OR、silent fallback 或只接受 classical component 的 compatibility mode。
SM2 DER 要求 canonical、完整消费且 `r/s` 正非零；Composite public key 要求精确
长度、未压缩 SM2 point 与曲线检查；AlgorithmIdentifier 和 marker/profile 任一不符
都使证书失败。

TLCP compatible mode 只允许 `NOT_APPLICABLE` 的传统证书进入原 GmSSL verifier。
已识别 Hybrid flow 的 `INVALID` 永不 fallback。strict expected-hybrid 对普通 SM2
signing certificate 视为 downgrade，并发送 fatal `bad_certificate`。

## Protocol security boundaries

- PQKEX `pqkex_negotiated` 只表示共同 KEM capability，不表示 shared secret。
- TLCP Certificate-chain authentication 是 Hybrid，但 ServerKeyExchange
  proof-of-possession 当前仍是 SM2。
- ML-KEM 尚未进入 TLCP secret derivation、Hybrid KDF 或 handshake messages。
- TLS `0xFF03` 使用 separately provisioned external PSK，不调用 ML-KEM；external
  PSK 不是 PQC algorithm。
- TLS `0xFF03` 强制 PSK-DHE 并保留 Certificate/CertificateVerify，不是 PSK-only
  authentication；early_data 与 resumption PSK 被禁止。

## Side-channel considerations

当前实现复用 OpenSSL、官方 Dilithium reference code 与 liboqs/mlkem-native 的既有
实现，但本项目没有完成独立 constant-time audit、power/EM/fault analysis、cache
hardening、masked implementation 或硬件密钥隔离。因此不得称为 side-channel
hardened implementation。

经典与量子攻击模型下的侧信道防护仍是计划项。未来分析至少应覆盖 secret-dependent
branches/memory access、compiler effects、zeroization、fault handling、key lifetime、
PSK provisioning 和部署平台。

## QROM status

项目当前没有完成 SM2 + CRYSTALS-Dilithium2 Composite construction 的正式 QROM
security proof，也没有把 draft 对其他组合的论证直接当成本项目证明。

QROM security argument 标记为 pending。未来工作需要明确组合安全目标、组件假设、
pre-hash/domain-separation 模型、multi-user setting、组合器定理适用性与降级条件，
并接受独立密码学审查。

## Responsible use

任何实际部署前都需要标准化 identifier、正式算法/profile 评审、互操作测试、完整
KEX 与 key-management 设计、side-channel review、fuzzing、长期兼容策略和第三方
安全审计。当前 artifact 只能证明仓库所述实验路径在固定依赖与测试条件下工作。
