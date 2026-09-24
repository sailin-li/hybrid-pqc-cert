# TLS 1.3 `post_quantum_pre_shared_key`

## 实验定位

`patches/gmssl/0004-add-tls13-post-quantum-pre-shared-key.patch` 为固定 GmSSL
增加私有 TLS 1.3 ExtensionType：

```text
post_quantum_pre_shared_key = 0xFF03
wire encoding               = FF030000
```

`0xFF03` 是 extension_data 为空的 flag。它的行为 modeled after RFC 9973
`tls_cert_with_extern_psk`，但它不是 RFC 9973 定义或 IANA 分配的 identifier。

## 与标准 `pre_shared_key` 的关系

`0xFF03` 不承载 PSK。TLS 1.3 标准 `pre_shared_key` 仍负责：

- ClientHello external PSK identity；
- transcript-bound binder；
- ServerHello selected_identity。

raw PSK 不进入握手。ClientHello 中 `pre_shared_key` 必须是最后一个 extension；
`0xFF03` 只允许出现在 ClientHello 与 ServerHello，不能出现在
EncryptedExtensions 或其他消息，且双方都拒绝 duplicate 或非空 extension_data。

## 必需 companions

启用 `0xFF03` 的 ClientHello 必须同时包含：

- `supported_groups`；
- `key_share`；
- `psk_key_exchange_modes`，且包含 `psk_dhe_ke`；
- 最后一个 `pre_shared_key`，其中是 external PSK identity 与 binder。

协议拒绝 PSK-only、resumption PSK 和 `early_data`。服务端不得 unsolicited 返回
`0xFF03`。

## Key schedule 与认证

补丁复用 GmSSL 既有 binder 与 TLS 1.3 key schedule，不复制 KDF：

```text
pre-provisioned external PSK -> Early Secret
                                    |
                                    + derived secret
                                    + ECDHE shared secret
                                    v
                              Handshake Secret
                                    |
                                    v
                     Master/Application Traffic Secrets

Server authentication: Certificate + CertificateVerify
```

成功协商时，`post_quantum_psk_negotiated` 与普通 PSK selection state 分开记录。
即使 external PSK 被选中，Server Certificate 与 CertificateVerify 仍必须发送，
客户端也必须验证。因此该模式不是 PSK-only authentication。

当前固定测试使用 `TLS_SM4_GCM_SM3`，对应 PSK binder/HKDF hash 为 SM3（32
bytes）。这是测试 cipher suite 的约束，不应推导为所有 external PSK 都固定 32
bytes。

## Compatible 与 strict policy

- 默认 compatible policy：identity 无匹配时回退普通 certificate-authenticated
  TLS 1.3。
- `-require_post_quantum_pre_shared_key`：要求成功选择合格 external PSK，否则
  握手失败。

回退不会把已发生的 binder 或协议错误降级为成功。strict flag 会同时启用
`post_quantum_pre_shared_key`。

## HelloRetryRequest

HelloRetryRequest 后，ClientHello2 必须重复空 `0xFF03`，保留必需 companion，
并继续保持 `pre_shared_key` last。binder 通过既有 HRR transcript 逻辑重新计算，
而不是用新实现绕过 transcript。

## CLI demo

patched GmSSL 沿用原有 PSK 参数：

```sh
gmssl tls13_server ... \
  -psk_dhe_ke \
  -psk_identity pq-demo \
  -psk_cipher_suite TLS_SM4_GCM_SM3 \
  -psk_key <hex> \
  -post_quantum_pre_shared_key

gmssl tls13_client ... \
  -psk_dhe_ke \
  -psk_identity pq-demo \
  -psk_cipher_suite TLS_SM4_GCM_SM3 \
  -psk_key <same-hex> \
  -post_quantum_pre_shared_key
```

`-psk_key` 只用于测试和演示；命令行参数可能出现在 process list 或 shell history。
正式 provisioning 应使用受保护配置、secure file、keystore 或硬件设施。本阶段不
定义 PSK 的生成、分发与长期保存。

## Security assumptions 与边界

external PSK 不是一种 PQC algorithm。“post-quantum”属性依赖 PSK 本身具有足够
entropy，并通过抗量子安全流程生成、配置和保护。`0xFF03`：

- 不调用 ML-KEM；
- 不负责 external PSK provisioning；
- 不修改 TLCP `0xFF02`、TLCP master secret 或 Composite X.509；
- 不表示 PSK 获得算法标准化或 FIPS validation。

测试覆盖 binder tamper、companion/位置约束、错误 PSK、identity policy、HRR、
Certificate/CertificateVerify 缺失或篡改，以及 PSK/ECDHE 对 key schedule 的独立
影响。完整清单见 [测试文档](testing.md)。
