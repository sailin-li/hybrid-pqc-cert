# TLCP PQKEX capability

## 背景与定位

仓库固定的 GmSSL 已提供 GM/T 0024/TLCP ClientHello、TLS extension 编解码和
握手状态机。项目通过以下补丁加入 PQ KEM capability，而不在主项目复制协议栈：

```text
patches/gmssl/0001-add-experimental-tlcp-pqkex-capability.patch
```

补丁基于 GmSSL commit `24ae482701a7b124826c382fffc55c19f76d475d`。

## Private identifiers

```text
PQKEX_EXTENSION_TYPE = 0xFF02  // project-private experimental
PQKEX_KEM_MLKEM768   = 0x0001  // ML-KEM-768 / FIPS 203
```

`0xFF02` 不是 GM/T 或 IANA 正式分配的 ExtensionType，`0x0001` 也是本项目协议
实验中的 KEM ID。传统 SM2 组件由未来 GM/T 0024 key establishment 负责，不编码
为名为 `SM2_MLKEM768` 的单一 ID。

## Wire format

完整 Extension 使用 big-endian：

```text
uint16 extension_type
uint16 extension_length
uint16 kem_list_length
uint16 kem_ids[kem_list_length / 2]
```

单一 ML-KEM-768 capability：

```text
FF 02 | 00 04 | 00 02 | 00 01
 type | extlen | listlen| KEM ID
```

固定 vector 为 `FF02000400020001`。

parser 拒绝空列表、奇数 byte length、声明长度不一致、截断、trailing garbage、
超过 8 个 KEM，以及同一 ClientHello 中重复 `0xFF02`。未知 KEM ID 在语法上可以
有效，但不会自动映射成已知 KEM。

## ClientHello 与选择策略

启用时，TLCP client 按配置顺序在真实 ClientHello extensions 中发布 KEM IDs。
server 严格解析，并由 `tls_pqkex_select_kem()` 按 client preference order 选择第一
个双方共同支持的 KEM。

结果保存在 GmSSL `TLS_CONNECT`：

- `pqkex_offered`：ClientHello 出现并通过语法解析；
- `pqkex_selected_kem`：选择的 KEM ID，当前可为 ML-KEM-768；
- `pqkex_negotiated`：双方找到共同 capability。

`pqkex_negotiated` 不表示已生成 KEM keypair、传输 ciphertext 或建立 shared
secret。

## 补丁内容与 demo

`0001` 修改 GmSSL 的 TLS header、TLCP ClientHello send/server parse path、通用
extension/trace、CMake tests 和 CLI。它增加：

- fixed wire vector 和严格 parser tests；
- unknown KEM、selection、malformed encoding 与 duplicate tests；
- `gmssl pqkex_demo` capability-only 演示。

补丁不 include、link 或 call 本项目 `mlkem`、Composite 或 X.509，也不调用 GmSSL
Kyber。主仓库没有第二套 PQKEX parser。

## 当前边界

已实现：

```text
ClientHello capability advertisement
                  |
                  v
server-side KEM selection
```

未实现：

```text
future ServerKeyExchange: ML-KEM encapsulation key + selected_kem
future ClientKeyExchange: ML-KEM ciphertext
future: SM2 secret + ML-KEM secret -> specified Hybrid KDF
```

当前 ClientHello 不携带 ML-KEM encapsulation key；ServerHello、ServerKeyExchange
和 ClientKeyExchange 均未被 `0001` 扩展成完整 KEX。TLCP master secret、PRF/KDF、
Finished 与 record layer 保持不变。

设计分层只参考已过期的
[draft-campagna-tls-bike-sike-hybrid-07](https://datatracker.ietf.org/doc/html/draft-campagna-tls-bike-sike-hybrid-07)，
不声称符合该 draft，也不声称为 GM/T 正式 PQKEX。补丁应用和测试方法见
[测试文档](testing.md)。

如需在 Ubuntu 虚拟机中生成真实 TCP ClientHello 抓包，并在 Windows Wireshark
中查看 `FF02000400020001`，见 [PQKEX 抓包指南](pqkex-capture.md)。
