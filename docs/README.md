# 文档导航

本目录保存 `hybrid-pqc-cert` 的设计、编码、协议、测试和安全细节。根目录
README 只回答项目是什么、当前做到哪里以及如何快速运行；实现规则以这里的专题
文档和当前代码为准。

| 文档 | 内容 |
|---|---|
| [architecture.md](architecture.md) | 总体分层、模块依赖和实现边界 |
| [composite-signature.md](composite-signature.md) | Composite 消息、公钥/签名编码与 strict AND |
| [composite-x509.md](composite-x509.md) | AlgorithmIdentifier、证书角色、扩展与链验证 |
| [mlkem.md](mlkem.md) | FIPS 203 ML-KEM-768 wrapper、KAT 与协议隔离 |
| [tlcp-pqkex.md](tlcp-pqkex.md) | TLCP ClientHello capability、wire format 与 KEM selection |
| [pqkex-capture.md](pqkex-capture.md) | Ubuntu TCP loopback 抓包与 Windows Wireshark 检查 |
| [tlcp-hybrid-certificate.md](tlcp-hybrid-certificate.md) | TLCP 双证书模型、adapter 与 downgrade policy |
| [tls13-pq-psk.md](tls13-pq-psk.md) | TLS 1.3 私有 `0xFF03`、external PSK 和 PSK-DHE |
| [benchmark.md](benchmark.md) | `composite_verify()` benchmark 方法与统计口径 |
| [testing.md](testing.md) | CTest、负向测试、sanitizer 与 GmSSL patch workflow |
| [security.md](security.md) | trust model、密钥存储、fail-closed 策略与未完成分析 |

## 阅读路径

- 了解系统：先读 [总体架构](architecture.md)，再读对应协议专题。
- 审查证书设计：读 [Composite Signature](composite-signature.md)、
  [Composite X.509](composite-x509.md) 和
  [TLCP Hybrid Certificate](tlcp-hybrid-certificate.md)。
- 复现实验：读 [测试](testing.md) 与 [Benchmark](benchmark.md)。
- 评估边界：读 [安全说明](security.md)。

所有 OID、ExtensionType 与协议扩展均保留实验性质；文档不把计划项写成已实现项。
