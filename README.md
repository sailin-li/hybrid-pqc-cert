# hybrid-pqc-cert

本项目是“国密证书支持抗量子算法方案设计”的实验实现。它保持标准 X.509
证书外层不变，以 SM2/SM3 签署最终 `TBSCertificate`，并把
CRYSTALS-Dilithium2 公钥和签名放入私有 X.509v3 扩展。

## 依赖与构建

默认依赖：

- OpenSSL 3.2.0：`third_party/openssl` 的现有构建产物；
- CRYSTALS-Dilithium2：`third_party/dilithium/ref`；
- GmSSL 和 liboqs 仅接受环境审计，本阶段新实现不链接它们。

克隆时需要同时初始化第三方 submodule：

```sh
git clone --recurse-submodules <repository-url>
```

如果已经完成普通克隆，则执行：

```sh
git submodule update --init --recursive
```

```sh
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

可用 `OPENSSL_ROOT_DIR`、`CMAKE_PREFIX_PATH` 和 `DILITHIUM_SOURCE_DIR`
指定其他位置，不包含 `/home/...` 绝对路径。例如：

```sh
cmake -S . -B build \
  -DOPENSSL_ROOT_DIR=/path/to/openssl-3.2.0 \
  -DDILITHIUM_SOURCE_DIR=/path/to/dilithium
```

可选检查：

```sh
cmake -S . -B build-sanitize -DHYBRID_ENABLE_SANITIZERS=ON
cmake --build build-sanitize -j
ctest --test-dir build-sanitize --output-on-failure
```

## 混合消息签名

两种算法必须签署完全相同的消息：

```text
HybridValid = SM2Valid && DilithiumValid
```

混合签名使用 DER，而不是裸拼接：

```asn1
HybridSignature ::= SEQUENCE {
    version              INTEGER,       -- 1
    sm2Signature         OCTET STRING,
    dilithiumSignature   OCTET STRING
}
```

解码器要求消耗全部输入，因此拒绝截断、错误长度、错误 tag 和尾随数据。

## X.509v3 PQC 扩展

扩展 OID 是课题指定的：

```text
1.3.6.1.4.1.2.267.7
```

扩展值为：

```asn1
PQCInfo ::= SEQUENCE {
    version       INTEGER,              -- 1
    algorithm     OBJECT IDENTIFIER,
    publicKey     OCTET STRING,
    signature     OCTET STRING OPTIONAL
}
```

当前 `algorithm` 使用 OID：

```text
1.3.6.1.4.1.2.267.7.4.4 = CRYSTALS-Dilithium2
```

该 OID 来自 NIST 的 PQC 迁移测试文档

### 避免 PQC 签名循环依赖

签发过程严格使用两阶段 TBS：

1. 构造包含 PQC 算法及 Dilithium 公钥、但 `signature` 缺省的 PQCInfo。
2. 先执行一次 SM2 预签，使 `TBSCertificate.signature` 固定为
   SM2-with-SM3；该临时外层签名不会进入最终证书。
3. 通过 `i2d_re_X509_tbs` 得到
   `TBSCertificate_without_PQC_signature` 的规范 DER。
4. Dilithium2 对步骤 3 的全部 DER 字节签名。
5. 将 Dilithium 签名加入同一扩展位置。
6. SM2/SM3 对包含完整 PQC 扩展的最终 `TBSCertificate` 签名。

验证端复制证书，把 PQCInfo 的可选 `signature` 字段移除，在同一扩展位置
重建并 DER 编码基础 TBS，然后执行 Dilithium 验签。扩展次序、算法、公钥、
主题、签发者、有效期和其他 TBS 字段都在 Dilithium 覆盖范围内；只有 PQC
签名字段自身被排除。

SM2 证书签名使用 SM3 和 SM2 ID `1234567812345678`。SM2 ID 不属于证书
DER，验证模块在调用 `X509_STORE`/`X509_verify_cert` 前按该项目策略设置 ID。

## 验证模式

- `HYBRID_VERIFY_STRICT`（默认辅助函数）：`SM2 && Dilithium`；缺失、畸形或
  未知 PQC 算法一律失败关闭。
- `HYBRID_VERIFY_CLASSICAL_COMPAT`：只要求标准 SM2 证书验证通过。
- 不提供 `SM2 || Dilithium` 模式。

## 工具

```sh
./build/hybrid_cert_gen certs/hybrid_cert.pem certs/hybrid_cert.der
./build/hybrid_cert_dump certs/hybrid_cert.pem
```

项目实现位于 `include/`、`src/`、`tests/` 和 `tools/`；早期 `test/` 单文件
原型已在模块化实现和测试完成后移除。
