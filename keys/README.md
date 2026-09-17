# Private keys

`generate_demo_chain` 在本目录持久化 CA/Server 各自独立的 Hybrid key：

```text
ca/sm2_private.pem
ca/dilithium2_private.enc
server/sm2_private.pem
server/dilithium2_private.enc
```

SM2 文件是加密 PKCS#8；Dilithium2 文件是 PBKDF2-HMAC-SHA256 +
AES-256-GCM 认证加密容器。口令只从 `HYBRID_KEY_PASSPHRASE` 环境变量读取。
加载 Server key 后必须与 `server_hybrid.crt` Composite SPKI 完全匹配。

除本说明文件外，目录内容均由顶层 `.gitignore` 排除，不得提交到 Git，也不得
让 CA 与 Server 复用组件私钥。

建议目录权限设为 `0700`，私钥文件权限设为 `0600`；SM2 使用加密 PKCS#8，
PQC 私钥也应使用经过认证的加密封装，不要长期保存裸私钥字节。
