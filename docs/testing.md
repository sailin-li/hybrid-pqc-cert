# 测试与复现

## 主项目 CTest

```sh
git submodule update --init --recursive
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

当前 CMake 注册 13 项：

| Test | Scope |
|---|---|
| `dilithium` | CRYSTALS-Dilithium2 primitive |
| `sm2` | OpenSSL EVP SM2/SM3 primitive |
| `hybrid_sign` | Composite core 与 strict AND |
| `composite_key` | Composite public-key encoding/parsing |
| `composite_message` | Prefix、label、ctx 与 pre-hash vector |
| `hybrid_key_store` | 加密持久化、权限、错误口令与 tamper |
| `hybrid_x509` | X.509 创建、结构与读取 |
| `hybrid_chain` | Root -> Server 与 12 类 chain negative cases |
| `hybrid_encryption_cert` | ordinary SM2 SPKI + Composite CA signature |
| `tlcp_hybrid_cert_adapter` | raw-DER 三态 adapter |
| `mlkem` | KeyGen/Encaps/Decaps、input validation、implicit rejection |
| `mlkem_kat` | NIST ACVP ML-KEM-768 byte-for-byte KAT |
| `benchmark_smoke` | 四条 verify 路径的短 smoke run |

## Certificate negative tests

chain tests 分别覆盖：Dilithium signature tamper、SM2 DER signature tamper、错误
CA SM2 key、错误 CA Dilithium key、未重签的 TBS 改动、缺失或截断组件、inner /
outer AlgorithmIdentifier mismatch、PQC marker 缺失，以及只通过一个组件的情况。

encryption-certificate tests 另外覆盖 ordinary SM2 SPKI、Composite issuer
signature、两张 TLCP certificate 的联合结果、错误 CA component、普通 SM2 CA
signature downgrade 与 marker/profile 失败。

## ML-KEM tests

`mlkem` 检查 provider identity、固定长度、随机化 KeyGen/Encaps、正确 Decaps、
NULL、长度和 capacity 错误，以及 provider 对 malformed `ek` / `dk` 的检查。
长度正确的错误 key 或 ciphertext 按 FIPS 203 implicit rejection 处理。

`mlkem_kat` 使用 ACVP-Server `v1.1.0.42` 的 ML-KEM-768 KeyGen 和
Encaps/Decaps tgId 2 / tcId 26。确定性 seeds 只存在于 test，不进入 production
header。

同时检查 minimal liboqs 配置：

```sh
rg 'OQS_ENABLE_KEM_(ml_kem_768|kyber_768)' \
  build/liboqs/include/oqs/oqsconfig.h
```

期望启用 ML-KEM-768，旧 Kyber-768 保持未定义。

## Sanitizer

```sh
cmake -S . -B build-sanitize -DHYBRID_ENABLE_SANITIZERS=ON
cmake --build build-sanitize -j
ASAN_OPTIONS=detect_leaks=0 \
  ctest --test-dir build-sanitize --output-on-failure
```

主项目使用 ASan + UBSan。现有 13 项测试可在 `detect_leaks=0` 基线运行；主项目
也可单独用 `detect_leaks=1` 检查。

patched GmSSL sanitizer 运行存在已知 upstream 噪声，不能误归因于本项目补丁：

- 未修改的 SM4 `GETU32/S32` 有 signed-shift UBSan 报告，验证补丁时使用
  `-fno-sanitize=shift`；
- TLS 1.3 CLI fixture 经固定上游 `reqsign` 的 `x509_cert_new_from_file()` 有
  565-byte leak，该 CLI 回归使用 `detect_leaks=0`；
- 固定上游 `x509_crltest` 有与本项目无关的 zero-length/null-pointer UBSan 报告。

`tls13pqpsktest` 本身可保持 LeakSanitizer 开启。项目补丁不夹带修复这些无关
upstream 路径。

## GmSSL patch workflow

不得直接修改或提交 `third_party/GmSSL` 工作树。使用临时 worktree，在固定 commit
上按文件名顺序应用 `0001` 到 `0004`：

```sh
gmssl_temp_root="$(mktemp -d)"
gmssl_worktree="$gmssl_temp_root/GmSSL"
git -C third_party/GmSSL worktree add --detach "$gmssl_worktree" \
  24ae482701a7b124826c382fffc55c19f76d475d

scripts/apply_gmssl_patches.sh "$gmssl_worktree"
git -C "$gmssl_worktree" diff --check

cmake -S "$gmssl_worktree" -B "$gmssl_worktree/build" \
  -DBUILD_SHARED_LIBS=OFF \
  -DENABLE_QUIC=OFF \
  -DENABLE_KYBER=OFF

cmake --build "$gmssl_worktree/build" \
  --target pqkextest tls13pqpsktest gmssl-bin -j

"$gmssl_worktree/build/bin/pqkextest"
"$gmssl_worktree/build/bin/gmssl" pqkex_demo
"$gmssl_worktree/build/bin/tls13pqpsktest"
scripts/test_gmssl_hybrid_integration.sh "$gmssl_worktree/build" "$PWD/build"
ctest --test-dir "$gmssl_worktree/build" \
  -R '^tool_tls13_pqpsk_' --output-on-failure

git -C third_party/GmSSL worktree remove --force "$gmssl_worktree"
rmdir "$gmssl_temp_root"
```

所有测试完成后，用 `--force` 移除这个明确创建的临时、已打补丁 worktree；不对
固定 submodule 工作树执行清理或重置。

`pqkextest` 覆盖 fixed vector、严格 parser、unknown KEM、selection 与 duplicate
extension。主项目 integration binary 将 patched GmSSL、`hybrid_pqc` 和 fixed
OpenSSL 链接起来，验证 Certificate receive / ServerKeyExchange 状态推进。

## TLS 1.3 PQ-PSK tests

`tls13pqpsktest` 与 CLI/CTest 回归覆盖：

- 空 `0xFF03` wire encoding、duplicate、non-empty 与非法位置；
- supported_groups、key_share、`psk_dhe_ke` 和 pre_shared_key-last；
- binder tamper、错误 PSK、external/resumption PSK type；
- early_data 与 PSK-only rejection；
- unsolicited ServerHello extension；
- compatible identity mismatch 与 strict policy；
- HRR 后 ClientHello2 和 binder transcript；
- Certificate / CertificateVerify 保留、缺失与 tamper；
- PSK 和 ECDHE 对 key schedule 的独立影响；
- application-data round trip。

未启用 `0xFF03` 时，普通 certificate、PSK-DHE、PSK-only、resumption 和 early-data
路径应保持上游语义。

## Documentation-only review

修改文档时至少执行：

```sh
git diff --check -- README.md docs/
git status --short
```

并检查所有相对 Markdown links 的目标存在。文档修改本身不替代涉及密码学、ASN.1、
patch 或 CMake 变更时所要求的完整 build/test。
