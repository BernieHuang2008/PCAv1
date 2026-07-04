# PCA v1.2 参考手册与示例程序

本目录是 PCA v1.2 草案的参考实现与操作手册。它展示如何派生密钥、如何将协议逻辑与 UI/CLI 分离，并指导操作者完成无法安全自动化的手动步骤，例如离线保存 Master Secret、发布 DNS 记录、广播紧急废止声明。

这些示例刻意保持保守：

- `pca_core/` 只包含协议逻辑。
- `pca_cli.py` 只包含 CLI 参数解析、文件 IO、展示和操作提示。
- `ui/` 是本地开发 UI，驱动同一组 CLI 命令。
- `tests/` 捕获未来示例应保持的协议不变量。

## 状态与范围

这份代码面向参考用途。它展示 PCA 兼容逻辑，但不是完整生产级钱包、证书机构、邮件客户端、DNS 发布器、HSM 集成或备份系统。

当前实现遵循这些核心规则：

- Master Secret 是 512-bit 随机数据。
- Namespace 用作 HKDF salt。
- HKDF 使用 HKDF-SHA-512。
- Canonical Info Path 是 ASCII 且保持稳定。
- Identity、Generation、Vault 职责分离。
- Identity 使用 Ed25519。
- Vault 通过 PyNaCl/libsodium 使用 XChaCha20-Poly1305，不手写密码算法轮函数。
- 签名 JSON 在签名前通过 `rfc8785` 执行 RFC 8785 JCS 规范化。
- Revocation 验证先检查 Namespace，再检查签名。
- CRL 与协议迁移示例使用 JCS + Ed25519 基础设施签名，并将 `signer_path` 固定为 `Identity/V1/PCA`。

`pca_core/constants.py` 中仍有一个参考实现选择：PCAv1.2 说明 `TrustRootKey` 由 Master Secret 通过 HKDF 派生，但草案尚未为这条边指定字面 info path。本实现固定为：

```text
PCA/V1/TrustRoot
```

建议对 PCAv1.2 协议作如下规范性补充，但本示例不会直接修改协议文件：

```text
TrustRootKey = HKDF-SHA-512(
  IKM  = Master Secret,
  salt = Namespace ID,
  info = "PCA/V1/TrustRoot",
  L    = 64
)
```

同时声明 `PCA/V1/TrustRoot` 是保留 Canonical Info Path，不得用于 Identity、Generation、Vault、CRL、迁移或应用自定义节点，并且在 `PCA-v1/<NamespaceID>` 格式族生命周期内保持稳定。

## 环境要求

安装声明的标准密码库与规范化库依赖：

```powershell
python3 -m pip install -r examples\pca_reference\requirements.txt
```

运行测试：

```powershell
Push-Location examples\pca_reference
python3 -B -m unittest discover tests
Pop-Location
```

以下命令默认从仓库根目录运行：

```powershell
cd C:\Bernie\DevG\git\BernieHuang2008\PCAv1
```

## 初始化

```powershell
python3 examples\pca_reference\pca_cli.py init
```

输出包含：

- `master_secret_hex`
- `namespace`
- `emergency_revocation_private_seed_hex`
- `emergency_revocation_public_key_b64`

Master Secret 必须离线保存；紧急废止私钥必须与 Master Secret 物理隔离保存；紧急废止公钥应配置到验证端或可信分发包中。

## 身份与派生

派生 PCA 基础设施身份：

```powershell
python3 examples\pca_reference\pca_cli.py identity --master-hex <MASTER_HEX> --namespace <NAMESPACE> --path Identity/V1/PCA
```

派生个人身份：

```powershell
python3 examples\pca_reference\pca_cli.py identity --master-hex <MASTER_HEX> --namespace <NAMESPACE> --path Identity/V1/Personal/Identity2026
```

从已派生父节点继续派生：

```powershell
python3 examples\pca_reference\pca_cli.py derive-node --parent-key-hex <PARENT_KEY_HEX> --parent-path Encrypt/V1/Vault/Finance --namespace <NAMESPACE> --path Encrypt/V1/Vault/Finance/2026/Q3 --length 64
```

目标 path 必须等于或位于提供的父 path 下方。

## DNS 与托管

DNS 绑定只是外部辅助发现，不能替代数学签名验证或带外信任建立：

```powershell
python3 examples\pca_reference\pca_cli.py dns-binding --domain example.com --public-key-b64 <PUBLIC_KEY_B64>
```

返回值应发布为：

```text
_pca.example.com. 3600 IN TXT "pca-binding=<SHA256_PUBLIC_KEY_HEX>"
```

DNS 不得用作 CRL 签名者授权、Vault 授权、软件更新授权或协议迁移授权。

如需托管废止材料，准备：

```text
https://<your-domain.com>/.well-known/pca/revocation.crl
```

该 URL 仅用于发现和传输，不代表授权。

## Generation

派生密码管理器种子：

```powershell
python3 examples\pca_reference\pca_cli.py generation --master-hex <MASTER_HEX> --namespace <NAMESPACE> --path Encrypt/V1/Generation/PasswordManager --length 32
```

派生 BIP32 master seed：

```powershell
python3 examples\pca_reference\pca_cli.py bip32-seed --master-hex <MASTER_HEX> --namespace <NAMESPACE> --network Mainnet
```

Generation keys 不建立公开信任。

## Vault

加密文件：

```powershell
python3 examples\pca_reference\pca_cli.py vault-encrypt --master-hex <MASTER_HEX> --namespace <NAMESPACE> --permission-path Finance/2026/Q3 --input secret.txt --output secret.pca --metadata secret.pca.json
```

解密文件：

```powershell
python3 examples\pca_reference\pca_cli.py vault-decrypt --master-hex <MASTER_HEX> --namespace <NAMESPACE> --permission-path Finance/2026/Q3 --file-id <FILE_ID> --input secret.pca --output secret.txt
```

Vault 使用 256-bit File ID、24 字节 nonce、per-file key 和完整 Canonical Info Path AAD。请同时备份密文与 metadata；Vault 密文丢失后外部秘密无法由 Master Secret 重新生成。

## 紧急废止

签署紧急废止声明：

```powershell
python3 examples\pca_reference\pca_cli.py sign-revocation --private-seed-hex <EMERGENCY_PRIVATE_SEED_HEX> --namespace <NAMESPACE> --revoked-at 2026-07-04T00:00:00Z --reason "Master Secret Compromised"
```

验证紧急废止声明：

```powershell
python3 examples\pca_reference\pca_cli.py verify-revocation --public-key-b64 <EMERGENCY_PUBLIC_KEY_B64> --namespace <NAMESPACE> --statement revocation.json
```

验证顺序：

1. 先将声明中的 `namespace` 与本地信任的 Namespace 比对。
2. 如果 Namespace 不同，立即忽略该声明。
3. 对移除 `signature` 字段后的 JCS JSON 验证 Ed25519 签名。
4. 如果有效，拒绝该 Namespace 下的后续操作。

`successor_namespace_hint` 只能作为提示，不能作为新 Namespace 的信任锚。

## CRL

准备一个文本文件，每行一个 64 字符大写 HEX 的 SHA-256 revoked identifier。

签署 CRL：

```powershell
python3 examples\pca_reference\pca_cli.py sign-crl --private-seed-hex <PCA_INFRA_PRIVATE_SEED_HEX> --issued-at 2026-07-04T00:00:00Z --revoked-identifiers revoked-identifiers.txt
```

验证 CRL：

```powershell
python3 examples\pca_reference\pca_cli.py verify-crl --public-key-b64 <PCA_INFRA_PUBLIC_KEY_B64> --crl revocation.crl
```

检查单个 identifier：

```powershell
python3 examples\pca_reference\pca_cli.py verify-crl --public-key-b64 <PCA_INFRA_PUBLIC_KEY_B64> --crl revocation.crl --identifier <SHA256_IDENTIFIER_HEX>
```

参考 CRL 实现只接受 `signer_path = Identity/V1/PCA`，不查询 DNS，也不把 HTTPS 托管路径视为授权。

## 协议迁移声明

签署协议迁移声明：

```powershell
python3 examples\pca_reference\pca_cli.py sign-migration --private-seed-hex <PCA_INFRA_PRIVATE_SEED_HEX> --issued-at 2026-07-04T00:00:00Z --from-protocol PCA-v1.2 --to-protocol PCA-v1.3 --migration-text "Upgrade serialization rules"
```

验证协议迁移声明：

```powershell
python3 examples\pca_reference\pca_cli.py verify-migration --public-key-b64 <PCA_INFRA_PUBLIC_KEY_B64> --statement migration.json
```

协议迁移声明不是紧急废止声明，也不能复活、覆盖或缩小已经生效的 Namespace 废止结果。

## 文件提纲

- `pca_core/constants.py`：字节长度、Namespace prefix、`TRUST_ROOT_INFO_PATH`。
- `pca_core/encoding.py`：Namespace、Uppercase HEX、Canonical Info Path、File ID、UTC 时间戳校验。
- `pca_core/hkdf.py`：HKDF-SHA-512 与层级派生。
- `pca_core/identity.py`：Ed25519 identity seed、公钥与签名 helper。
- `pca_core/generation.py`：Generation secret 和 64 字节 BIP32 seed。
- `pca_core/xchacha20poly1305.py`：PyNaCl/libsodium XChaCha20-Poly1305 wrapper，不手写密码算法。
- `pca_core/vault.py`：Vault 文件加密、AAD、nonce、metadata。
- `pca_core/jcs.py`：RFC 8785 JCS。
- `pca_core/revocation.py`：紧急废止声明签名与验证。
- `pca_core/crl.py`：CRL 签名与验证。
- `pca_core/migration.py`：协议迁移声明签名与验证。
- `tests/`：派生、路径校验、Vault 认证、JCS、revocation、CRL、migration 测试。

## 常见错误

- 不要把 Master Secret 存入 Git。
- 不要把 emergency revocation private seed 和 Master Secret 放在一起。
- 不要从 Master Secret 派生 emergency revocation key。
- 不要用 DNS 做内部授权。
- 不要在 Canonical Info Path 产生语义后修改它。
- 不要用 Generation keys 建立公开身份信任。
- 不要假设 Vault 密文可以重新生成。
- 不要自动信任 successor Namespace。
