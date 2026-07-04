# PCA v1.2 参考手册与示例程序

本目录是 PCA v1.2 草案的参考实现与 setup 手册。
它用于展示一个兼容实现如何派生密钥、如何将协议逻辑与 UI/CLI 代码分离，并指导操作者完成无法安全自动化的手动步骤，例如离线保存 Master Secret、发布 DNS 记录，以及广播紧急废止声明。

这些示例刻意保持保守：

- `pca_core/` 只包含协议逻辑。
- `pca_cli.py` 只包含 CLI 参数解析、文件 IO、展示，以及给操作者的提示。
- `ui/` 包含一个本地开发者 UI，它会驱动同一组 CLI 命令。
- `tests/` 捕获未来示例应当保持的协议不变量。

## 状态与范围

这份代码面向参考用途。它展示 PCA 兼容逻辑，但不是完整的生产级钱包、证书机构、邮件客户端、DNS 发布器、HSM 集成或备份系统。

本实现遵循以下 PCA 核心规则：

- Master Secret 是 512-bit 随机数据。
- Namespace 用作 HKDF 的 salt。
- HKDF 使用 HKDF-SHA-512。
- Canonical Info Path 是 ASCII 且保持稳定。
- Identity、Generation、Vault 的职责保持分离。
- Identity 使用 Ed25519。
- Vault 使用 XChaCha20-Poly1305。
- 签名 JSON 在签名前使用规范化序列化。
- Revocation 验证先检查 Namespace，再检查签名。

`pca_core/constants.py` 中有一个明确的参考实现选择：PCAv1.2 说明 `TrustRootKey` 由 Master Secret 通过 HKDF 派生，但草案尚未为这条边指定字面 info path。本实现将它固定为：

```text
PCA/V1/TrustRoot
```

如果规范文档未来指定了不同值，只需在一个位置更新 `TRUST_ROOT_INFO_PATH`，然后重新生成测试向量。

## 环境要求

在此 Codex 工作区中使用内置 Python 运行时：

```powershell
python3 --version
```

以下所有命令都假设当前工作目录为仓库根目录。

```powershell
cd C:\Bernie\DevG\git\BernieHuang2008\PCAv1
```

运行测试：

```powershell
python3 -B -m unittest discover examples\pca_reference\tests
```

## Setup 手册

本节说明如何结合示例代码和必要的手动操作，建立一个完整的 PCA 体系。

### 1. 初始化 PCA Root

运行：

```powershell
python3 examples\pca_reference\pca_cli.py init
```

输出包含：

- `master_secret_hex`
- `namespace`
- `emergency_revocation_private_seed_hex`
- `emergency_revocation_public_key_b64`

CLI 会把机器可读 JSON 写入 stdout，并把给人的操作提示写入 stderr。

### 2. 离线保存 Master Secret

Master Secret 是 PCA 中唯一永久的根秘密。不要把它存放在联网项目目录、源码控制系统、云笔记、聊天记录、截图或命令历史中。

推荐的手动操作：

- 将 512-bit 的 `master_secret_hex` 写入或刻录到耐久的离线介质上。
- 至少保存两份地理位置分离的副本。
- 如果你的操作模型需要阈值恢复，可以考虑使用经过审查的 Shamir / SLIP-0039 风格流程拆分秘密。
- 永远不要发布 Master Secret，也不要把它当作登录密码使用。
- 日常操作中尽可能优先从中间父节点派生密钥，而不是反复使用 Master Secret。

### 3. 单独保存 Emergency Revocation Key

紧急废止密钥独立于 Master Secret。它不是从 Master Secret 派生出来的，必须单独保存。

手动操作：

- 将 `emergency_revocation_private_seed_hex` 保存在与 Master Secret 不同的物理位置。
- 将 `emergency_revocation_public_key_b64` 放入验证端配置、应用程序包，或受信任的分发包中。
- 不要将紧急废止密钥用于普通协议升级。
- 只有在当前 Namespace 必须被宣告死亡时才使用它。

### 4. 记录 Namespace

`namespace` 值是公开元数据，但它在密码学上非常重要。本 PCA 实例中的每个 HKDF 操作都会使用同一个 Namespace 作为 salt。

手动操作：

- 将 Namespace 记录在公共配置旁边。
- 将它包含在验证端配置中。
- 不要因为普通软件升级而更换 Namespace。
- 如果 Master Secret 泄露，应废止旧 Namespace，并在新 Namespace 下重建。

### 5. 派生基础设施身份与个人身份节点

派生 PCA 基础设施身份：

```powershell
python3 examples\pca_reference\pca_cli.py identity --master-hex <MASTER_HEX> --namespace <NAMESPACE> --path Identity/V1/PCA
```

派生个人身份：

```powershell
python3 examples\pca_reference\pca_cli.py identity --master-hex <MASTER_HEX> --namespace <NAMESPACE> --path Identity/V1/Personal/Identity2026
```

派生设备或用途身份：

```powershell
python3 examples\pca_reference\pca_cli.py identity --master-hex <MASTER_HEX> --namespace <NAMESPACE> --path Identity/V1/Personal/Identity2026/Laptop
```

手动操作：

- 将私钥种子视为敏感信息。
- 只发布确实需要对外可见的公钥。
- 通过带外方式为外部验证者建立 trust anchor。
- 外部身份验证不应要求公开 `IdentityRoot`。

### 6. 设置 DNS 域名绑定

DNS 绑定是可选的外部发现机制。它不能替代数学签名验证或带外信任建立。

首先派生身份公钥：

```powershell
python3 examples\pca_reference\pca_cli.py identity --master-hex <MASTER_HEX> --namespace <NAMESPACE> --path Identity/V1/Personal/Identity2026
```

然后创建 DNS 绑定文本：

```powershell
python3 examples\pca_reference\pca_cli.py dns-binding --domain example.com --public-key-b64 <PUBLIC_KEY_B64>
```

发布返回的 TXT 记录：

```text
_pca.example.com. 3600 IN TXT "pca-binding=<SHA256_PUBLIC_KEY_HEX>"
```

DNS 手动步骤：

- 打开你的 DNS 服务商控制台。
- 创建名为 `_pca` 的 TXT 记录。
- 将值设置为 `pca-binding=<SHA256_PUBLIC_KEY_HEX>`。
- setup 期间保持适中的 TTL，例如 300 或 3600 秒。
- DNS 传播完成后，验证者只能将该记录作为辅助发现信号。

重要：DNS 不是 PCA 的内部授权来源。不要将 DNS TXT 记录用作 CRL 签名者授权、Vault 授权、软件更新授权或协议迁移授权。

### 7. 设置 well-known 废止托管路径

选择一个你控制的域名，并准备这个公共路径：

```text
https://<your-domain.com>/.well-known/pca/revocation.crl
```

手动托管步骤：

- 在你的 web 主机上创建 `.well-known/pca/` 目录。
- 确保它通过 HTTPS 提供服务。
- 确保文件以 UTF-8 JSON 形式提供。
- 备份以前发布过的废止材料。
- 如果通过 CDN 发布，应在紧急情况发生前了解它的缓存失效流程。

当前示例会签署紧急废止声明。生产级 CRL 流程可能包含额外的签名列表和证书链验证。不要把 HTTPS 托管本身视为授权。

## 日常操作

### 派生通用节点

从 Master Secret 派生：

```powershell
python3 examples\pca_reference\pca_cli.py derive-node --master-hex <MASTER_HEX> --namespace <NAMESPACE> --path Encrypt/V1/Vault/Finance --length 64
```

从已经派生出的父节点派生：

```powershell
python3 examples\pca_reference\pca_cli.py derive-node --parent-key-hex <PARENT_KEY_HEX> --parent-path Encrypt/V1/Vault/Finance --namespace <NAMESPACE> --path Encrypt/V1/Vault/Finance/2026/Q3 --length 64
```

目标 path 必须等于或位于提供的父 path 之下。`PCA/V1/TrustRoot` 被视为协议分支根的父节点。

### Generation Secrets

派生密码管理器种子：

```powershell
python3 examples\pca_reference\pca_cli.py generation --master-hex <MASTER_HEX> --namespace <NAMESPACE> --path Encrypt/V1/Generation/PasswordManager --length 32
```

派生 BIP32 master seed：

```powershell
python3 examples\pca_reference\pca_cli.py bip32-seed --master-hex <MASTER_HEX> --namespace <NAMESPACE> --network Mainnet
```

Generation keys 不建立公开信任。它们是确定性秘密。

## Vault 操作

加密文件：

```powershell
python3 examples\pca_reference\pca_cli.py vault-encrypt --master-hex <MASTER_HEX> --namespace <NAMESPACE> --permission-path Finance/2026/Q3 --input secret.txt --output secret.pca --metadata secret.pca.json
```

解密文件：

```powershell
python3 examples\pca_reference\pca_cli.py vault-decrypt --master-hex <MASTER_HEX> --namespace <NAMESPACE> --permission-path Finance/2026/Q3 --file-id <FILE_ID> --input secret.pca --output secret.txt
```

手动操作：

- 将密文和 metadata 一起保存。
- 备份 Vault 密文；它无法由 Master Secret 重新生成。
- 密钥可以恢复，但如果密文丢失，被加密的外部秘密无法恢复。
- 保留 `permission_path` 和 `file_id`；它们是重新计算文件密钥所必需的。

## 紧急废止

只有在当前 Namespace 必须被宣告死亡时才使用废止，例如 Master Secret 泄露之后。

签署废止声明：

```powershell
python3 examples\pca_reference\pca_cli.py sign-revocation --private-seed-hex <EMERGENCY_PRIVATE_SEED_HEX> --namespace <NAMESPACE> --revoked-at 2026-07-04T00:00:00Z --reason "Master Secret Compromised"
```

带有 successor hint 的签署方式：

```powershell
python3 examples\pca_reference\pca_cli.py sign-revocation --private-seed-hex <EMERGENCY_PRIVATE_SEED_HEX> --namespace <OLD_NAMESPACE> --revoked-at 2026-07-04T00:00:00Z --reason "Master Secret Compromised" --successor-namespace-hint <NEW_NAMESPACE>
```

手动发布步骤：

- 将 stdout 原样保存为 UTF-8 JSON。
- 如果该域名是你的废止发布点，将它发布到 `https://<your-domain.com>/.well-known/pca/revocation.crl`。
- 通过额外渠道发布同一份声明：个人网站、签名邮件、社交资料、PGP keyserver note、公共时间戳服务，或验证者会监控的其他渠道。
- 不要将 `successor_namespace_hint` 表示为 trust anchor。
- 告知验证者：新 Namespace 的信任必须通过带外方式建立。

验证废止声明：

```powershell
python3 examples\pca_reference\pca_cli.py verify-revocation --public-key-b64 <EMERGENCY_PUBLIC_KEY_B64> --namespace <NAMESPACE> --statement revocation.json
```

验证顺序：

1. 将声明中的 `namespace` 与本地信任的 Namespace 比对。
2. 如果 Namespace 不同，立即忽略该声明。
3. 对移除 `signature` 字段后的规范化 JSON 验证 Ed25519 签名。
4. 如果有效，拒绝该 Namespace 下的后续操作。

## 废止后重建

一旦某个 Namespace 被合法废止，就应将其视为永久死亡。

手动重建步骤：

- 生成新的 Master Secret。
- 生成新的独立紧急废止密钥。
- 使用新的 Namespace。
- 重新派生新的 identity roots 和 branch keys。
- 为新的公开身份公钥重新发布 DNS 绑定。
- 通过带外方式分发新的 trust anchors。
- 不要仅因为旧废止声明包含 `successor_namespace_hint` 就自动信任新 Namespace。

## UI

运行本地 UI：

```powershell
python3 examples\pca_reference\ui\server.py 8765
```

打开：

```text
http://127.0.0.1:8765/
```

UI 行为：

- 预制主干节点是灰色。
- 成功生成后节点标记为绿色。
- 动态节点通过分支专用表单创建。
- 右侧 PCACLI 面板显示每个 UI 操作实际执行的精确 CLI 命令。
- Derivation Source 面板支持 Master Secret、已生成的选中父节点，或手动输入 parent key/path。

## 文件提纲

`pca_core/constants.py`

定义字节长度、namespace prefix，以及 `TRUST_ROOT_INFO_PATH`。

`pca_core/encoding.py`

校验 Namespace ID、Uppercase HEX 字段、Canonical Info Path、Identity paths、Generation paths、Vault permission paths、File IDs 和 UTC timestamps。

`pca_core/hkdf.py`

实现 HKDF-SHA-512 和分层派生。`derive_path_key` 从 Master Secret 开始。`derive_descendant_key` 从任意 parent key/path 对开始。

`pca_core/identity.py`

从 `Identity/V1/...` 路径派生 Ed25519 private seeds，并提供签名和公钥 helper。

`pca_core/generation.py`

从 `Encrypt/V1/Generation/...` 路径派生确定性 Generation secrets。BIP32 helper 精确返回 64 字节。

`pca_core/xchacha20poly1305.py`

使用 HChaCha20 加 `cryptography` 提供的 IETF ChaCha20-Poly1305 实现 XChaCha20-Poly1305。

`pca_core/vault.py`

实现 Vault 文件加密。每个文件获得一个 256-bit File ID、一个新的 192-bit nonce、一个 per-file key，并使用完整路径作为 AAD。

`pca_core/jcs.py`

为 PCA 签名结构提供受限的 canonical JSON serialization。

`pca_core/revocation.py`

签署和验证紧急废止声明。

`pca_cli.py`

提供访问参考实现的命令行接口。操作提示会打印到 stderr，因此 stdout 保持机器可读。

`ui/server.py`

提供本地树形 UI，并将 UI 操作映射为具体的 `pca_cli.py` 子进程调用。

`ui/static/`

包含浏览器 UI。

`tests/`

包含针对确定性派生、parent derivation、路径校验、Vault 认证、JCS 行为和 revocation 验证顺序的聚焦测试。

## 操作清单

在使用 PCA Namespace 之前：

- 已通过 `init` 生成 Master Secret。
- Master Secret 已离线保存。
- Emergency revocation private seed 已单独保存。
- Emergency revocation public key 已配置到验证端。
- Namespace 已记录。
- 基础设施身份和公开身份已派生。
- 公开身份公钥已通过可信渠道分发。
- 可选 DNS 绑定已发布。
- 可选 well-known 废止路径已准备。
- Vault 密文备份策略已建立。
- 已用非生产数据演练 revocation。

## 常见错误

- 不要把 Master Secret 存入 Git。
- 不要把 emergency revocation private seed 和 Master Secret 放在一起。
- 不要从 Master Secret 派生 emergency revocation key。
- 不要将 DNS 用作内部授权。
- 不要在 Canonical Info Path 产生语义之后修改它。
- 不要用 Generation keys 建立公开身份信任。
- 不要假设 Vault 密文可以重新生成。
- 不要自动信任 successor Namespace。

