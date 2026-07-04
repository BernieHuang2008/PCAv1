# Personal Cryptographic Architecture（PCA）Protocol Specification

**Version:** v1.2
**Status:** Formal
**Date:** 2026-07-04

---

# 前言（Preamble）

## 规范性关键词

本文档采用 RFC 2119 与 RFC 8174 中定义的规范性关键词。

下列关键词具有严格的规范意义：

- **MUST**
- **MUST NOT**
- **REQUIRED**
- **SHALL**
- **SHALL NOT**
- **SHOULD**
- **SHOULD NOT**
- **RECOMMENDED**
- **MAY**
- **OPTIONAL**

除非另有说明，所有兼容 PCA 的实现 **MUST** 遵循本文档中的规范性要求。

任何违反 **MUST** 或 **MUST NOT** 要求的实现，不应视为兼容 PCA 的实现。

---

## 术语表（Terminology）

本文档采用以下术语。

### Master Secret

整个 PCA 唯一的 Root of Trust。

Master Secret 是整个系统唯一需要永久保存且无法恢复的秘密。

### Trust Root

由 Master Secret 经 HKDF 派生得到的逻辑根密钥。

Trust Root 不需要长期保存，可随时重新计算。

### Persona

Persona 表示一个独立的身份空间（Identity Namespace）。

不同 Persona 应被视为彼此独立的公开身份。

例如：

- Alice
- Bob
- Personal
- Work
- Anonymous

每个 Persona 可以拥有多个 Identity 节点（如 `Identity2026`、`IdentityLongTerm` 等，命名具有语义灵活性）。

### Identity

Identity 用于建立公开信任关系（Public Trust）。

Identity 负责身份认证、数字签名以及建立信任链。

### Generation

Generation 用于确定性生成各种秘密。

例如：

- Password
- Bitcoin Wallet
- Vault Key

Generation 不建立公开信任。

### Vault

Vault 用于保护无法重新生成的外部秘密。

例如：

- API Key
- OAuth Token
- Recovery Code

Vault 不负责生成秘密，仅负责保护秘密。

### 紧急废止密钥（Emergency Revocation Key）

独立于 Master Secret 之外生成的第二把密钥，专门用于在 Master Secret 泄露时宣告整个协议体系废止。

该密钥与 Master Secret 物理隔离保存。

### Canonical Info Path

Canonical Info Path 是 HKDF 的唯一上下文。

所有兼容 PCA 的实现 **MUST** 使用完全一致的 Canonical Info Path。

---

# 第 1 章 简介（Introduction）

Personal Cryptographic Architecture（简称 PCA）是一套用于管理个人身份（Identity）、密钥（Key）以及秘密数据（Secret）的统一密码学架构。

PCA 不发明新的密码算法，而是定义一套长期稳定、职责清晰、可确定性恢复（Deterministic Recovery）的密钥管理协议，使所有兼容 PCA 的实现都能够生成完全一致的密钥体系。

整个系统只有一个永久离线保存的 Master Secret，其余绝大部分密钥均可由 HKDF 确定性派生恢复。

PCA 的目标并不是规定某一种具体软件，而是定义一种稳定的密码学架构，使不同实现之间能够保持完全一致的密钥体系与身份体系。

---

# 第 2 章 设计目标（Design Goals）

PCA 的设计遵循以下原则：

- **Single Root of Trust（唯一信任根）**：整个系统仅有一个信任锚点。
- **Deterministic Recovery（确定性恢复）**：所有密钥均可由 Master Secret 重新计算。
- **Minimal Persistent Secrets（最少长期密钥）**：除 Master Secret 和外部 Vault 数据外，无其他长期保存的秘密。
- **Separation of Responsibilities（职责分离）**：Identity、Generation、Vault 三者职责互不重叠。
- **Least Disclosure（最小公开）**：默认匿名，仅在必要时选择性披露。
- **Capability Isolation（能力隔离）**：HKDF 保证了子密钥泄露不影响父级与兄弟节点。
- **Long-term Evolvability（长期可演进）**：协议支持版本升级与信任链迁移。

---

# 第 3 章 总体架构（Architecture）

## 3.1 密钥树全景图

```text
Master Secret
(512-bit Random)
        │
        ▼
TrustRootKey
(HKDF-SHA-512)
        │
        ├──────────────────────────┬──────────────────────────┐
        │                          │                          │
        ▼                          ▼                          ▼
IdentityRoot                EncryptRoot                  (Reserved)
(私钥永不公开，公钥绝对保密)
        │                          │
        │                          ├── Generation
        │                          │   ├── PasswordManager
        │                          │   ├── Bitcoin/Mainnet
        │                          │   └── ...
        │                          │
        │                          └── VaultRoot
        │                              └── PermissionNode...
        │                                      └── PerFileKey
        │
        ├── PCA
        │   (此公钥被硬编码在所有兼容程序中)
        │
        ├── Personal
        │   ├── Identity2026
        │   │   ├── Laptop
        │   │   ├── Desktop
        │   │   └── EmailCa
        │   │           └── Email Identity (Ephemeral)
        │   └── IdentityLongTerm
        │
        ├── Work
        │   └── Identity2026
        │
        └── Alice
            └── Identity2026
```

## 3.2 派生架构

全树采用统一的 `HKDF-SHA-512` 确定性派生。

## 3.3 三大独立分支概述

PCA 包含三个彼此独立的安全域（Security Domain）：

| 模块（Module） | 职责（Responsibility） | 公开信任（Public Trust） | 可恢复（Recoverable） |
| :--- | :--- | :--- | :--- |
| **Identity** | 建立公开身份与信任 | Yes | Yes |
| **Generation** | 确定性生成秘密 | No | Yes |
| **Vault** | 保存外部秘密并加密文件 | No | Vault 数据本身不可恢复，但密钥可恢复 |

三者职责完全分离。`Identity` 不负责保存秘密。`Generation` 不负责建立信任。`Vault` 不负责生成秘密。

---

# 第 4 章 Master Secret（主密钥）

## 4.1 生成规范

Master Secret **MUST** 是使用密码学安全随机数生成器（CSPRNG）生成的 **512-bit** 随机数。

## 4.2 保存与离线要求

Master Secret 是整个 PCA 唯一需要永久保存的秘密。

Master Secret **MUST** 永远离线保存，不参与任何业务操作，仅用于恢复整个密钥体系。

建议保存方式包括：

- 金属助记板
- HSM
- 多份异地备份
- 银行保险柜

Master Secret **MUST NOT** 联网。

Master Secret 一旦泄漏，攻击者将能够恢复整个 PCA 的全部密钥体系。因此，Master Secret 的保护等级应高于任何其他密钥。

## 4.3 紧急废止密钥的独立生成与保存

在生成 Master Secret 的同一时刻，实现 **MUST** 额外生成一对独立的 **紧急废止密钥（Emergency Revocation Key）**，算法为 Ed25519。

- **生成要求**：必须使用独立的 CSPRNG 随机数生成，**不得**从 Master Secret 派生。
- **保存要求**：该密钥的私钥 **MUST** 与 Master Secret **物理隔离保存**（例如存放在不同的保险柜或由不同的受托人保管）。
- **公钥分发**：该公钥 **SHOULD** 被硬编码（内嵌）在验证端软件的可执行文件或受信任的更新配置包中，并通过代码签名（Code Signing）机制确保其完整性与来源可信。

除紧急废止密钥外，所有兼容 PCA 的实现 **MUST** 在可执行文件中硬编码基础设施身份 `Identity/V1/PCA` 的公钥及其完整 Canonical Path。该公钥作为 CRL 验证、软件升级包签名、协议迁移签名等内部校验流程的最高信任锚点（Trust Anchor）。

---

# 第 5 章 命名空间（Namespace）

Namespace 是 PCA 协议的最高层级隔离标识。它作为所有 HKDF 操作的 `salt` 输入，并决定紧急废止声明的唯一生效范围。

同一个 Namespace 内的密钥、证书、撤销状态和协议版本兼容状态构成一个封闭的密码学宇宙。不同 Namespace 之间 **MUST** 被视为完全独立，旧 Namespace 中的信任锚、废止声明或证书链 **MUST NOT** 自动作用于新 Namespace。

## 5.1 Namespace ID

整个 PCA 协议实例仅存在一个 Namespace ID。

Namespace ID **MUST** 满足：

- 长度为 256 bit。
- 随机生成。
- 使用 Uppercase HEX 编码。
- 整个协议生命周期保持不变。
- 所有 HKDF 均使用同一个 Namespace ID。

格式如下：

```text
PCA-v1/<NamespaceID>
```

例如：

```text
PCA-v1/A980E2656D5D0349012434FF624506C9650187D1F4B897D20D0E0918B1E1186E
```

Namespace ID 中的 `PCA-v1` 前缀用于标识命名空间格式族，不等同于协议版本升级本身。普通协议版本升级（如算法、序列化格式或字段兼容性调整）**MUST NOT** 被解释为自动更换 Namespace ID；只有当新规范明确要求隔离的命名空间格式，或 Master Secret 泄露后需要重建体系时，才使用全新的 Namespace ID。

## 5.2 废止作用域

紧急废止声明仅对声明中指定的 **`namespace`** 字段生效。

当 Master Secret 泄露时，合法所有者可以签署废止声明，使当前 Namespace（例如 `PCA-v1/A980...`）进入废止状态。若所有者希望在废止后重建体系，则 **MUST** 生成全新的 Master Secret，并注册或选择一个**全新的 Namespace ID**（例如 `PCA-v2/3F8A...`）。该流程属于 Namespace 迁移，不属于普通协议版本升级。

旧 Namespace 的紧急废止公钥、证书链和撤销状态对新 Namespace **MUST** 完全无效。验证端 **MUST NOT** 将旧 Namespace 的废止结果扩展解释到任何其他 Namespace。

---

# 第 6 章 HKDF 密码学原语规范（HKDF Specification）

整个 PCA 所有确定性派生均采用：

```text
HKDF-SHA-512
```

所有兼容 PCA 的实现 **MUST** 使用统一的 HKDF 参数。

## 6.1 HKDF 输入

所有 HKDF 使用以下输入：

```text
IKM  = Parent Key
salt = Namespace ID
info = Canonical Info Path
```

其中：

- IKM 表示父密钥。
- salt 表示 PCA 协议命名空间。
- info 表示唯一上下文。

对于相同的 IKM、salt、info，HKDF **MUST** 产生完全一致的输出。

## 6.2 Canonical Info Path

所有 HKDF 的 info **MUST** 使用统一路径格式。

基本格式如下：

```text
Branch/Version/Object...
```

路径编码强制满足以下要求：

- **MUST** 仅包含 US-ASCII 字符。
- **MUST** 仅允许字符集 `[A-Za-z0-9/-]`。
- **MUST NOT** 包含任何 Unicode 字符、空格、控制字符或上述集合之外的符号。

例如：

```text
Identity/V1/Personal/Identity2026/Laptop
Identity/V1/Work/Identity2026/Phone
Identity/V1/Alice/Identity2026/Email/3F91A27C6E0D5B88C42E8A9F0C7B11D4
Encrypt/V1/Generation/PasswordManager
Encrypt/V1/Generation/Bitcoin/Mainnet
Encrypt/V1/Vault/Root
```

Canonical Info Path **MUST** 保持稳定。

一旦某一路径被定义，其语义 **MUST NOT** 被修改。

未来如需变更语义，应创建新的路径（如使用 `V2` 版本段），而不是修改已有路径。

## 6.3 确定性输出长度规范表（Normative Output Lengths）

不同用途的密钥对 HKDF 输出字节的长度要求不同。实现 **MUST** 严格遵守下表规定的截取或使用规则：

| 用途（Purpose） | 路径示例 | 所需字节数 | 具体规则 |
| :--- | :--- | :--- | :--- |
| **Ed25519 私钥种子** | `Identity/.../Email/...` | **32 字节** | 取 HKDF 输出的**前 32 字节**，作为 Ed25519 的种子（seed）。 |
| **XChaCha20-Poly1305 密钥** | `Encrypt/.../Vault/...` | **32 字节** | 取 HKDF 输出的**前 32 字节**作为对称加密密钥。 |
| **BIP32 主种子** | `Encrypt/.../Generation/...` | **64 字节** | 取 HKDF 输出的**完整 64 字节**，直接作为 BIP32 的 Master Seed（HMAC-SHA512 原生接受 512-bit 输入）。 |
| **SHA-256 指纹/哈希** | 撤销列表、证书指纹 | **32 字节** | 标准 SHA-256 输出。 |

## 6.4 确定性密钥树生成逻辑

每一级节点均由上一层节点通过 HKDF 派生。

因此，只要拥有 Master Secret，即可按照完全一致的路径重新恢复整个密钥体系。

PCA 不需要长期保存整个密钥树。除 Master Secret 外，其余所有密钥均可在需要时重新计算。

---

# 第 7 章 命名与编码规范（Naming & Encoding Rules）

## 7.1 统一命名规则

所有 Path 中的对象名称 **MUST** 使用 CamelCase（驼峰命名）。

例如：

```text
PasswordManager
Vault
DocumentSigning
CodeSigning
EmailCa
LongTermIdentity
```

禁止使用：

```text
password_manager
PASSWORD_MANAGER
password-manager
```

整个协议统一使用路径分隔符：

```text
/
```

禁止使用其他符号作为路径层级分隔符。

所有 Path **MUST** 区分大小写。

未来新增路径时，应保持已有路径命名风格一致。

## 7.2 编码规范

整个 PCA 协议统一采用以下编码规范：

| 对象 | 编码 |
| :--- | :--- |
| Namespace ID | Uppercase HEX |
| Email ID | Uppercase HEX |
| File ID | Uppercase HEX |
| Hash | Uppercase HEX |
| Fingerprint | Uppercase HEX |

所有 HEX 字符串 **MUST** 使用大写字母。

例如：

```text
8E4D9AF3C2B18F...
```

禁止：

```text
8e4d9af3c2b18f...
```

所有字符串 **SHOULD** 使用 UTF-8 编码（仅用于外部元数据展示，不参与密码学计算）。

Canonical Info Path **MUST** 按照本文定义的 US-ASCII 字节表示进行编码，不允许因平台差异而改变其字节表示。

## 7.3 JSON 签名序列化强制标准

任何涉及数字签名的 JSON 数据结构（包括但不限于撤销列表 CRL、证书元数据等），其序列化 **MUST** 遵循 **RFC 8785（JSON Canonicalization Scheme，JCS）**。

具体要求：

- 无额外空格。
- 无换行符。
- 使用双引号。
- 键名按照字典序（ASCII 码顺序）排列。
- 转义规则严格遵循 RFC 8785。

签名计算时，**MUST** 对经过 JCS 序列化后的字节流（UTF-8 编码）直接进行签名。

## 7.4 路径分隔符与大小写敏感性

重申：路径分隔符为 `/`，所有路径大小写敏感。

---

# 第 8 章 Identity Branch（身份分支）

Identity Branch 用于建立公开信任关系（Public Trust）。

算法：

```text
Ed25519
```

## 8.1 IdentityRoot、PCA 与 Persona 管理

IdentityRoot 长期离线保存，仅负责签发 `PCA` 基础设施身份与 Persona。

IdentityRoot 的私钥 **MUST** 永不公开。为避免外部观察者通过根公钥关联 `Personal`、`Work`、`Alice` 等身份分支，IdentityRoot 的公钥默认也 **SHOULD NOT** 公开发布。

`Identity/V1/PCA` 是 PCA 基础设施身份。所有兼容 PCA 的实现 **MUST** 硬编码该身份的公钥及完整 Canonical Path，并将其作为内部校验流程的最高信任锚点。`PCA` 身份 **MUST NOT** 用作个人、工作、邮件或其他外部公开身份。

每个 Persona 表示一个逻辑身份空间。

例如：

```text
Personal
Work
Anonymous
```

Persona 可以继续签发子 Identity 节点。节点命名具有语义灵活性，例如：

```text
Personal
    ├── Identity2026
    └── IdentityLongTerm
```

不同 Persona 应被视为互相独立的公开身份。

## 8.2 设备与用途身份派生

每个 Identity 节点可以继续签发各种用途身份，例如：

- `Laptop`
- `Desktop`
- `Phone`
- `DocumentSigning`
- `CodeSigning`
- `EmailCa`

派生路径示例：

```text
Identity/V1/Personal/Identity2026/Laptop
Identity/V1/Work/Identity2026/CodeSigning
```

## 8.3 证书链与公开验证模型

所有子身份（如 `Laptop`）的公钥可以由父级身份（如 `Identity2026`）签名形成证书链。

对于外部公开身份，验证者通过逐级验证签名，并以其已经通过带外方式信任的 Persona、Identity 节点或其他公开父级身份作为信任起点。外部验证流程 **MUST NOT** 要求公开 `IdentityRoot` 公钥。

对于 PCA 内部基础设施身份，验证者通过逐级验证签名，最终信任锚为硬编码的 `Identity/V1/PCA` 公钥。

## 8.4 基础设施验证流程（Infrastructure Verification）

所有涉及 PCA 内部组件的权限校验，包括但不限于 Vault 文件解密授权、Generation 派生授权、CRL 验证、软件升级包签名和协议迁移签名，验证端 **MUST** 仅依赖证书链回溯至硬编码的 `Identity/V1/PCA` 信任锚。

内部验证流程 **MUST NOT** 执行任何 DNS 查询，**MUST NOT** 将 DNS TXT、WKD、HTTPS 托管路径或其他外部发现结果作为授权依据。DNS 仅可用于第 18 章定义的外部辅助发现流程，且不得替代数学签名验证。

---

# 第 9 章 Email Identity（邮件身份与匿名分组）

Email Identity 用于建立邮件身份，采用**临时隔离发送**与**事后选择性归组**的设计。

## 9.1 临时邮件身份（Ephemeral Identity）

默认情况下，每封邮件 **MUST** 使用一个**全新的、独立的临时 Ed25519 密钥对**。

派生路径：

```text
Identity/V1/<Persona>/<IdentityNode>/Email/Ephemeral/<RandomEmailId>
```

其中 `<RandomEmailId>` 是一个 256-bit 随机数（Uppercase HEX），一次性使用。

该密钥仅用于签署当前这一封邮件，签署完成后 **SHOULD** 立即从内存中销毁。

> 该设计确保默认情况下，外部观察者无法将多封邮件关联到同一个发件人身份。

## 9.2 延迟绑定（Delayed Binding）策略

当发件人希望证明某封（或多封）临时邮件属于某个公开身份（如 `Personal`）时，**MUST NOT** 创建独立的中心化清单文件。

取而代之，**MUST** 采用 **OpenPGP 交叉签名证书（RFC 4880 Subkey Binding / Third-party Certification）** 格式进行证明。

**具体流程**：

1. **生成临时密钥**：按照 9.1 生成 Ed25519 密钥对（或直接生成一个标准的 PGP 子密钥）。
2. **发送邮件**：使用临时私钥签署邮件正文。
3. **事后归组**：发件人使用其长期身份私钥（如 `Personal/Identity2026`）为临时公钥签发一个 **PGP 认证签名（Certification Signature，类型 `0x10` 或 `0x18`）**。
   - 该签名包中 **MUST** 包含临时公钥的指纹、签发时间（`iat`）以及可选的说明（如邮箱地址）。
4. **分发证明**：发件人 **SHOULD** 将该 PGP 交叉签名证书作为独立的 `.asc` 文件，通过独立信道发送给特定接收者，例如第二封邮件、U 盘、即时通讯软件或当面交换。

**验证者流程**：

1. 验证邮件正文的临时签名（证明邮件未被篡改）。
2. 使用标准 OpenPGP 库导入父级身份公钥，并读取独立分发的 `.asc` 证明文件。
3. 手动触发签名验证，确认该证明确由 `Personal/Identity2026` 的私钥签署。
4. 若验证者已经通过带外方式信任 `Personal/Identity2026` 公钥，则确认该临时邮件归属于该身份。

**安全性分析**：

- 对于外界（未收到附带证明的第三方），这封邮件看起来只是一封普通的 PGP 签名邮件，无法关联到特定身份。
- 该行为与全球 PGP 生态完全兼容，即使全球只有你一人使用 PCA，也不会产生独特的协议指纹。
- PCA 协议不要求也不依赖邮件客户端（如 Thunderbird、Outlook）自动解析延迟绑定证明。手动验证是确保延迟绑定匿名性与去中心化信任网的基础。

**父级签名者身份的灵活性说明**：

签发延迟绑定证明的父级身份（Signing Identity）不限于 PCA 密钥树中的 Identity 节点。任何持有符合 RFC 4880 标准的 PGP 兼容私钥（包括但不限于外部生成的 RSA 或 Ed25519 密钥）均可作为父级身份，为临时公钥签发认证签名（`0x10` 或 `0x18`）。

验证端在执行延迟绑定校验时，**MUST** 仅依赖标准 OpenPGP 签名验证流程验证该父级公钥与签名的数学关系，**MUST NOT** 要求该父级身份必须存在于 PCA 命名空间内，亦 **MUST NOT** 依赖 DNS 或任何外部发现协议对该父级身份进行自动化信任裁决。父级身份的最终信任锚点由验证者通过带外方式（Out-of-band）自行确立。

## 9.3 验证者标准流程

验证者 **SHOULD** 按以下顺序执行检查：

1. 获取临时公钥并验证邮件签名。
2. 检查是否存在独立分发的 PGP 认证签名证明。若存在，使用标准 OpenPGP 库验证父级身份签名链。
3. 若父级身份未被信任，验证者 **SHOULD** 提示用户采用带外方式（Out-of-band，例如当面交换、U 盘拷贝、可信即时通讯）导入父级公钥。
4. DNS 查询（见第 18 章）仅作为 **OPTIONAL** 的外部辅助发现手段，其结果 **MUST NOT** 用于替代数学签名验证或带外信任确认。
5. 若以上均失败，则仅接受为“匿名签名”。

## 9.4 匿名模式说明

默认情况下，PCA 仅提供临时身份私钥用于签名。验证者无法将其关联到特定 Persona 或个人。

发件人拥有是否披露归组证明的完全主动权。

## 9.5 环签名（Ring Signatures）可选增强

为进一步增强发送者匿名性（Unlinkability），实现 **MAY** 支持环签名（Ring Signatures）作为可选扩展。

- 在派生临时密钥时，**MAY** 使用环签名算法（如 CLSAG）替代 Ed25519。
- 环签名允许签名者隐藏在一组公钥中，验证者仅能确认签名来自该集合，无法确定具体成员。
- 当前版本不将环签名纳入 **MUST** 要求，具体实现细节由上层应用自行定义。

---

# 第 10 章 Encrypt Branch（加密分支）

Encrypt Branch 不建立任何公开信任。

Encrypt Branch 仅负责：

- Generation（秘密生成）
- Vault（秘密保护）

EncryptRoot 不需要长期保存。EncryptRoot 可由 Master Secret 随时重新恢复。

Encrypt Branch 与 Identity Branch 完全独立。任何 Encrypt Branch 派生出的密钥均不得用于建立公开身份。

---

# 第 11 章 Generation（确定性秘密生成）

Generation 用于生成所有能够确定性恢复的秘密。

## 11.1 通用生成路径

例如：

```text
Encrypt/V1/Generation/PasswordManager
Encrypt/V1/Generation/Bitcoin/Mainnet
Encrypt/V1/Generation/APIKeys/GitHub
```

所有 Generation Key 均由 HKDF 派生。Generation Key 不需要长期保存。

## 11.2 子密钥轮换规范

对于需要版本轮换或衍生多个平行秘密的场景（如每年更换密码管理器主密码），可以通过新增路径层级进行轮换。

例如将 `/2024` 变更为 `/2025`

## 11.3 Bitcoin 钱包派生

PCA 不重新定义 Bitcoin 钱包标准。PCA 仅规定 Bitcoin 根密钥的生成方式。

派生流程如下：

```text
Encrypt/V1/Generation/Bitcoin/Mainnet
            │
            ▼
          HKDF (取完整 64 字节)
            │
            ▼
      BIP32 Master Seed (512-bit)
            │
            ▼
     Standard BIP32 Derivation
```

HKDF 输出的 512-bit 数据 **MUST** 直接作为 BIP32 Master Seed。

之后所有钱包派生均应遵循 BIP32 标准（BIP44、BIP84 等）。

PCA 不要求使用 BIP39 助记词。Master Secret 已承担整个系统唯一恢复入口的职责，因此无需再生成额外助记词。

---

# 第 12 章 Vault（外部秘密保护与文件加密）

Vault 用于保存无法重新生成的外部秘密或用于加密文件。

## 12.1 权限树（Permission Tree）架构

整体结构如下：

```text
Encrypt/V1/Vault/Root
            │
            ▼
         VaultRoot
            │
            ▼
    PermissionNodeKey
            │
    HKDF(File ID)
            │
            ▼
        PerFileKey (取前 32 字节)
            │
            ▼
      Encrypt(File)
```

## 12.2 PermissionNode 派生

每个权限节点（PermissionNode）代表一个逻辑权限域（如 `Finance`、`HR`、`PersonalDocs`）或者其他子域。

路径示例：

```text
Encrypt/V1/Vault/Finance
Encrypt/V1/Vault/Finance/2026/Q3
Encrypt/V1/Vault/Company1/Department2/User3
```

不同 PermissionNode 之间彼此独立。拥有某个节点，不应能够恢复其父节点或兄弟节点。

## 12.3 File ID 随机化规范

每个文件对应一个唯一 File ID。

File ID **MUST** 满足：

- 长度为 256 bit。
- 使用密码学安全随机数生成器（CSPRNG）生成。
- 使用 Uppercase HEX 编码。

例如：

```text
5C5F68690ACDBC085A1C2E86A1C4A7BE0AFC2B3DB160558BEBB026224A7BD8BD
```

对应 HKDF Path：

```text
Encrypt/V1/Vault/<Permission Path>/<File ID>
```

File ID 的随机性用于隐藏文件元数据，避免文件名称、编号或数量等元数据被预测。

## 12.4 PerFileKey 派生

每个文件使用独立密钥。

从 PermissionNode 派生 PerFileKey：

```text
PerFileKey = HKDF(PermissionNodeKey, "File/" + FileID)
```

取 HKDF 输出的**前 32 字节**作为 XChaCha20-Poly1305 密钥。

## 12.5 加密存储格式规范

所有使用 Vault 进行的文件加密 **MUST** 采用 XChaCha20-Poly1305。

对于每次加密操作，使用 CSPRNG 生成 **192-bit（24 字节）** 随机 Nonce 是 **RECOMMENDED** 的默认方式。

实现 **MAY** 采用确定性派生方式生成 Nonce，例如：

```text
Nonce = HKDF(PerFileKey, "NonceSalt/" + FileID)
```

并截取输出的前 24 字节作为 XChaCha20-Poly1305 Nonce。

无论采用随机方式还是确定性派生方式，实现 **MUST** 确保对于同一个 `PermissionNodeKey` 下的同一个 `FileID`，每次加密所使用的 Nonce 永不重复。

加密后的存储格式 **MUST** 为：

```text
字节偏移 0-23：   Nonce (24 字节)
字节偏移 24 起：  Ciphertext
文件末尾 16 字节： Tag (16 字节)
```

解密时，实现 **MUST** 从文件头部读取 Nonce，并使用该 Nonce 与 PerFileKey 进行解密。

## 12.6 附加认证数据（AAD）规范：

所有使用 `XChaCha20-Poly1305` 执行的加密操作，**MUST** 将待加密文件对应的 **完整 Canonical Info Path**（例如 `Encrypt/V1/Vault/Finance/2026/Q3/5C5F...`）的 ASCII 大端序字节流，作为算法的 **附加认证数据（AAD）** 输入。

解密时，**MUST** 使用完全相同的路径字节流作为 AAD 进行 Tag 校验。若 AAD 不匹配，解密 **MUST** 立即抛出认证失败错误，不得输出任何明文数据。

> 设计意图：此机制可有效防止加密文件在不同权限目录之间被非法重定位（Relocation Attack），确保密文与特定路径强绑定。

> Nonce 安全说明：由于 PCA 采用一文件一密钥（PerFileKey）结构，即使两个不同文件使用了相同的 Nonce，因加密密钥不同，攻击者也无法通过异或运算还原明文。上述 Nonce 唯一性要求旨在防御同一文件被重复加密时可能出现的密钥流重用风险。

---

# 第 13 章 生命周期管理（Lifecycle）

## 13.1 组件生命周期总表

| 组件（Component） | 长期保存（Long-term） | 离线保存（Offline） | 可恢复（Recoverable） |
| :--- | :--- | :--- | :--- |
| Master Secret | Yes | Yes | No |
| 紧急废止密钥 | Yes | Yes | No（丢失不可恢复） |
| TrustRootKey | No | No | Yes |
| IdentityRoot | Optional | Optional | Yes |
| Persona | Optional | Optional | Yes |
| Identity 节点 | Optional | Optional | Yes |
| 临时 Email 密钥 | No | No | Yes |
| EncryptRoot | No | No | Yes |
| Generation 密钥 | No | No | Yes |
| VaultRoot | No | No | Yes |
| Vault 加密数据（密文） | Yes | Optional | No（仅密钥可恢复） |

## 13.2 密钥销毁策略

- 临时 Email 密钥：签名完成后立即销毁。
- 短期 Identity 节点：过期后可从在线存储中移除，但可通过 Master Secret 恢复。
- Master Secret：永不销毁，除非手动执行废止流程。

---

# 第 14 章 安全模型（Security Model）

## 14.1 三个安全域的职责矩阵

| 模块（Module） | 职责（Responsibility） | 公开信任（Public Trust） | 可恢复（Recoverable） |
| :--- | :--- | :--- | :--- |
| **Identity** | 建立公开身份与信任 | Yes | Yes |
| **Generation** | 确定性生成秘密 | No | Yes |
| **Vault** | 保存外部秘密 | No | No（密钥可恢复，数据不可） |

## 14.2 威胁模型与假设

PCA 假设：

1. Master Secret 和紧急废止密钥的物理安全性得到保障。
2. 实现没有侧信道漏洞（如时序攻击、缓存攻击）。
3. CSPRNG 的质量符合 NIST SP 800-90 标准。

PCA 不防御：

1. Master Secret 泄露后的持续攻击（但紧急废止密钥可宣布体系死亡）。
2. 量子计算机对 Ed25519 和 ECDLP 的攻击（参见第 19 章抗量子扩展）。

---

# 第 15 章 推荐算法（Recommended Algorithms）

## 15.1 原语清单

PCA 不发明新的密码算法。PCA 推荐采用当前已经广泛验证的现代密码算法。

| 对象 | 推荐算法 |
| :--- | :--- |
| Master Secret | 512-bit Random |
| HKDF | HKDF-SHA-512 |
| Identity | Ed25519 |
| Vault Encryption | XChaCha20-Poly1305 |
| File Encryption | XChaCha20-Poly1305 |
| Bitcoin Wallet | BIP32 (HD Wallet) |

---

# 第 16 章 协议迁移（Protocol Migration）

PCA 支持协议长期演进。

新的协议版本可以在保持信任连续性的前提下逐步替代旧版本。

## 16.1 协议迁移与 Namespace 迁移的边界

协议迁移是指 PCA 规范本身的升级，例如算法套件、序列化格式、证书字段、验证规则或基础设施信任锚的演进。协议迁移 **MUST** 由 `Identity/V1/PCA` 基础设施身份签发的新协议规范、迁移声明或软件升级包建立信任连续性。

Namespace 迁移是指在 Master Secret 泄露或同等级灾难事件后，废止旧 Namespace 并以全新 Master Secret 建立全新 Namespace 的过程。Namespace 迁移 **MUST** 由第 17 章定义的紧急废止声明触发，并受第 5 章的 Namespace 生命周期规则约束。

协议迁移与 Namespace 迁移是两个独立概念：

- 协议版本升级 **MUST NOT** 被表示为紧急废止声明。
- 紧急废止声明 **MUST NOT** 被用作发布普通协议升级的机制。
- `Identity/V1/PCA` 签发的新协议规范可以定义新算法或新格式，但 **MUST NOT** 复活、覆盖或缩小已经生效的 Namespace 废止结果。
- 废止声明可以提示存在后继 Namespace，但该提示 **MUST NOT** 被解释为协议迁移，也 **MUST NOT** 使验证端自动信任新 Namespace。

## 16.2 信任连续性

例如：

```text
Identity/V1/PCA
        │
        ├────────────── Sign ──────────────► PCA-v2 Protocol Trust Anchor
        │
        └────────────── Sign ──────────────► PCA-v3 Protocol Trust Anchor
```

新的协议信任锚 **MUST** 由上一代受信任的 `Identity/V1/PCA` 或其已签发的迁移身份进行签名。

验证新的协议版本时，实现 **MUST** 验证完整的基础设施信任链，并确认迁移声明适用于当前实现支持的协议范围。

协议升级期间：

- 新旧协议 **MAY** 长期共存。
- 已有 Identity 不需要立即迁移。
- 新创建的 Identity **SHOULD** 使用新的协议版本。
- 若新协议仍在同一 Namespace 下运行，废止状态仍由该 Namespace 的废止声明决定。
- 若新协议要求使用全新 Namespace，该动作属于 Namespace 迁移，验证端 **MUST** 按第 5 章和第 17 章处理，不得因协议升级签名而自动继承旧 Namespace 的信任状态。

---

# 第 17 章 紧急废止机制（Emergency Revocation）

## 17.1 废止密钥的独立生成与保存

如第 4.3 节所述，实现 **MUST** 在初始化时生成一对独立的 Ed25519 紧急废止密钥对。

- **废止私钥** **MUST** 与 Master Secret **物理隔离保存**（如存放于不同保险柜或由不同受托人保管）。
- **废止公钥** **MUST** 在验证端预先配置（硬编码于可执行文件或受信任的安全更新包中），并通过代码签名机制确保其完整性与来源可信。

> **设计意图**：废止密钥独立于 Master Secret 派生体系之外。即使攻击者完全控制了 Master Secret，只要废止私钥未被同时获取，合法所有者依然能通过废止声明宣告整个体系失效，实现“最终断尾求生”。

---

## 17.2 废止声明（Revocation Statement）的格式与作用域

废止声明 **MUST** 采用 **RFC 8785（JCS）** 序列化的 JSON 格式：

```json
{
  "version": 1,
  "namespace": "PCA-v1/<NamespaceID>",
  "revoked_at": "2026-07-03T10:00:00Z",
  "reason": "Master Secret Compromised",
  "successor_namespace_hint": "Optional: PCA-v2/3F8A..."
}
```

`successor_namespace_hint` 为 **OPTIONAL** 字段，仅用于提示验证端存在可能的后继 Namespace。该字段 **MUST NOT** 被解释为新 Namespace 的信任锚，也 **MUST NOT** 触发自动导入、自动切换或自动信任。

### 17.2.1 作用域强制绑定（Namespace Scope Binding）

- `namespace` 字段为 **MUST**。该字段指定了本废止声明**唯一且全部**的作用域。
- 废止私钥本身不代表任何命名空间（Namespace），但每一份废止声明 **MUST** 明确绑定一个特定的 `namespace` ID。
- 验证端在接收到废止声明后，**MUST** 首先检查 `namespace` 字段是否与当前运行环境所信任的 Namespace ID 一致。若不一致，验证端 **MUST** 立即忽略该声明，不得执行任何后续检查或生效操作。
- 废止声明对该 `namespace` 下的**所有协议版本（V1、V2……Vn）** 同时生效。废止密钥不绑定 `min_version` 或 `max_version`。

### 17.2.2 废止后的合法重建路径

一旦当前 Namespace 被合法废止（即所有者确认 Master Secret 泄露并签署废止声明），**该 Namespace ID 永久死亡，不可逆转**。

若所有者希望重建密码学体系，**MUST** 执行以下流程：

1. 生成**全新的 Master Secret**（512-bit CSPRNG）。
2. 申请并注册一个**全新的 Namespace ID**（如 `PCA-v2/3F8A...`，详见第 5 章《命名空间》）。
3. 在新 Namespace 下派生新的 `IdentityRoot` 及全部子身份。
4. 通过带外方式（如当面交换、安全邮件）将新 Namespace 的信任锚分发给关键验证方。

> 废止声明的生效范围、命名空间的永久死亡以及重建流程，均受第 5 章《命名空间》中定义的生命周期规则约束。

---

## 17.3 废止声明的广播与分发

废止声明 **SHOULD** 通过以下多渠道方式广播，以对抗网络分区或单点故障：

- 上传至域名根目录下的 `/.well-known/pca/revocation.crl`（具体托管与拉取流程见第 18 章）。
- 在个人网站、社交媒体、邮件列表、PGP 密钥服务器等公开渠道同步发布。
- 必要时，可通过公证机构或区块链时间戳服务固化废止声明的发布时间，以证明废止操作的时效性。

---

## 17.4 验证端检查流程（含 Namespace 前置校验）

所有兼容 PCA 的验证端（邮件客户端、验证服务、文件解密工具）**MUST** 按以下**严格顺序**执行废止检查：

1. **命名空间匹配（Namespace Match）**：
   - 从废止声明中提取 `namespace` 字段。
   - 将其与本地硬编码或持久化信任的 Namespace ID 进行比对。
   - 若 **不一致**，验证端 **MUST** 立即终止检查，忽略该声明，并视为未发生废止事件。

2. **签名有效性验证（Signature Verification）**：
   - 使用**硬编码的紧急废止公钥**（见 17.1 节）验证 JCS 序列化后的 JSON 字节流（剔除 `signature` 字段）的 Ed25519 签名。
   - 若签名无效，**MUST** 拒绝。

3. **生效时间检查（Optional）**：
   - 验证端 **MAY** 检查 `revoked_at` 时间戳。若该时间晚于验证端的当前可信时间（如通过 NTP 同步），验证端 **SHOULD** 发出警告，但建议不以此作为唯一拒绝理由，以防时钟偏差攻击。

4. **信任迁移引导（Migration Guidance）**：
   - 若以上检查全部通过，验证端 **MUST** 拒绝该 Namespace 下的所有后续操作（包括新签名、新文件解密）。
   - 若 `successor_namespace_hint` 字段存在，验证端 **SHOULD** 以醒目方式提示用户存在后继 Namespace 线索，但 **MUST NOT** 自动导入、自动切换或自动信任该 Namespace。新 Namespace 的信任锚 **MUST** 通过带外方式或其他明确受信任的渠道建立。

---

## 17.5 废止密钥与协议版本的关系澄清

- 废止声明作用于 **Namespace 生命周期**，而非协议版本号。
- 合法所有者**不依赖**升级协议版本（如 V1 → V100）来回避废止声明。因为废止声明不包含 `max_version`，对同一个 Namespace 下的所有历史及未来版本均有效。
- 若所有者希望摆脱已泄露的旧 Master Secret 带来的废止风险，唯一合法路径是**迁移至全新的 Namespace ID**（见 17.2.2），而非修改协议版本号。
- 协议迁移由 `Identity/V1/PCA` 签发的新协议规范或迁移声明完成；Namespace 迁移由紧急废止声明触发。二者 **MUST NOT** 混用。

---

# 第 18 章 域名绑定与外部辅助发现（Domain Binding & External Discovery）

本章机制仅适用于非 PCA 原生节点，或首次建立信任的外部实体。对于已经通过硬编码锚点、带外导入或其他可信方式建立信任的节点，本章所有机制均为 **OPTIONAL**。

本章中的 DNS 与 HTTPS 发现机制 **MUST NOT** 用于 PCA 内部授权校验，**MUST NOT** 替代证书链签名验证，也 **MUST NOT** 成为 Vault、Generation、CRL、软件升级或协议迁移流程的信任来源。

## 18.1 DNS TXT 记录绑定公钥哈希

为了在不暴露个人身份的前提下，证明某个域名属于特定的 PCA 身份，域管理员 **SHOULD** 在其 DNS 中发布 TXT 记录。

格式如下：

```text
_pca.example.com. 3600 IN TXT "pca-binding=<SHA-256(IdentityYYYY_Public_Key).HEX>"
```

验证者流程：

1. 获取发件人域名（如 `example.com`）。
2. 查询 `_pca.example.com` 的 TXT 记录。
3. 若记录的哈希值与发件人提供的公钥哈希匹配，则可以将该结果作为外部辅助发现信号。

DNS 查询结果仅表示域名所有者发布了某个公钥哈希。验证者 **MUST** 继续执行数学签名验证，并 **SHOULD** 通过带外方式确认父级身份是否可信。

**匿名性**：验证者仅获得公钥哈希，无法关联到具体个人姓名。

## 18.2 撤销列表托管路径

所有兼容 PCA 的实现 **SHOULD** 在如下路径托管撤销列表：

```text
https://<your-domain.com>/.well-known/pca/revocation.crl
```

该文件 **MUST** 为 UTF-8 编码的 JSON 格式。

## 18.3 CRL JSON 格式与签名规范

```json
{
  "version": 1,
  "issued_at": "2026-07-03T00:00:00Z",
  "signer_path": "Identity/V1/PCA",
  "revoked_identifiers": [
    "SHA-256(EmailID_1)",
    "SHA-256(EmailID_2)",
    "DeviceFingerprint_HASH",
    "ElectionID_HASH"
  ],
  "signature": "Base64_Ed25519_Signature"
}
```

- **序列化**：整个 JSON 对象（不含 `signature` 字段）**MUST** 使用 **RFC 8785（JCS）** 进行序列化。
- **签名计算**：对 JCS 序列化后的字节流进行 Ed25519 签名。
- **签名者路径**：`signer_path` **MUST** 是 PCA 内部 Identity 路径，且 **MUST** 为 `Identity/V1/PCA` 或其签发的专用撤销子身份。
- **验证**：验证者 **MUST** 使用 `signer_path` 对应的公钥验证 `signature` 字段，并继续验证该公钥是否可回溯至硬编码的 `Identity/V1/PCA` 信任锚。

## 18.4 验证端 CRL 检查流程

验证者 **MUST** 按以下顺序执行 CRL 检查：

1. **拉取**：从 `https://<domain>/.well-known/pca/revocation.crl` 拉取 CRL 文件。该 URL 仅用于文件发现和传输，**MUST NOT** 被解释为授权绑定。
2. **签名有效性校验**：使用 RFC 8785 重新序列化 JSON（剔除 `signature` 字段），并用 `signer_path` 对应的公钥验证 Ed25519 签名。若签名无效，**MUST** 拒绝。
3. **链式验签**：若签名有效，验证端 **MUST** 进一步向上回溯该公钥的证书链，直至硬编码的 `Identity/V1/PCA` 信任锚。若无法回溯或锚点不匹配，**MUST** 拒绝此 CRL。
4. **黑名单命中检查**：检查目标标识符是否存在于 `revoked_identifiers` 列表中。

CRL 验证流程 **MUST NOT** 查询 DNS，也 **MUST NOT** 使用 DNS TXT 记录中的哈希值作为 CRL 签名者授权依据。

---

# 第 19 章 后续可扩展方向（Future Extensions）

PCA 在保持协议兼容性的前提下，可以持续扩展新的能力。

未来可考虑加入：

- **Master Secret 分片备份（RECOMMENDED）**：采用 Shamir Secret Sharing（如 SLIP-0039）将 Master Secret 切分为 3-of-5 分片。
- **Multi-device Synchronization**：多设备同步与状态管理。
- **Hardware Security Module**：HSM 集成。
- **YubiKey Integration**：FIDO2/WebAuthn 绑定。
- **Post-Quantum Cryptography**：抗量子密码算法（如 Kyber / Dilithium）。
- **Zero-Knowledge Identity**：零知识身份证明。
- **Audit Log**：审计日志。

新增能力应尽可能采用新增 Branch、新增 Path 或新增 Protocol Version 的方式扩展。已有 Canonical Info Path 的语义 **MUST NOT** 被修改。

---

# 附录 A：设计哲学（Design Philosophy，非规范性）

本附录不属于协议规范，仅用于说明 PCA 的设计理念。

PCA 的核心思想可以概括为以下几个原则：

- Single Root of Trust
- Deterministic Recovery
- Separation of Responsibilities
- Minimal Persistent Secrets
- Capability Isolation
- Long-term Evolvability

整个系统只有一个永久保存的 Master Secret。其余绝大部分密钥均可通过 HKDF 确定性恢复。

PCA 并不追求减少密钥数量，而是追求减少需要长期保存的密钥数量。

Identity、Generation、Vault 分别承担公开信任、秘密生成、秘密保护三种职责。三者互相独立，不共享职责。

---

# 附录 B：PCA 与 BIP32 的兼容与扩展关系（规范性附录）

## B.1 设计同源性

PCA 与 Bitcoin BIP32（Hierarchical Deterministic Wallets）共享相同的密码学根基：单一种子（Single Seed）驱动的确定性层级密钥树。两者均利用 512-bit HMAC 类算法实现无限深度的密钥派生。

## B.2 差异与优势互补

| 特性 | BIP32 | PCA（本协议） |
| :--- | :--- | :--- |
| **路径语义** | 纯数字索引（如 `m/44'/0'/0'`） | 人类可读 ASCII 路径（如 `Identity/V1/Personal`） |
| **硬化派生** | 原生强制支持（`'` 后缀） | PCA 可为 Bitcoin 应用生成符合 BIP32 标准的 64 字节种子 |
| **隐私模型** | Xpub 泄露导致所有地址可被关联 | 临时身份 + PGP 延迟绑定，实现事中匿名 |

---

# 附录 C：PGP 交叉签名格式规范（用于延迟绑定，规范性附录）

## C.1 临时公钥的 PGP 证书结构

临时公钥 **SHOULD** 被封装为标准的 OpenPGP 传输公钥包（Transferable Public Key）。

## C.2 父级身份签名包的构造

父级身份（如 `Personal/Identity2026`）为临时公钥签发签名时，**MUST** 使用 **RFC 4880 定义的 `0x18`（子密钥绑定签名）** 或 `0x10`（通用认证签名）类型。

签名包中 **MUST** 包含以下子包（Subpackets）：

- `Issuer Fingerprint` (Subpacket 33)：指明签发者身份。
- `Signature Creation Time` (Subpacket 2)：签名时间。
- `Key Flags` (Subpacket 27)：指明该签名用于认证目的。

## C.3 验证者的标准 PGP 验证流程

验证者 **MUST**：

1. 使用标准 OpenPGP 库解析签名包。
2. 手动导入或选择已经通过带外方式信任的父级公钥。
3. 验证签名链：临时公钥 <- 父级签名 <- 父级公钥信任链。
4. 若父级公钥通过信任检查，则确认归组有效。

该流程与全球 PGP 生态完全兼容，无需特殊实现。PCA 协议不要求邮件客户端自动发现、自动拉取或自动解析延迟绑定证明。
