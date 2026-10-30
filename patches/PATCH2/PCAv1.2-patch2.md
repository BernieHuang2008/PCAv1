# Personal Cryptographic Architecture（PCA）Protocol Specification

**Version:** v1.2
**Status:** Draft
**Date:** 2026-08-14

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

```
TrustRootKey = HKDF-SHA-512(
  IKM  = Master Secret,
  salt = Namespace ID,
  info = "PCA/V1/TrustRoot",
  L    = 64
)
```

并且 `PCA/V1/TrustRoot` 是保留 Canonical Info Path，不得用于 Identity、Generation、Vault、CRL、migration 或应用自定义节点。

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
Master Secret                     Emergency Revocation Key
(512-bit Random)                    (Standalone Ed25519)
        │
        ▼
TrustRootKey
(HKDF-SHA-512)
        │
        ├──────────────────────────┬──────────────────────────┐
        │                          │                          │
        ▼                          ▼                          ▼
     Identity                  Generation                   Vault
(私钥永不公开，公钥绝对保密)
        │                          │                          │
        │                          ├── PasswordManager        └── PermissionNode...
        │                          ├── Bitcoin/Mainnet            └── PerFileKey
        │                          └── ...
        │
        │
        │
        │
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

# 第 4 章 Three Root-Level-Keys

**PCA** 的设计中，有三个最重要密钥，它们共同构成了“Root-Level”，即根层级：
- Master Secret
- Trust Root
- Emergency Revocation Key

Master Secret 和 Trust Root 的所有者拥有当前 PCA 实例的 **完全控制权限**；而 Emergency Revocation Key 的所有者则可以 **使整个实例失效**。
有关这三者的详细资料参见本章的三个小节。

这三个密钥共同构成了 PCA 的 “Root-Level”，即“根层级”。任何一个的泄漏均会对实例造成不可估量的影响。因此我们建议，对这三者实行 **最为严格** 的保密措施，并且遵守本章的所有建议。

## 4.1 Master Secret（主密钥）

Master Secret 是 PCA 体系的主密钥，**仅用于** 派生 Trust Root。
拥有 Master Secret 即可派生出 Trust Root，从而派生出 HKDF Tree 中的任意节点，获取对 PCA 实例的 **完全控制权限**。

### 4.1.1 Master Secret 的生成

Master Secret **MUST** 是使用密码学安全随机数生成器（CSPRNG）生成的 **512-bit** 随机数。

### 4.1.2 Master Secret 的保存

Master Secret 是整个 PCA 唯一需要永久保存的秘密。

Master Secret **MUST** 永远离线保存，不参与任何业务操作，仅用于恢复整个密钥体系。

建议保存方式包括：

- 金属助记板
- HSM
- 多份异地备份
- 银行保险柜

Master Secret **MUST NOT** 联网。

Master Secret 一旦泄漏，攻击者将能够恢复整个 PCA 的全部密钥体系。因此，Master Secret 的保护等级应 **高于任何其他密钥**。

## 4.2 Trust Root

Trust Root 是 HKDF Tree 的根节点，由 Master Secret 通过 HKDF-SHA512 算法生成。拥有 Trust Root 即可派生出 HKDF Tree 的所有节点，拥有对 PCA 实例 的 **完全控制权限**。

### 4.2.1 Trust Root 的生成

Trust Root 由 Master Secret 通过 HKEF-SHA512 算法生成，并以 `PCA/V1/TrustRoot` 作为其 Canonical Info Path。

生成 Trust Root 的伪代码如下：
```
HKDF-SHA-512(
	len  = 64 (Bytes)
	IKM  = Master Secret
	salt = Namespace  (Encode using UTF-8)
	info = "PCA/V1/TrustRoot"  (Encode using UTF-8)
)
```

### 4.2.2 Trust Root 不应被保存

Trust Root 是一个中间密钥，不应被保存在 **任何介质** 中，包括但不限于内存、硬盘、纸张、助记板。

使用时，Trust Root 应现场由 Master Secret 推导，并在派生 Identity, Generation, Encrypt 三个子分支的跟密钥后立刻销毁，避免长时间保存。

## 4.3 Emergency Revocation Key（紧急废止密钥）

在生成 Master Secret 的同一时刻，实现 **MUST** 额外生成一对独立的 **紧急废止密钥（Emergency Revocation Key）**，算法为 Ed25519。

- **生成要求**：必须使用独立的 CSPRNG 随机数生成，**不得**从 Master Secret 派生。
- **保存要求**：该密钥的私钥 **MUST** 与 Master Secret **物理隔离保存**（例如存放在不同的保险柜或由不同的受托人保管）。
- **公钥分发**：该公钥 **SHOULD** 被硬编码（内嵌）在验证端软件的可执行文件或受信任的更新配置包中，并通过代码签名（Code Signing）机制确保其完整性与来源可信。

紧急废止密钥的作用为，在 Master Secret 或重要节点泄漏时宣布协议失效，终止外界对 PCA 体系的信任 的一种止损方法。

有关紧急废止机制，参见 [[#第 17 章 紧急废止机制（Emergency Revocation）]]。

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

## 6.1 HKDF 派生

PCA v1.2 规范中，使用 HKDF-SHA-512 算法，并使用以下参数派生子节点：

```text
HKDF-SHA-512(
	len  = 64 (Bytes)
	IKM  = Parent Key
	salt = Namespace (Encode using UTF-8)
	info = Canonical Info Path (Encode using UTF-8)
)
```

其中：

- `len` 表示 HKDF 生成的长度。固定为 64 字节（512 bits）
- `IKM` 表示父密钥（父节点）。
- `salt` 表示 PCA 协议命名空间（包括前缀）。形如：`PCA-v1/<32 Uppercase HEX>`
- `info` 表示唯一上下文。

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
Generation/V1/PasswordManager
Generation/V1/Bitcoin/Mainnet
Vault/V1/Root
```

Canonical Info Path **MUST** 保持稳定。

一旦某一路径被定义，其语义 **MUST NOT** 被修改。

未来如需变更语义，应创建新的路径（如使用 `V2` 版本段），而不是修改已有路径。

## 6.3 确定性输出长度规范表（Normative Output Lengths）

不同用途的密钥对 HKDF 输出字节的长度要求不同。实现 **MUST** 严格遵守下表规定的截取或使用规则：

| 用途（Purpose）               | 路径示例                         | 所需字节数     | 具体规则                                                                          |
| :------------------------ | :--------------------------- | :-------- | :---------------------------------------------------------------------------- |
| **Ed25519 私钥**            | `Identity/.../Email/...`     | **32 字节** | 取 HKDF 输出的**前 32 字节**，作为 Ed25519 的私钥（private key）。                            |
| **XChaCha20-Poly1305 密钥** | `Encrypt/.../Vault/...`      | **32 字节** | 取 HKDF 输出的**前 32 字节**作为对称加密密钥。                                                |
| **BIP32 主种子**             | `Encrypt/.../Generation/...` | **64 字节** | 取 HKDF 输出的**完整 64 字节**，直接作为 BIP32 的 Master Seed（HMAC-SHA512 原生接受 512-bit 输入）。 |
| **SHA-256 指纹/哈希**         | 撤销列表、证书指纹                    | **32 字节** | 标准 SHA-256 输出。                                                                |

## 6.4 确定性密钥树生成逻辑

每一级节点均由上一层节点通过 HKDF 派生。且每级 Canonical Info Path **MUST** 拥有对应的节点，例如：
- ".../A/B/C" **MUST** 由 ".../A/B" **直接派生** （使用 `IKM=<node at B>`，`info=".../A/B/C"` 等参数）
- ".../A/B/C" **MUST NOT** 由 ".../A" **直接派生**

因此，只要拥有 Master Secret，即可按照完全一致的路径重新恢复整个密钥体系。

PCA 不需要长期保存整个密钥树。除 Master Secret 外，其余所有密钥均可在需要时重新计算。

## 6.5 HKDF‑Stream 流式生成规范（用于确定性字节流）

某些确定性算法（如密码桶混洗、Fisher‑Yates 洗牌）需要按顺序消费**无限长度的确定性随机字节流**。本规范定义了一种基于 `HKDF-Extract` 和 `HKDF-Expand` 算法的惰性分块生成方法，确保跨平台、跨设备的一致性。

### 6.5.1 核心原则

- **全局顺序性**：所有需要随机字节的操作（如字符选取、数组洗牌）**MUST** 严格按照顺序从该流中消费字节。
- **字节粒度**：所有读取操作**MUST** 以字节（8‑bit）为单位，禁止按位偏移或跨字节位拼接。例如：步骤1使用了第1-19个字节，则无论步骤1是否用完完整的字节，步骤2 **MUST**从第20个字节开始使用，**MUST NOT**从第19个字节的第3bit开始。
- **惰性生成**：由于拒绝采样可能导致理论消耗量无上限，实现 **SHOULD NOT** 预先分配固定大小的缓冲区。
- **无缝衔接**：HKDF-Stream对外暴露的字节流应该是无缝的，虽然内部以 block 为单位生成字节流，但是外部调用HKDF-Stream时不应受到block的限制，可以将HKDF-Stream视为连续的、无限长的字节流。

### 6.5.2 HKDF-Extract 和 HKDF-Expand

有关HKDF-Extract 和 HKDF-Expand算法的具体定义和伪代码，请参照 RFC 5869中的描述。
本节仅对其参数（函数签名）及该算法在PCA中的表述进行规范。

函数签名如下：
```
HKDF-Extract(salt, IKM) -> PRK
HKDF-Expand(PRK, info, L) -> OKM
```

### 6.5.3 HKDF-Stream(IKM, CanonicalInfoPath)

基于前文提到的 HKDF-Extract 和 HKDF-Expand 算法，本节提出一种新的“字节流”生成算法，用于某些需要确定性随机字节流的场景。

首先需要使用 HKDF-Extract 计算PRK，方法如下：
```
PRK = HKDF-Extract(
  IKM = Parent Key 
  salt =  <Namespace ID>
)
```
- `IKM`：由HKDF-Stream的入参指定，一般为当前密码生成上下文中的父密钥（例如 `PasswordRootKey`，见 11.4.2）
- `salt`：需符合 第 6.1 节中的规范，使用完整的Namespace ID作为盐值。

字节流由连续的块组成，每个块通过 `HKDF-Expand` 独立生成，**必须**按以下方式构造：

```text
Stream_Block_i = HKDF-Expand(
    PRK  = PRK,
    info = CanonicalInfoPath + "/Block" + i,
    L    = 256
)
```

- **`PRK`**：PRK calculated in the previous step。
- **`info`**：PRK所用IKM的完整 CanonicalInfoPath，后接 `/Block` 与块序号 `i`（十进制，无前导零）。  
  示例：  
  `Generation/V1/PasswordRoot1/8E.../Block0`  
  `Generation/V1/PasswordRoot1/8E.../Block11`
- **`L`**：固定为 `256` 字节（使用 SHA‑512，符合 RFC 5869）。

### 6.5.4 块序号与状态维护

- 块序号 `i` 从 `0` 开始，按需递增（当前块字节耗尽时，自动请求 `i+1` 块）。
- 每次**新的密码生成过程**起始时，消费位置**必须**重置为 `Block 0` 的起始位置，以保证可重现性。
- 实现**必须**确保 `Block i` 的最后一个字节之后紧跟 `Block i+1` 的第一个字节，无截断、无跳过、无重复。
- 实现**必须**以状态机方式维护当前消费位置（当前块索引及块内偏移量）。

> **说明**：该流生成规范适用于所有需要确定性随机字节的场景，包括但不限于第 11.4.4 节中的桶内选字符、补齐字符以及 Fisher‑Yates 洗牌。

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

任何涉及数字签名的 JSON 数据结构（包括但不限于撤销列表 CRL、证书元数据、密码生成配置等），其序列化 **MUST** 遵循 **RFC 8785（JSON Canonicalization Scheme，JCS）**。

具体要求如下：

1. **格式规范**：
   - 无额外空格、无换行符。
   - 使用双引号包裹键名和字符串值。
   - 键名按照字典序（ASCII 码顺序）排列。
   - 转义规则严格遵循 RFC 8785。

2. **Unicode 预归一化（Pre‑normalization）**：
   - JCS 本身不定义 Unicode 归一化。为确保跨平台（特别是 macOS 默认 NFD 与 Linux/Windows 默认 NFC 之间的差异）的字节级确定性，**所有包含人类可读文本的 JSON 字符串值**（例如用户名、域名显示部分、证书持有者名称等）**MUST**，在赋值给 JSON 对象并传入 JCS 序列化器之前，先转换为 **Unicode 规范化形式 C（Normalization Form Composition，简称 NFC）**。
   - **执行顺序**：实现 **MUST** 遵循 `原始输入 → NFC 归一化 → 作为JSON相应字段的值 → JCS 序列化` 的严格顺序。
   - **实现约束**：**MUST NOT** 依赖 JSON 库或 JCS 库内部的隐式归一化（大多数库并不提供此功能）；归一化 **MUST** 由应用层作为显式的预处理步骤完成。
   - **例外情况**：对于仅包含 ASCII 字符（`U+0000` - `U+007F`）的字符串，NFC 归一化操作是幂等的（无变化），实现可跳过处理以提升性能，但结果必须等价。

3. **后续用途**：
   - 后续用途 **MUST** 先对 JSON 序列化之后的 **字符串** 进行 **UTF-8编码** 后，再对 **字节流** 进行操作，**MUST NOT**修改编码或字节。
   - 对于签名计算任务，**MUST** 对经过上述**完整流程**（格式规范化 + Unicode 归一化）序列化后的字节流（UTF-8 编码）直接进行签名（如 Ed25519）。
   - 验证端 **MUST** 使用完全相同的流程重新生成字节流以验证签名。
   - 其他情况下，建议可以先对字节流计算 SHA-256，然后使用SHA-256替代JSON字节流以避免编码问题。

## 7.4 路径分隔符与大小写敏感性

重申：路径分隔符为 `/`，所有路径大小写敏感。

---

# 第 8 章 Identity, Generation, Vault 三个子分支

## 8.1 三个分支的区别

在 TrustRoot 之下，整棵树被分为三个子分支，职责分明 **互不相交** ：
- `Identity` 负责建立信任。包括但不限于 建立数字身份、进行邮件签名、管理 PCA 体系内的 CRL 等信任问题。注意：**Identity 分支不能用于加密**！
- `Generation` 负责生成确定性的秘密。例如：派生出比特币钱包、生成网站密码等。推荐尽可能多地使用 Generation 生成密码等，以维持 PCA 体系”确定性“的哲学和设计初衷。
- `Vault` 负责保存（加密）秘密。例如：保存 TOTP 密钥、保存 API Key 、加密文件等不能由 Generation 生成的秘密。

## 8.2 分支根节点 的生成

分支根节点由 Trust Root 直接派生，使用以下 Canonical Info Path：
```text
PCA/V1/<Branch>
```

并按照 [[#6.1 HKDF 输入]] 的标准操作从 Trust Root 派生。随后即可作为分支根节点，派生子分支。

三个分支根节点的 Canonical Info Path 分别为：

| 分支         | Canonical Info Path |
| :--------- | ------------------- |
| Identity   | `PCA/V1/Identity`   |
| Generation | `PCA/V1/Generation` |
| Vault      | `PCA/V1/Vault`      |

## 8.3 继续派生分支

生成 分支根节点 之后，可以继续派生子节点。

例如，`PCA/V1/Identity` （Identity 分支根节点）可以 **直接派生** `Identity/V1/XXX`。

---

# 第 9 章 Identity Branch（身份分支）

Identity Branch 用于建立公开信任关系（Public Trust）。

PCA v1.2 版本中，如无特别说明，签名算法默认使用：

```text
Ed25519
```

## 9.1 IdentityRoot 与 特殊身份 “PCA”

IdentityRoot 长期离线保存（或删除，并在需要时由 Master Key 推出），仅负责签发 `PCA` 基础设施身份与 Persona。

IdentityRoot 的私钥 **MUST** 永不公开。为避免外部观察者通过根公钥关联 `Personal`、`Work`、`Alice` 等身份分支，IdentityRoot 的公钥默认也 **SHOULD NOT** 公开发布。

`Identity/V1/PCA` 是 PCA 基础设施身份。所有兼容 PCA 的实现 **MUST** 硬编码该身份的公钥及完整 Canonical Path，并将其作为内部校验流程的最高信任锚点。`PCA` 身份 **MUST NOT** 用作个人、工作、邮件或其他外部公开身份。
更多有关 `Identity/V1/PCA` 身份的介绍，参见 [[#9.4 内部验证模型]] 。

## 9.2 多重身份与 Persona

### 9.2.1 多重身份

PCA v1.2 协议支持创建若干 **相互独立** 的不同身份，称为 **Persona** 。

每个 Persona 表示一个 **逻辑身份空间**，其命名并不代表真实身份的名字。

例如：

```text
Alice
Bob
```

**注意**：Persona 可以任意命名，但需要遵守 [[#6.2 Canonical Info Path]] 的驼峰命名等规则，并且 **MUST NOT** 为 `PCA` （这是预留的，用于内部 Identity）。

不同 Persona **SHOULD** 被视为互相独立的公开身份。

### 9.2.2 Persona 的子节点

每个 Persona 节点可以继续签发 **子 Identity** ，例如：
- 每年签发新的 Identity 以进一步加强安全性。（e.g. `Identity2026`）
- 区分不同的工作/信任空间。（e.g. `Work`, `Personal`）

**子 Identity** 的节点命名具有语义灵活性，例如以下命名都是合法的：
```text
Alice
 ├── Identity2026
 ├── Work
 ├── Work2026
 └── IdentityLongTerm
```

每个 **子 Identity** 节点可以继续签发各种 **用途身份** ，例如：

- `Laptop`
- `Phone`
- `CodeSigning`
- `EmailCa`

派生路径示例：

```text
Identity/V1/Alice/Identity2026/Laptop
Identity/V1/Alice/Work/CodeSigning
```

## 9.3 外部验证模型 与 证书链

PCAv1 标准本质上是一颗确定性派生的 HKDF Tree。因此 Identity 分支的任意节点均可以参与任何外部验证。例如作为 Ed25519 / PGP 私钥（见：[[#第 10 章 Email Identity（邮件身份与匿名分组）]]）、执行其他任何密码学操作、搭建私有 CA 信任体系、用于其他 RFC 规范等。

但是，不同的 Persona **MUST** 被外部视为完全独立的身份。这一层是预留的，以进行身份隔离、防止追踪。

对于外部公开身份，验证者可以通过逐级验证签名，并以其已经通过带外方式信任的 Persona、Identity 节点或其他公开父级身份作为信任起点。外部验证流程 **MUST NOT** 要求公开 `IdentityRoot` 公钥。

对于 PCA 内部基础设施身份，验证者通过逐级验证签名，最终信任锚为硬编码的 `Identity/V1/PCA` 公钥。

## 9.4 内部验证模型

在执行任何 PCA 操作前， **MUST** 确保 PCA 实例的有效性。即，验证 Emergency Revocation 是否触发。此外，涉及 *Identity 分支* 或 *需要内部信任的操作* 时，**MUST** 先检查 CRL（Certificate Revocation List）并验证 *信任链*。

简而言之，执行任何 PCA 操作前，**MUST** 执行如下步骤：
- 验证 Emergency Revocation （见 第 17 章）
- （部分操作需要）获取并验证 CRL

### 9.4.1 信任锚

任何 PCA 实例 **MUST** 硬编码如下两个信任锚：
- Emergency Revocation PubKey / 紧急废止公钥
- 位于 `Identity/V1/PCA` 的公钥（“PCA 内部信任锚/信任根”）

其中，*紧急废止公钥* 仅用于紧急废止的检验，不用于普通操作。

而 `Identity/V1/PCA` 则负责所有内部校验，作为 PCA 体系的 **唯一信任根** 。注意事项如下：
- 所有内部信任 **MUST** 最终追溯到 `Identity/V1/PCA` ，并使用硬编码的公钥进行校验，方能判定有效。
- `Identity/V1/PCA` 需要被妥善保管，并且 **不直接** 用于信任用途，而是签发 **子证书** 用于办法 CRL 等信任操作。你可以将其比作互联网中的 CA（Certificate Authority）。
- 我们建议 `Identity/V1/PCA` **SHOULD NOT** 拥有进一步的子分支。信任链的证书 **SHOULD** 归属到 **有所有权（e.g. 存储该证书私钥）的真实 Persona/其他 Identity 节点** ，例如 `Identity/V1/Alice/Server2/CRL1` 。

### 9.4.2 信任链

#### 9.4.2.1 节点
内部信任链的 **每一个节点** 由如下 JSON 格式进行描述：
```json
{
	"signed_at": 1786499331,
	"valid_until": 1786600000,
	"purpose": "PCA/CRL",
	"to_path": "Identity/V1/.../to",
	"to_pubkey": "AB2315...",
	"signer_path": "Identity/V1/.../signer",
	"sign_algo": "SHA-256",
	"signature": "0AC4BF..."
}
```

字段解释：

| 字段            | 描述                                                                                                | 格式/标准                        |
| :------------ | :------------------------------------------------------------------------------------------------ | :--------------------------- |
| `signed_at`   | 上一节点签发该节点的时间                                                                                      | 64位 UNIX 秒级时间戳               |
| `valid_until` | 过期时间（`time.now() >=valid_until` 时节点失效）                                                            | 64位 UNIX 秒级时间戳               |
| `purpose`     | 信任链的用途。格式如 `<scope>/<purpose>`。其中，PCA 的保留用途 **MUST** 以 `PCA/`开头，自定义信任链用途 **MUST** 以 `Custom/` 开头。 | str，`<scope>/<purpose>`      |
| `to_path`     | 该节点（signer的下一节点）的 Canonical Info Path                                                             | [[#6.2 Canonical Info Path]] |
| `to_pubkey`   | 该节点的 Public Key。                                                                                  | Uppercase HEX                |
| `signer_path` | 签发者的 Canonical Info Path。**MUST** 属于 **Identity 分支** 且符合 [[#6.2 Canonical Info Path]] 中的规范。       | [[#6.2 Canonical Info Path]] |
| `sign_algo`   | 哈希算法。PCAv1.2 中使用 `SHA-256`                                                                        | "SHA-256"                    |
| `signature`   | 由签发者私钥签署的该 JSON 的 SHA-256 （或者由`sign_algo`字段指定的算法） 哈希值。具体描述见下文。                                    | Uppercase HEX                |

其中，`signature`字段的计算步骤如下：
1. 构造完整的 **节点 JSON** 。
2. 仅去除 `signature` 字段。
3. 将去除后的 JSON 按照 [[#7.3 JSON 签名序列化强制标准]] 序列化为 **字节流**。
4. 使用 `sign_algo` 字段定义的哈希算法，对 第3步 得到的字节流进行哈希。
5. 对 第4步 得到的哈希值进行 Ed25519 签名。
6. 将签名以 Uppercase HEX 形式存储到 `signature` 字段。

其中，对于 `purpose` 字段，有如下保留用途：

| `purpose`         | 用途               | 详细介绍                                    |
| :---------------- | ---------------- | --------------------------------------- |
| `PCA/CR`          | 节点撤销令            |                                         |
| `PCA/CRL`         | 证书撤销列表（CRL）的公开发布 |                                         |
| `PCA/PubkeyTrust` | 公钥认证             | 确认位于 `<to_path>` 节点的公钥内容是 `<to_pubkey>` |

对于保留用途，整条信任链 **MUST** 使用相同的 `purpose`。
对于非保留用途，**MUST NOT** 以 `PCA/` 开头，**MUST** 以 `Custom/` 开头。

#### 9.4.2.2 信任链的 JSONL 表示
信任链推荐使用 JSONL (plain text) 进行传输/存储，格式为：每行一个 JCS 序列化后的 json。
例如：
```jsonl
{"purpose":"PCA/CRL","sign_algo":"SHA-256","signature":"0AC4BF...","signed_at":1786499331,"signer_path":"Identity/V1/.../signer","to_path":"Identity/V1/Alice","to_pubkey":"AB2315...","valid_until":1786600000}
{"purpose":"PCA/CRL","sign_algo":"SHA-256","signature":"23464F...","signed_at":1786499331,"signer_path":"Identity/V1/Alice","to_path":"Identity/V1/Alice/Server2/CRL1","to_pubkey":"67AD33...","valid_until":1786600000}
```

有如下注意事项：
- **MUST** 按照信任链的顺序进行排列。例如信任链为：`A->B->C`，则 JSONL 的顺序也必须为 `A\nB\nC`。也就是说，前一个 json 所描述的节点 *签发* 后一个节点。
- 第一个节点 **MUST** 由 `Identity/V1/PCA` **直接签发**。
- `Identity/V1/PCA` 节点本身不处于信任链中。
- 最后一个节点 **MUST** 为需要证明的节点。例如，想证明`A`拥有某项权限，则最后一个节点 **MUST** 为：A的上一级签发给A的（`to_path`=A）
- 每个节点的权限 **SHOULD** <= 上一个节点的授权。`Custom/`的权限大小根据实际情况，由客户端/签名端自行判断，不属于协议范围。

### 9.4.3 证书撤销列表（CRL）

PCA v1.2 规范中的 CRL (Certificate Revocation List，证书撤销列表) 借鉴了 RFC 5280 规范的 CRL 设计，采用快照式存储+12小时的发布周期。

#### 9.4.3.1 CRL 格式

CRL 由一个 **JCS 序列化后** 的 JSON 对象表示。CRL 的结构如下：
```json
{
    "version": "v1",
    "namespace": "PCA-v1/...",
    "source_id": "<ANYTHING>",
	"this_update": 1786499331,
	"next_update": 1786585731,
	"crl": [
		{
			"revoked_path": "Identity/V1/.../A",
			"revoked_at": 1786499321
		},
		{
			"revoked_path": "Identity/V1/.../B",
			"revoked_at": 1786499311
		},
	],
	"issuer_path": "Identity/V1/.../C",
	"issuer_trustchain": "<JSONL>",
	"hash_algo": "SHA-256",
	"signature": "xxxx"
}
```

字段解释如下，所有字段均为 **MUST** 填写。

| 字段                  | 解释                                                               | 格式/标准                                                          |
| :------------------ | ---------------------------------------------------------------- | -------------------------------------------------------------- |
| `version`           | CRL 版本                                                           | **MUST** 为 `v1`                                                |
| `namespace`         | 当前 PCA 实例 的命名空间                                                  | [[#5.1 Namespace ID]]                                          |
| `this_update`       | 该 CRL 的更新时间                                                      | 64位 UNIX 秒级时间戳                                                 |
| `next_update`       | 下一次 CRL 更新时间（该 CRL 的失效时间）                                        | 64位 UNIX 秒级时间戳                                                 |
| `crl`               | CRL 列表，每一项都代表了一个 **被撤销的节点** （注1）                                 | list[dict]，可为空列表。每一项的格式参见下一张表。                                 |
| `issuer_path`       | CRL 发布者节点的 Canonical Info Path                                   | 参见 [[#6.2 Canonical Info Path]]                                |
| `issuer_turstchain` | CRL 发布者节点的 trust chain                                           | 参见 [[#9.4.2.2 信任链的 JSONL 表示]] 。`purpose` **MUST** 全为 `PCA/CRL` |
| `hash_algo`         | 签名哈希算法                                                           | 目前仅支持 `SHA-256`                                                |
| `signature`         | 数字签名                                                             | Uppercase Hex。签名计算方法参见 [[#9.4.2.1 节点]] 中的计算方法。                 |
| `source_id`         | 此 ”CRL 源“ 的唯一身份标识。**不强制要求唯一** ，但是不唯一可能导致该源不被信任。建议使用域名等可以有意义的字符串。 | 任意 **字符串** 。                                                   |
*（注1）*：撤销一个节点，其子节点自动失效。见下文。

由于 PCA v1.2 采取的 HKDF Tree 的特性，父节点的私钥泄漏后，攻击者可以推断出任意一个子节点。因此，撤销一个节点时，**等同于撤销整颗子树，其子节点自动失效** ！

`crl` 字段的每一项，格式如下：

| 字段             | 解释                                | 格式/标准                           |
| :------------- | --------------------------------- | ------------------------------- |
| `revoked_path` | 被撤销的节点 的 Canonical Info Path      | 参见 [[#6.2 Canonical Info Path]] |
| `revoked_at`   | 撤销时间，计算方法见 [[#9.4.3.2 CRL 服务器规范]] | 64位 UNIX 秒级时间戳                  |

#### 9.4.3.2 CRL 权限范围

CRL 隶属 `Identity` 分支，因此 **MUST** 仅撤销 `Identity` 分支的身份节点，**MUST NOT** 撤销 `Generation` 或 `Vault` 分支的任何节点。

此外，部分根节点 **不可被 CRL 撤销** 。若这些节点被泄漏，**MUST** 立刻进行 *紧急废止* 流程。这些节点的 Canonical Info Path 完整名单如下：
- `PCA/V1/TrustRoot`
- `PCA/V1/Identity`
- `Identity/V1/PCA`

CRL 发布者（或”节点撤销令”发布者）的权威性依赖 *Trust Chain 父节点* 以及 *HKDF Tree* 父节点。因此，CRL **MUST NOT** 撤销：
- 自己所用 Trust Chain 的 **任何父节点**。
- 自己在 HKDF Tree 中的 **任何父节点**。但是可以撤销兄弟节点及其子分支。
例如，若某 CRL 节点位于`A/B/C`，且由 `D->E->C` 的Trust Chain 受到信任，则无权撤销：
- `A` 或 `A/B` 或 `A/B/C`(自己)
- `D` 或 `E`
- `D` 或 `E` 的 **任何父节点**。

#### 9.4.3.3 节点撤销令（CR）

*CRL 服务器* 负责接收“节点撤销令”，并汇总为 CRL（证书撤销列表），对外发布。
而“节点撤销令”则是由 *CR 节点* 向 *CRL 服务器* 发布的 **内部请求**，请求向 CRL 中加入对于某节点的撤销。

需要注意，CRL 对外不会提供 CR 的信息，因此 `CRL` 权限 > `CR` 权限。

节点撤销令 （CR） 请求由如下 JSON 进行描述：
```json
{
	"version": "v1",
	"namespace": "PCA-v1/...",
    "issued_at": 1786499331,
    "issuer_path": "Identity/V1/.../B",
    "issuer_trustchain": "<JSONL>",
    "revoke_path": "Identity/V1/.../A",
    "hash_algo": "SHA-256",
    "signature": "xxxx"
}
```

所有字段均为必填，字段解析如下：

| 字段                  | 解释                                                         | 格式/标准                                                         |
| :------------------ | ---------------------------------------------------------- | ------------------------------------------------------------- |
| `version`           | CR 格式版本                                                    | **MUST** 为 "v1"                                               |
| `namespace`         | 当前 PCA 实例 的命名空间                                            | [[#5.1 Namespace ID]]                                         |
| `issued_at`         | CR 发布时间。仅用于 CRL 服务器 对 CR 进行校验，**不用于 CRL 的 revoked_at 字段！** | 64位 UNIX 秒级时间戳                                                |
| `issuer_path`       | CR 发布者的 Canonical Info Path                                | 参见 [[#6.2 Canonical Info Path]]                               |
| `issuer_trustchain` | CR 发布者节点的 trust chain                                      | 参见 [[#9.4.2.2 信任链的 JSONL 表示]] 。`purpose` **MUST** 全为 `PCA/CR` |
| `revoke_path`       | **一个** 被撤销节点 的 Canonical Info Path                         | 参见 [[#6.2 Canonical Info Path]]                               |
| `hash_algo`         | 哈希算法                                                       | 目前仅支持 `SHA-256`                                               |
| `signature`         | 数字签名                                                       | Uppercase Hex。签名计算方法参见 [[#9.4.2.1 节点]] 中的计算方法。                |

注意：一个 CR 仅能撤销 **一个** 节点，但是该节点的 **所有子节点** 将全部失效。

#### 9.4.3.4 多途径获取 CRL

为了应对不同的网络环境，PCA v1.2 **允许并且鼓励** 客户端从多个服务器获取 CRL。
每个提供 CRL 的服务器或其他途径都被称作 一个 **“CRL 源”** 。

满足以下条件，一个 “CRL 源” 可以被客户端认定为 **“CRL 有效源”**：
- **处于同一 Namespace** ：`namespace` 字段与客户端硬编码的 PCA Namespace 相同。
- **source_id 验证** ：对 `source_id` 字段进行验证，确认该 CRL 是从正确的 ”源“ 发出的。
- **结构完整** ：拥有 [[#9.4.3.1 CRL 格式]] 中定义的完整 JSON 格式，拥有所有字段。
- **签名和信任链有效** ：信任链可以追溯到 `Identity/V1/PCA`，信任链完整且每一环节都没有过期；验证消息内容符合 `signature` 字段的签名。
- **时间有效** ：满足 `this_update` <= `client.now()` < `next_update` 。

注意：”CRL 有效源“ 是由 **客户端** 在每次获取 CRL 时的自主验证的，**MUST NOT** 相信服务端/其他客户端的验证结果。

客户端 **MAY** 在 `next_update` 之前储存从 ”CRL 源“ 获取的数据。若存储，则以下两点中， **MUST** 二选一执行：
- **下次读取前进行完整验证**：下次读取前，完整执行 [[#9.4.3.4 多途径获取 CRL]] 中的检查清单。特别注意检查 **source_id** 字段。
- **加密/签名 存储的数据**：加密/签名 保存的 CRL 内容。加密密钥/签名私钥 的保护级别 **MUST** >= 客户端的修改权限，即攻击者需要修改客户端的代码/逻辑，才能修改密钥。以防止数据被调包。

注意：一个源升级为 ”CRL 有效源“ 并不代表其 CRL 可以被 **直接使用** 。还需进行下一步（冲突处理），CRL 才能交给下游使用。但是，**MUST** 至少有 1 个”有效源“，才能继续进行冲突处理，否则直接返回 无效CRL，并拒绝进行进一步的 PCA 操作。

#### 9.4.3.5 多 ”CRL 有效源“ 的冲突处理

进行冲突处理之前，**MSUT** 确保 **至少有 1 个** ”CRL 有效源“。否则，客户端应直接返回 无CRL，并拒绝执行进一步的 PCA 操作。本节讨论均在”有效源“的前提下进行。

当两个或以上”CRL 有效源“发生如下列举的 **任意** 一种情况时，标记他们为”有冲突“：
1. 两个 ”CRL 有效源“ 拥有相同的 `source_id` 字段。
2. 一个 ”CRL 有效源“ 判定另一个 ”CRL 有效源“ 的签发者（或其父节点，或信任链父节点）无效。
3. 拥有不一致的 CRL 列表。例如 `C` 被 源A 撤销，但是未被 源B 撤销。



#### 9.4.3.4 CRL 服务器规范

CRL 服务器，也就是 CRL 的发布者，需要遵循以下规范：
- **仅信任有效的”撤销令“。**
  信任一个 CR 之前，**MUST** 确认其有效：没有违反 PCA v1.2 协议中的强制规定，且Trust Chain 有效。
- **查询其他 CRL 源**。
  在判断 CR 是否有效前，**MUST** 不仅依赖自身的 CRL 记录，而应在查询其他 “CRL 源” 之后进行 **综合判断**。“综合判断”指 **MAY** 不按照标准客户端的验证步骤，**MAY** 按照管理员的指令 **强制废除/确认** 一个 CR 的有效性。
- **仅信任自己的时间线。**
  为了防止伪造时间戳，CRL 服务器 **MUST** 以自己的时间线为准。例如，`crl` 列表的 `revoked_at` 字段 **MUST NOT** 相信其他服务器提供的时间戳，而是应使用 **收到”撤销令“时刻的本机时间** 。
- **定期更新。**
  为了防止重放攻击，CRL 设计了 `this_update` 和 `next_update` 字段。这两个字段需要被妥善利用。**RECOMMEND** 建议每 12 小时 更新一次。


---

# 第 10 章 Email Identity（邮件身份与匿名分组）

Email Identity 用于建立邮件身份，采用**临时隔离发送**与**事后选择性归组**的设计。

## 10.1 临时邮件身份（Ephemeral Identity）

默认情况下，每封邮件 **MUST** 使用一个**全新的、独立的临时 Ed25519 密钥对**。

派生路径：

```text
Identity/V1/<Persona>/<IdentityNode>/Email/Ephemeral/<RandomEmailId>
```

其中 `<RandomEmailId>` 是一个 256-bit 随机数（Uppercase HEX），一次性使用。

该密钥仅用于签署当前这一封邮件，签署完成后 **SHOULD** 立即从内存中销毁。

> 该设计确保默认情况下，外部观察者无法将多封邮件关联到同一个发件人身份。

## 10.2 延迟绑定（Delayed Binding）策略

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

## 10.3 验证者标准流程

验证者 **SHOULD** 按以下顺序执行检查：

1. 获取临时公钥并验证邮件签名。
2. 检查是否存在独立分发的 PGP 认证签名证明。若存在，使用标准 OpenPGP 库验证父级身份签名链。
3. 若父级身份未被信任，验证者 **SHOULD** 提示用户采用带外方式（Out-of-band，例如当面交换、U 盘拷贝、可信即时通讯）导入父级公钥。
4. DNS 查询（见第 18 章）仅作为 **OPTIONAL** 的外部辅助发现手段，其结果 **MUST NOT** 用于替代数学签名验证或带外信任确认。
5. 若以上均失败，则仅接受为“匿名签名”。

## 10.4 匿名模式说明

默认情况下，PCA 仅提供临时身份私钥用于签名。验证者无法将其关联到特定 Persona 或个人。

发件人拥有是否披露归组证明的完全主动权。

## 10.5 环签名（Ring Signatures）可选增强

为进一步增强发送者匿名性（Unlinkability），实现 **MAY** 支持环签名（Ring Signatures）作为可选扩展。

- 在派生临时密钥时，**MAY** 使用环签名算法（如 CLSAG）替代 Ed25519。
- 环签名允许签名者隐藏在一组公钥中，验证者仅能确认签名来自该集合，无法确定具体成员。
- 当前版本不将环签名纳入 **MUST** 要求，具体实现细节由上层应用自行定义。


---

# 第 11 章 Generation（确定性秘密生成）

Generation 用于生成所有能够确定性恢复的秘密。

## 11.1 通用生成路径

例如：

```text
Generation/V1/PasswordManager
Generation/V1/Bitcoin/Mainnet
Generation/V1/APIKeys/GitHub
```

所有 Generation Key 均由 HKDF 派生。Generation Key 不需要长期保存。

## 11.2 子密钥轮换规范

对于需要版本轮换或衍生多个平行秘密的场景（如每年更换密码管理器主密码），可以通过新增路径层级进行轮换。

例如将 `/2024` 变更为 `/2025`

## 11.3 Bitcoin 钱包派生

PCA 不重新定义 Bitcoin 钱包标准。PCA 仅规定 Bitcoin 根密钥的生成方式。

派生流程如下：

```text
Generation/V1/Bitcoin/Mainnet
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

## 11.4 密码生成（Password Generation）

### 11.4.1 目的与范围

本规范定义了一种从 PCA 主密钥中确定性派生网站登录密码的方法，使用户无需依赖第三方密码管理器、无需跨设备同步密码，即可在不同设备、不同时间重现完全一致的密码字符串。

派生的密码 **MUST** 可重现，**SHOULD NOT** 长期存储，且 **MUST NOT** 用于任何加密目的（如文件加密或数字签名）。

---

### 11.4.2 密码种子根（Password Root）

密码生成的逻辑根路径**必须**为：

```text
Generation/V1/PasswordRoot1
```

注：若 `PasswordRoot1` 泄漏，可更换为 `Generation/V1/PasswordRoot2`，以此类推。

**MUST** 按照第 6 章规定的 HKDF 派生方式，从 `TrustRootKey` 沿此完整路径派生一个 **32 字节**的 `PasswordRootKey`：

```text
PasswordRootKey = HKDF-SHA-512(
  IKM  = HKDF node at Generation/V1,
  salt = Namespace ID,
  info = "Generation/V1/PasswordRoot1",
  L    = 32
)
```

`PasswordRootKey` 将作为生成器的唯一密钥，直接参与密码的确定性生成。

---

### 11.4.3 特定账户密码派生路径

使用以下 JSON 格式的几个字段唯一地描述一个“用户账户”及其配置：

```json
{
    "service": <ServiceIdentifier>,
    "username": <Username>,
    "counter": <Counter>,
    "pwdcharset": <Charset>,
    "pwdlength": <Length>
}
```

**各组成部分的解释与规范化规则**：

1. **`<ServiceIdentifier>`**：
   - 服务唯一标识符，一般情况下是网站域名。
   - **MUST** 将 Unicode 域名按照 IDNA 2008 (RFC 5891) 编码为 ASCII（Punycode），再参与后续的JSON构造。由于 Punycode 仅含 ASCII 字符，无需再执行 NFC 归一化。
   - IPv4 或 IPv6 作为 ServiceIdentifier 时，**SHOULD** 采取国际统一规范。对于 IPv6，**SHOULD** 使用 RFC 3986 定义的带括号格式，如 `"[::1]"`。
   - 携带端口时，**MUST** 使用 `":"` 分割，形如 `<host>:<port>`（例如 `wikipedia.org:8080`，`[fe80::1]:13445`）。
   - 确定性无严格规定，用户应能回忆起相同标识符；若由程序自动提取，**SHOULD** 明确告知用户并允许手动修改。

2. **`<Username>`**：
   - **大小写规范化**：默认 **SHOULD** 转换为全小写（Lowercase），符合大多数网站不区分大小写的实际情况。**MUST** 允许用户保留大小写以应对特殊网站。
   - **Unicode 处理**：若包含 Unicode 字符，**MUST** 先进行大小写转换，再按照第 7.3 节的JSON序列化规范（NFC）进行规范化。

3. **`<Counter>`（轮换计数器）**：
   - **MUST** 为正整数（从 `1` 开始），十进制表示（如 `1`、`2`）。
   - 用于密码轮换（泄露或策略要求），**MUST** 递增计数器，**MUST NOT** 修改域名或用户名来代指新密码。

4. **`<Charset>`（字符集名称）**：
   - **MUST** 取自第 11.4.4.1 节定义的规范名称列表。

5. **`<Length>`（密码长度）**：
   - 必须为正整数，十进制（如 `8`、`20`）。
   - **强制约束**：若 `<Length>` 小于该字符集的桶数量（`B`，定义见第 11.4.4.2 节表 1），**MUST** 在派生前直接拒绝并报错。

**默认参数建议**（若用户未指定）：
- `Charset` = `PRINTABLE-88`
- `Length` = `20`
- `Counter` = `1`

**派生执行步骤**：
- 严格遵循第 7.3 节（JSON 序列化标准）将上述构造的完整 JSON 序列化为UTF-8编码，并取 SHA‑256，再取 Uppercase HEX，得到 `<JSON Hash>`。
- 使用 `PasswordRootKey` 作为父密钥（IKM）。
- 使用当前 PCA 实例的完整 `Namespace` ID 作为盐（Salt）。
- 使用以下字符串作为 `info`：  
  `Generation/V1/PasswordRoot1/<JSON Hash>`  
  例如：`Generation/V1/PasswordRoot1/8E...`
- 执行 `HKDF-SHA-512`，输出长度 `L = 64` 字节，记为 `RawPasswordKey`。

伪代码：

```text
RawPasswordKey = HKDF-SHA-512(
  IKM  = PasswordRootKey,
  salt = Namespace ID,
  info = "Generation/V1/PasswordRoot1/<JSON Hash>",
  L    = 64
)
```

---

### 11.4.4 密码字符集与桶混洗构造算法

#### 11.4.4.1 预定义字符集（规范名称与确切顺序）

实现 **MUST** 支持以下字符集，且 **MUST** 使用大小写等**完全一致**的 ASCII 字符串表示同一个字符集。任何未在列表中定义的 `Charset` 均视为无效，**MUST** 拒绝派生并报错。

- `PRINTABLE-88`
- `BASE-62`
- `BASE-32`
- `BASE-16`
- `BASE-10`

详细字符集定义参见第 11.4.4.2 节表 1。

> **重要**：表内现有字符集及其顺序作为本版本的冻结快照，一经发布即**永久固定**，**不得**修改。未来若需引入新字符集，**必须**通过新增规范名称（如 `PRINTABLE-88-V2`）扩展。

#### 11.4.4.2 桶混洗（Bucket Shuffling）密码构造算法

为实现满足常见复杂度要求（如至少包含一个大写字母、一个小写字母、一个数字和一个特殊符号）的密码，**MUST** 采用桶混洗方法构造最终密码，取代任何简单的直接取模映射。

**算法流程**：

0. **初始化统一随机字节流**：
   后续若有需要用到随机字节流时，**MUST**从**此处**的统一随机字节流中获取。
   统一随机字节流**MUST**使用第 6.5 节中定义的 HKDF-Stream 算法确定性生成，参数如下：
  ```
  HKDF-Stream(
       IKM =  HKDF node at Generation/V1/PasswordRoot1/<JSON Hash>,
       path = "Generation/V1/PasswordRoot1/<JSON Hash>"
   )
  ```

1. **确定字符桶（Character Buckets）**：  
   根据 `<Charset>`，按表 1 将字符集划分为若干个互斥的桶。**MUST** 严格按照该表的划分进行。

   **表 1：各字符集的桶划分规则**

   | `CharsetName` | 桶名称 | 桶内容（源自字符集字符串的子串） |
   | :--- | :--- | :--- |
   | `PRINTABLE-88` | 大写字母 | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` |
   |                | 小写字母 | `abcdefghijklmnopqrstuvwxyz` |
   |                | 数字     | `0123456789` |
   |                | 特殊符号 | `!@#$%^&*()-_=+[]{}|;:,.<>?` |
   | `BASE-62`      | 大写字母 | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` |
   |                | 小写字母 | `abcdefghijklmnopqrstuvwxyz` |
   |                | 数字     | `0123456789` |
   | `BASE-32`      | 字母 | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` |
   |                | 数字 | `234567` |
   | `BASE-16`      | hex 数字（仅一个桶） | `0123456789ABCDEF` |
   | `BASE-10`      | 数字（仅一个桶） | `0123456789` |

   **桶遍历顺序**：**MUST** 按照表 1 中**自上而下**的顺序进行遍历（先列出第一个桶，再第二个，以此类推）。`MandatoryChars` 数组必须按此顺序依次存放每个桶选出的字符，例如 `aba111@*!`。

2. **预检长度约束**：如果 `<Length>` 小于桶的数量 `B`（表 1 中该字符集的桶总数），**MUST** 立即报错并终止派生，错误信息应明确提示所需最小长度。

3. **从每个桶中确定性选取至少一个字符**：  
   设桶的数量为 `B`。**MUST** 从第 6.5 节定义的**统一确定性字节流**中按顺序消费字节。
   - 计算当前桶的长度 `L_bucket`。
   - 使用**拒绝采样（Rejection Sampling）** 消除模数偏差。算法参考 NIST SP 800-90A Rev. 1 第 10.1 节 “Generating a Random Number in a Range”（Simple Discard Method）：
     阈值计算方式为：threshold = floor(256/m) * m，拒绝并丢弃一切 >= threshold的字节。
     实现 **MUST** 将从第 6.5 节字节流输出的每个字节视为无符号 8 位整数（0–255）进行阈值比较，确保跨平台一致性。
   - 选取该桶中的第 `index` 个字符（0‑indexed）。
   - 记录所有选中的字符，组成长度为 `B` 的数组 `MandatoryChars`。

4. **补齐至目标长度**：  
   如果 `B < Length`（记为 `N`），则需从**完整字符集**中再选取 `N - B` 个字符。**必须**继续从第 6.5 节的字节流中按顺序消费字节，使用拒绝采样获取无偏索引并选取字符。将这些字符与 `MandatoryChars` 合并，得到长度为 `N` 的字符数组 `AllChars`。

5. **确定性洗牌（Deterministic Shuffle）**：  
   使用 **Fisher‑Yates 洗牌算法**对 `AllChars` 数组进行确定性置换。置换所需的随机性**必须**继续从第 6.5 节的字节流中按顺序消费（即紧接着第 4 步结束后的位置）。
   - 在洗牌的每次迭代中，使用拒绝采样从流中获取无偏索引 `j`（模数为 `i + 1`）。
   - 伪代码：
     ```text
     function DeterministicShuffle(array, stream):
         for i = len(array) - 1 down to 1:
             j = rejection_sampling(stream, i + 1)
             swap(array[i], array[j])
         return array
     ```

6. **输出密码**：将洗牌后的字符数组连接为字符串，作为最终密码输出。

#### 11.4.4.3 密码强度验证与手动计数器递增

实现 **MAY** 提供密码强度验证功能（如熵值估算），但该验证仅作为用户参考，**MUST NOT** 在用户未手动操作的情况下自动阻止密码输出或自动递增计数器。

- **通报**：每次生成密码后，**MUST** 以清晰、无歧义的方式向用户通报以下信息：
  - 原始规范化后的**人类可读 Domain**（例如 `example.com` 或 `[::1]:8080`）。
  - 原始规范化后的**人类可读 Username**（例如 `alice`）。
  - 使用的 `<Counter>`。
  - 使用的 `<Charset>`、`<Length>`。
  - 若 `Charset` 或 `Length` 为默认值（见 11.4.3），**MAY** 省略显示默认值。

---

# 第 12 章 Vault（外部秘密保护与文件加密）

Vault 用于保存无法重新生成的外部秘密或用于加密文件。

## 12.1 权限树（Permission Tree）架构

整体结构如下：

```text
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
Vault/V1/Finance
Vault/V1/Finance/2026/Q3
Vault/V1/Company1/Department2/User3
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
Vault/V1/<Permission Path>/<File ID>
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

所有使用 `XChaCha20-Poly1305` 执行的加密操作，**MUST** 将待加密文件对应的 **完整 Canonical Info Path**（例如 `Vault/V1/Finance/2026/Q3/5C5F...`）的 ASCII 大端序字节流，作为算法的 **附加认证数据（AAD）** 输入。

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
