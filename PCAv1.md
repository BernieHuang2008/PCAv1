# Personal Cryptographic Architecture（PCA）Protocol Specification

**Version:** v1.0

---

# Normative Keywords

本文档采用 RFC 2119 与 RFC 8174 中定义的规范性关键词。

下列关键词具有严格的规范意义：

* **MUST**
* **MUST NOT**
* **REQUIRED**
* **SHALL**
* **SHALL NOT**
* **SHOULD**
* **SHOULD NOT**
* **RECOMMENDED**
* **MAY**
* **OPTIONAL**

除非另有说明，所有兼容 PCA 的实现 **MUST** 遵循本文档中的规范性要求。

任何违反 **MUST** 或 **MUST NOT** 要求的实现，不应视为兼容 PCA 的实现。

---

# Terminology

本文档采用以下术语。

### Master Secret

整个 PCA 唯一的 Root of Trust。

Master Secret 是整个系统唯一需要永久保存且无法恢复的秘密。

---

### Trust Root

由 Master Secret 经 HKDF 派生得到的逻辑根密钥。

Trust Root 不需要长期保存，可随时重新计算。

---

### Persona

Persona 表示一个独立的身份空间（Identity Namespace）。

不同 Persona 应被视为彼此独立的公开身份。

例如：

* Personal
* Work
* OpenSource
* Anonymous

每个 Persona 可以拥有多个年度 Identity。

---

### Identity

Identity 用于建立公开信任关系（Public Trust）。

Identity 负责身份认证、数字签名以及建立信任链。

---

### Generation

Generation 用于确定性生成各种秘密。

例如：

* Password
* Bitcoin Wallet
* Vault Key

Generation 不建立公开信任。

---

### Vault

Vault 用于保护无法重新生成的外部秘密。

例如：

* API Key
* OAuth Token
* Recovery Code

Vault 不负责生成秘密，仅负责保护秘密。

---

### Canonical Info Path

Canonical Info Path 是 HKDF 的唯一上下文。

所有兼容 PCA 的实现 **MUST** 使用完全一致的 Canonical Info Path。

---

# 1. 简介（Introduction）

Personal Cryptographic Architecture（简称 PCA）是一套用于管理个人身份（Identity）、密钥（Key）以及秘密数据（Secret）的统一密码学架构。

PCA 不发明新的密码算法，而是定义一套长期稳定、职责清晰、可确定性恢复（Deterministic Recovery）的密钥管理协议，使所有兼容 PCA 的实现都能够生成完全一致的密钥体系。

整个系统只有一个永久离线保存的 Master Secret，其余绝大部分密钥均可由 HKDF 确定性派生恢复。

PCA 的目标并不是规定某一种具体软件，而是定义一种稳定的密码学架构，使不同实现之间能够保持完全一致的密钥体系与身份体系。

---

# 2. 设计目标（Design Goals）

PCA 的设计遵循以下原则：

* Single Root of Trust（唯一信任根）
* Deterministic Recovery（确定性恢复）
* Minimal Persistent Secrets（最少长期密钥）
* Separation of Responsibilities（职责分离）
* Least Disclosure（最小公开）
* Capability Isolation（能力隔离）
* Long-term Evolvability（长期可演进）

整个协议中，Identity、Generation 与 Vault 三者互相独立，各自负责不同职责。

---

# 3. 总体架构（Architecture）

```text
Master Secret
(512-bit Random)

│
└── TrustRootKey
    (HKDF-SHA-512)

    ├──────────────────────────────────────────────┐
    │                                              │
    ▼                                              ▼

IdentityRoot V1                           EncryptRoot V1

│                                              │

├── Personal                                  ├── Generation
│   │                                          │
│   ├── Identity2026                           ├── Bitcoin
│   │   ├── Laptop                             ├── PasswordManager
│   │   ├── Desktop                            └── Vault
│   │   ├── Phone                                  └── PermissionNode ... 
│   │   ├── DocumentSigning                             └── File Encryption Key 
│   │   ├── CodeSigning                        
│   │   └── EmailCa                            
│   │        │                                 
│   │        └── EmailIdentity                 
│   │
│   └── Identity2027
│
├── Work
│
├── OpenSource
│
└── Anonymous
```

整个系统只有 Master Secret 为真正的 Root of Trust。

TrustRootKey 不长期保存，可随时重新计算。

IdentityRoot 用于管理所有 Persona。

每个 Persona 可以拥有多个年度 Identity。

Encrypt Branch 与 Identity Branch 完全独立。

---

# 4. Master Secret

（保持原文，仅增加一句）

Master Secret **MUST** 是使用密码学安全随机数生成器（CSPRNG）生成的 512-bit 随机数。

Master Secret 是整个 PCA 唯一需要永久保存的秘密。

Master Secret **MUST** 永远离线保存，不参与任何业务操作，仅用于恢复整个密钥体系。

建议保存方式包括：

* 金属助记板
* HSM
* 多份异地备份
* 银行保险柜

Master Secret **MUST NOT** 联网。

---

# 5. Master Secret

Master Secret 是整个 PCA 唯一需要永久保存的秘密。

Master Secret 是整个系统唯一的 Root of Trust。

Master Secret **MUST** 使用密码学安全随机数生成器（CSPRNG）生成。

Master Secret **MUST** 为 **512-bit** 随机数。

Master Secret **MUST** 永远离线保存，不参与任何业务操作，仅用于恢复整个密钥体系。

建议保存方式包括：

* 金属助记板
* HSM
* 多份异地备份
* 银行保险柜

Master Secret **MUST NOT** 联网。

Master Secret 一旦泄漏，攻击者将能够恢复整个 PCA 的全部密钥体系。因此，Master Secret 的保护等级应高于任何其他密钥。

---

# 6. HKDF 规范（HKDF Specification）

整个 PCA 所有确定性派生均采用：

```text
HKDF-SHA-512
```

所有兼容 PCA 的实现 **MUST** 使用统一的 HKDF 参数。

---

## 6.1 HKDF 输入

所有 HKDF 使用以下输入：

```text
IKM
=
Parent Key

salt
=
Namespace ID

info
=
Canonical Info Path
```

其中：

* IKM 表示父密钥。
* salt 表示 PCA 协议命名空间。
* info 表示唯一上下文。

对于相同的：

* IKM
* salt
* info

HKDF **MUST** 产生完全一致的输出。

HKDF 本身不包含随机性，因此所有兼容 PCA 的实现都能够生成一致的密钥树。

---

## 6.2 Namespace ID

整个 PCA 协议仅存在一个 Namespace ID。

Namespace ID **MUST** 满足：

* 长度为 256 bit。
* 随机生成。
* 使用 Uppercase HEX 编码。
* 整个协议生命周期保持不变。
* 所有 HKDF 均使用同一个 Namespace ID。

格式如下：

```text
PCA-v1/<NamespaceID>
```

当前版本采用：

```text
PCA-v1/A980E2656D5D0349012434FF624506C9650187D1F4B897D20D0E0918B1E1186E
```

未来若发布新的协议版本，可以使用新的 Namespace ID，以避免不同协议之间发生命名空间冲突。

---

## 6.3 Canonical Info Path

所有 HKDF 的 info **MUST** 使用统一路径格式。

基本格式如下：

```text
Branch/Version/Object...
```

例如：

```text
Identity/V1/Personal/2026/Laptop

Identity/V1/Work/2026/Phone

Identity/V1/OpenSource/2026/Email/3F91A27C6E0D5B88C42E8A9F0C7B11D4

Generation/V1/PasswordManager

Generation/V1/Bitcoin/Mainnet

Generation/V1/Vault
```

Canonical Info Path **MUST** 保持稳定。

一旦某一路径被定义，其语义 **MUST NOT** 被修改。

未来如需变更语义，应创建新的路径，而不是修改已有路径。

---

## 6.4 Deterministic Tree

PCA 的整个密钥体系是一棵确定性密钥树（Deterministic Key Tree）。

除 Master Secret 外，其余所有密钥均通过 HKDF 按层级派生。

例如：

```text
Master Secret
        │
        ▼
TrustRootKey
        │
        ▼
IdentityRoot
        │
        ▼
Personal
        │
        ▼
Identity2026
        │
        ▼
EmailCa
        │
        ▼
Email Identity
```

每一级节点均由上一层节点通过 HKDF 派生。

因此，只要拥有 Master Secret，即可按照完全一致的路径重新恢复整个密钥体系。

PCA 不需要长期保存整个密钥树。

除 Master Secret 外，其余所有密钥均可在需要时重新计算。

---

# 7. 命名规范（Naming Rules）

整个 PCA 协议采用统一命名规范。

所有 Path **MUST** 使用 CamelCase（驼峰命名）。

例如：

```text
PasswordManager

Vault

DocumentSigning

CodeSigning

EmailCa

OpenSource
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

---

# 8. 编码规范（Encoding Rules）

整个 PCA 协议统一采用以下编码规范：

| 对象           | 编码            |
| ------------ | ------------- |
| Namespace ID | Uppercase HEX |
| Email ID     | Uppercase HEX |
| File ID      | Uppercase HEX |
| Hash         | Uppercase HEX |
| Fingerprint  | Uppercase HEX |

所有 HEX 字符串 **MUST** 使用大写字母。

例如：

```text
8E4D9AF3C2B18F...
```

禁止：

```text
8e4d9af3c2b18f...
```

所有字符串 **SHOULD** 使用 UTF-8 编码。

Canonical Info Path **MUST** 按照本文定义进行编码，不允许因平台差异而改变其字节表示。

---

# 9. Identity Branch

Identity Branch 用于建立公开信任关系（Public Trust）。

推荐算法：

```text
Ed25519
```

IdentityRoot 长期离线保存，仅负责签发 Persona。

每个 Persona 表示一个逻辑身份空间。

例如：

```text
Personal

Work

OpenSource

Anonymous
```

Persona 可以继续签发年度 Identity。

例如：

```text
Personal
    │
    ├── Identity2026
    └── Identity2027
```

每个年度 Identity 可以继续签发各种用途身份，例如：

* Laptop
* Desktop
* Phone
* DocumentSigning
* CodeSigning
* EmailCa

不同 Persona 应被视为互相独立的公开身份。

Identity Version 表示 Identity 树的逻辑版本，而不是密码算法版本。

未来如果 Identity 体系升级，可以创建：

```text
IdentityRoot V2
```

而无需影响已有 Identity。

---

# 10. Email Identity

Email Identity 用于建立邮件身份（Email Identity）。

Email Identity 不直接长期保存，而是根据 Email ID 确定性派生。

Email Identity 的派生路径如下：

```text
Identity/V1/<Persona>/<Year>/Email/<EmailID>
```

例如：

```text
Identity/V1/Personal/2026/Email/5C5F68690ACDBC085A1C2E86A1C4A7BE0AFC2B3DB160558BEBB026224A7BD8BD
```

其中：

* Persona 表示身份空间。
* Year 表示年度 Identity。
* Email ID 表示该邮件的唯一标识。

Email ID **MUST** 满足：

* 长度为 256 bit。
* 使用密码学安全随机数生成器（CSPRNG）生成。
* 使用 Uppercase HEX 编码。

EmailCa 不直接参与任何签名。

EmailCa 仅用于派生一次性的 Email Identity。

派生流程如下：

```text
EmailCa
      │
      ▼
 HKDF(Email ID)
      │
      ▼
 Email Identity (PGP Key)
      │
      ▼
 Sign(Message)
```

Email Identity 不需要长期保存。

签名完成后即可销毁。

未来验证时，只需根据相同的：

* Persona
* Year
* Email ID

即可重新派生出完全一致的公钥。

因此，整个系统无需维护大量 Email Identity，也无需维护额外的密钥数据库。

建议邮件 Header 至少保存以下字段：

* Persona
* Year
* Email ID

验证方即可恢复对应的 Email Identity。

---

# 11. Encrypt Branch

Encrypt Branch 不建立任何公开信任。

Encrypt Branch 仅负责：

* Generation（秘密生成）
* Vault（秘密保护）

EncryptRoot 不需要长期保存。

EncryptRoot 可由 Master Secret 随时重新恢复。

Encrypt Branch 与 Identity Branch 完全独立。

任何 Encrypt Branch 派生出的密钥均不得用于建立公开身份。

---

# 12. Generation

Generation 用于生成所有能够确定性恢复的秘密。

例如：

```text
Generation/V1/PasswordManager

Generation/V1/Bitcoin/Mainnet

Generation/V1/Vault
```

所有 Generation Key 均由 HKDF 派生。

Generation Key 不需要长期保存。

只要拥有 Master Secret，即可重新恢复全部 Generation Key。

Generation Branch 不负责保存任何外部秘密。

对于无法重新生成的数据，应使用 Vault 保存。

---

## 12.1 Bitcoin

PCA 不重新定义 Bitcoin 钱包标准。

PCA 仅规定 Bitcoin 根密钥的生成方式。

派生流程如下：

```text
Generation/V1/Bitcoin/Mainnet
            │
            ▼
          HKDF
            │
            ▼
     512-bit Master Seed
            │
            ▼
     BIP32 Master Key
            │
            ▼
 Standard BIP32 Derivation
```

HKDF 输出的 512-bit 数据 **MUST** 直接作为 BIP32 Master Seed。

之后所有钱包派生均应遵循 BIP32 标准。

PCA 不要求使用 BIP39 助记词。

Master Secret 已承担整个系统唯一恢复入口的职责，因此无需再生成额外助记词。

---

# 13. Vault

Vault 用于保存无法重新生成的外部秘密或用于加密文件。
Vault 不负责生成秘密，仅负责保护秘密。

例如：

* OAuth Token
* API Key
* Cookie
* Recovery Code
* License
* WireGuard PSK
* File Encryption

推荐采用权限树（Permission Tree）结构。

整体结构如下：

```text
Generation/V1/Vault
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
        PerFileKey
            │
            ▼
      Encrypt(File)
```

每个文件均拥有独立的 PerFileKey。

PermissionNodeKey 可以继续派生更多权限节点，从而形成完整的权限树。

知道某个 PermissionNodeKey，即表示拥有该节点以下全部子节点的派生能力。

不同 PermissionNodeKey 之间彼此独立。

拥有某个节点，不应能够恢复其父节点或兄弟节点。

---

## 13.1 File ID

每个文件对应一个唯一 File ID。

File ID **MUST** 满足：

* 长度为 256 bit。
* 使用密码学安全随机数生成器（CSPRNG）生成。
* 使用 Uppercase HEX 编码。

例如：

```text
5C5F68690ACDBC085A1C2E86A1C4A7BE0AFC2B3DB160558BEBB026224A7BD8BD
```

对应 HKDF Path：

```text
Generation/V1/Vault/<Permission Path>/<File ID>
```

File ID 的随机性用于隐藏文件元数据。

随机 File ID 并非 HKDF 的安全性要求，而是为了避免文件名称、编号或数量等元数据被预测。

采用该设计具有以下优点：

* 每个文件使用独立密钥。
* 文件之间完全隔离。
* 不同权限树互相独立。
* 所有密钥均可确定性恢复。
* 无需长期保存文件密钥。

---

# 14. 生命周期（Lifecycle）

PCA 中不同组件具有不同的生命周期。

| Component      | Long-term | Offline  | Recoverable |
| -------------- | --------- | -------- | ----------- |
| Master Secret  | Yes       | Yes      | No          |
| TrustRootKey   | No        | No       | Yes         |
| IdentityRoot   | Yes       | Yes      | Yes         |
| Persona        | Optional  | Optional | Yes         |
| IdentityYYYY   | Optional  | Optional | Yes         |
| Email Identity | No        | No       | Yes         |
| EncryptRoot    | No        | No       | Yes         |
| Generation Key | No        | No       | Yes         |
| Vault KEK      | No        | No       | Yes         |
| Vault Data     | Yes       | Optional | No          |

Master Secret 是整个系统唯一不可恢复的秘密。

除 Master Secret 外，其余所有 PCA 密钥均可以通过确定性派生重新恢复。

Vault Data 属于外部秘密，不属于 PCA 密钥体系，因此无法重新生成。

---

# 15. 安全模型（Security Model）

PCA 将整个系统划分为三个彼此独立的安全域（Security Domain）。

| Module     | Responsibility | Public Trust | Recoverable |
| ---------- | -------------- | ------------ | ----------- |
| Identity   | 建立公开身份与信任      | Yes          | Yes         |
| Generation | 确定性生成秘密        | No           | Yes         |
| Vault      | 保存外部秘密         | No           | No          |

三者职责完全分离。

Identity 不负责保存秘密。

Generation 不负责建立信任。

Vault 不负责生成秘密。

任何实现 **SHOULD NOT** 混用三个模块的职责。

整个 PCA 的核心思想可以概括为：

* Identity 负责证明身份（Trust）。
* Generation 负责生成秘密（Generate Secrets）。
* Vault 负责保护秘密（Protect Secrets）。

这种职责划分能够降低长期密钥数量，并减少不同用途之间的相互影响。

---

# 16. 推荐算法（Recommended Algorithms）

PCA 不发明新的密码算法。

PCA 推荐采用当前已经广泛验证的现代密码算法。

| 对象               | 推荐算法               |
| ---------------- | ------------------ |
| Master Secret    | 512-bit Random     |
| HKDF             | HKDF-SHA-512       |
| Identity         | Ed25519            |
| Vault Encryption | XChaCha20-Poly1305 |
| File Encryption  | XChaCha20-Poly1305 |
| Bitcoin Wallet   | BIP32              |

未来如果推荐算法发生变化，应通过新的 Protocol Version 引入，而不是修改已有 Version 的语义。

---

# 17. 协议迁移（Protocol Migration）

PCA 支持协议长期演进。

新的协议版本可以在保持信任连续性的前提下逐步替代旧版本。

协议迁移采用 Trust Root 信任链。

例如：

```text
IdentityRoot V1
        │
        ├────────────── Sign ──────────────► IdentityRoot V2
        │
        └────────────── Sign ──────────────► IdentityRoot V3
```

新的 IdentityRoot **MUST** 由上一代受信任的 IdentityRoot 进行签名。

验证新的协议版本时，应验证整个信任链。

例如：

```text
IdentityRoot V1
        │
        ▼
IdentityRoot V2
        │
        ▼
IdentityRoot V3
        │
        ▼
Identity2028
```

只要整个签名链有效，则新的协议版本应被视为可信。

协议升级期间：

* 新旧协议 **MAY** 长期共存。
* 已有 Identity 不需要立即迁移。
* 新创建的 Identity **SHOULD** 使用新的协议版本。

协议迁移的目标是在保持长期兼容性的同时，实现密码学架构的持续演进，而无需破坏已有身份体系。

---

# 18. 后续可扩展方向（Future Extensions）

PCA 在保持协议兼容性的前提下，可以持续扩展新的能力。

未来可考虑加入：

* Identity Revocation
* Multi-device Synchronization
* Hardware Security Module
* YubiKey Integration
* Post-Quantum Cryptography
* Zero-Knowledge Identity
* Audit Log
* Automatic Key Rotation

新增能力应尽可能采用新增 Branch、新增 Path 或新增 Protocol Version 的方式扩展。

已有 Canonical Info Path 的语义 **MUST NOT** 被修改。

PCA 的设计目标是在保持长期稳定性的前提下，允许协议不断演进，而无需破坏已有密钥体系与身份体系。

---

# Appendix A. Design Philosophy（Non-Normative）

本附录不属于协议规范，仅用于说明 PCA 的设计理念。

PCA 的核心思想可以概括为以下几个原则：

* Single Root of Trust
* Deterministic Recovery
* Separation of Responsibilities
* Minimal Persistent Secrets
* Capability Isolation
* Long-term Evolvability

整个系统只有一个永久保存的 Master Secret。

其余绝大部分密钥均可通过 HKDF 确定性恢复。

PCA 并不追求减少密钥数量，而是追求减少需要长期保存的密钥数量。

Identity、Generation 与 Vault 分别承担公开信任、秘密生成与秘密保护三种职责。

三者互相独立，不共享职责，从而使整个密码学架构具有良好的可维护性、可恢复性以及长期演进能力。
