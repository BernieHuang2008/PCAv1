# Personal Cryptographic Architecture（PCA）
> Version 0.1 Draft

---

# 1. 设计目标

本系统旨在建立一套统一的个人密码学基础设施（Personal Cryptographic Architecture，PCA），用于管理个人所有身份、密钥与秘密数据。

系统设计遵循以下原则：

- **唯一根密钥（Single Root of Trust）**
- **确定性恢复（Deterministic Recovery）**
- **最小长期密钥（Minimal Persistent Secrets）**
- **职责分离（Separation of Responsibilities）**
- **风险隔离（Risk Isolation）**
- **最小公开原则（Least Disclosure）**

整个系统仅长期保存一个 Master，其余绝大多数密钥均可确定性恢复。

---

# 2. 系统总体结构

```
Master（Offline）
        │
        ▼
    Trust0（临时恢复节点）
        │
        ├───────────────┐
        │               │
        ▼               ▼
 Identity Root     Encrypt Root
```

Master 是整个系统唯一信任根。

Trust0 不长期保存，仅作为恢复节点，用于划分整个系统的两个功能域：

- Identity（身份）
- Encrypt（秘密）

Trust0 在恢复完成后立即销毁。

---

# 3. Master

## 职责

整个系统唯一根密钥。

用于：

- 恢复 Identity Root
- 恢复 Encrypt Root

Master 不参与任何业务。

---

## 生命周期

永久。

长期离线保存。

建议：

- 纸质备份
- 金属助记板
- HSM
- 银行保险柜

Master 不应联网。

---

# 4. Identity Branch

Identity 负责：

- 身份认证
- 数字签名
- 建立公开信任链

Identity 是一棵 **信任树（Trust Tree）**。

## 结构

```
Master
    │
Identity Root
    │
    ├── Identity 2026
    ├── Identity 2027
    ├── Identity 2028
```

Identity Root 长期离线保存。

每年签发一个新的年度 Identity。

年度 Identity 到期后停止签发新的身份。

---

## 用途身份

每个年度身份负责签发各种用途身份。

例如：

```
Identity 2026
      │
      ├── Email
      ├── Laptop
      ├── Desktop
      ├── Phone
      ├── Document
      └── Code Signing
```

不同用途互不影响。

---

## 一次性邮件身份

邮件采用一次性身份。

```
Identity 2026
      │
Email CA
      │
────────────（默认不公开）
      │
Email #123
      │
      ▼
Message Signature
```

每封邮件生成新的 Email Identity。

邮件默认仅公开：

```
Email #123
↓

Message
```

默认情况下：

- 无法判断发送者是谁。
- 无法关联不同邮件。

若未来需要证明：

> "该邮件确实由本人发送。"

则公开缺失证书：

```
Identity 2026
↓

Email #123
```

验证者即可恢复完整信任链。

实现：

- 默认匿名
- 选择性证明（Selective Disclosure）

---

# 5. Encrypt Branch

Encrypt 负责：

- 所有秘密管理
- 所有对称密钥
- 外部秘密保护

Encrypt 是一棵 **能力树（Capability Tree）**。

Encrypt 不建立任何公开信任关系。

---

## 结构

```
Encrypt Root
      │
      ├── Generation
      └── Vault
```

---

# 6. Generation

Generation 用于生成所有可以确定性恢复的秘密。

例如：

```
Generation
      │
      ├── Bitcoin
      ├── Password Manager
      ├── File Encryption
      ├── Database
      ├── SSH
      └── ...
```

特点：

- 全部由 HKDF 派生。
- 不需要长期保存。
- 可由 Master 完整恢复。

例如：

```
Master
↓

Encrypt Root
↓

Generation
↓

Bitcoin Entropy
↓

BIP39 Mnemonic
```

Generation 负责：

> **Generate Secrets**

---

# 7. Vault

Vault 用于保存所有**外部产生**的秘密。

例如：

- TOTP
- OAuth Token
- API Secret
- Cookie
- Recovery Code
- License
- WireGuard PSK

这些秘密无法由 Master 推导。

Vault 的职责是：

> **Protect Secrets**

而不是：

> Generate Secrets。

---

## Vault 结构

```
Vault
      │
      ├── Alpha
      ├── Bravo
      └── Charlie
```

三个 Vault 对应三个安全等级。

每个 Vault 使用独立密钥：

```
Vault Alpha

HKDF(
    Encrypt Root,
    "vault/alpha"
)
```

Bravo、Charlie 同理。

---

# 8. Vault Alpha

定位：

**Hot Vault**

特点：

- 在线
- 高频访问
- 可同步

建议存放：

- TOTP
- OAuth Token
- 普通 API Key
- 浏览器 Cookie
- 临时 SSH Key
- 日常登录信息

存放设备：

- 手机
- 主电脑

---

# 9. Vault Bravo

定位：

**Warm Vault**

特点：

- 半离线
- 偶尔访问

建议：

- Recovery Code
- 软件许可证
- WireGuard 配置
- SSH Backup
- 小额钱包恢复信息
- 历史档案密码

建议：

- NAS
- 加密 U 盘
- 不自动同步

---

# 10. Vault Charlie

定位：

**Cold Vault**

特点：

- 长期离线
- 极少访问

建议：

- Bitcoin 助记词
- Ethereum 助记词
- PGP Root
- Master Recovery
- 数字遗产
- 家庭重要文件
- 高价值恢复材料

建议：

- 加密 U 盘
- 光盘
- 钢板
- 保险柜

---

# 11. 风险分级原则

Vault 不按数据类型分类。

而按风险分类。

判断标准：

## 第一问

如果泄露：

损失是否重大？

---

## 第二问

如果丢失：

还能恢复吗？

---

## 第三问

访问频率如何？

根据：

- 泄露风险
- 恢复难度
- 使用频率

决定：

Alpha / Bravo / Charlie。

---

# 12. 生命周期

## Master

永久。

离线。

---

## Trust0

恢复时生成。

恢复结束立即销毁。

---

## Identity Root

长期离线。

每年签发一次。

---

## Identity YYYY

一年有效。

负责签发用途身份。

---

## Email Identity

一次性。

一封邮件对应一个身份。

---

## Encrypt Root

恢复时重新计算。

无需长期保存。

---

## Generation

按需重新生成。

无需保存。

---

## Vault

长期保存密文。

密钥由 Encrypt Root 动态派生。

---

# 13. 三棵树的职责

| 模块 | 类型 | 作用 |
|------|------|------|
| Identity | Trust Tree | 建立身份与信任 |
| Generation | Capability Tree | 派生秘密 |
| Vault | Secure Storage | 保护外部秘密 |

---

# 14. 核心设计原则

## 唯一根密钥

整个系统仅信任：

Master。

---

## 最小长期密钥

除 Master 外：

尽可能不保存可恢复密钥。

所有可派生密钥均动态生成。

---

## 分层职责

|模块|职责|
|-|-|
|Identity|负责证明身份|
|Generation|负责生成密钥|
|Vault|负责保护秘密|

---

# 15. 未来可扩展方向

- 多设备同步协议
- 自动密钥轮换
- Threshold Recovery（Shamir Secret Sharing）
- HSM / YubiKey 集成
- 后量子密码算法迁移
- 短期身份证书（Short-lived Certificates）
- 零知识身份认证（Zero-Knowledge Identity）
- 可撤销匿名（Revocable Anonymity）
- 审计日志与密钥使用记录
