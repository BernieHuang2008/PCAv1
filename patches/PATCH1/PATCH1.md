# 第 6 章 HKDF 密码学原语规范（新增 6.5 节）

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
  `Encrypt/V1/Generation/PasswordRoot1/8E.../Block0`  
  `Encrypt/V1/Generation/PasswordRoot1/8E.../Block11`
- **`L`**：固定为 `256` 字节（使用 SHA‑512，符合 RFC 5869）。

### 6.5.4 块序号与状态维护

- 块序号 `i` 从 `0` 开始，按需递增（当前块字节耗尽时，自动请求 `i+1` 块）。
- 每次**新的密码生成过程**起始时，消费位置**必须**重置为 `Block 0` 的起始位置，以保证可重现性。
- 实现**必须**确保 `Block i` 的最后一个字节之后紧跟 `Block i+1` 的第一个字节，无截断、无跳过、无重复。
- 实现**必须**以状态机方式维护当前消费位置（当前块索引及块内偏移量）。

> **说明**：该流生成规范适用于所有需要确定性随机字节的场景，包括但不限于第 11.4.4 节中的桶内选字符、补齐字符以及 Fisher‑Yates 洗牌。

---

# 第 7 章 命名与编码规范（Naming & Encoding Rules）

## 7.3 JSON 签名序列化强制标准（修订）

任何涉及数字签名的 JSON 数据结构（包括但不限于撤销列表 CRL、证书元数据、密码生成配置等），其序列化 **MUST** 遵循 **RFC 8785（JSON Canonicalization Scheme，JCS）**。

具体要求如下：

1. **格式规范**：
   - 无额外空格、无换行符。
   - 使用双引号包裹键名和字符串值。
   - 键名按照字典序（ASCII 码顺序）排列。
   - 转义规则严格遵循 RFC 8785。

2. **Unicode 预归一化（Pre‑normalization）**（新增）：
   - JCS 本身不定义 Unicode 归一化。为确保跨平台（特别是 macOS 默认 NFD 与 Linux/Windows 默认 NFC 之间的差异）的字节级确定性，**所有包含人类可读文本的 JSON 字符串值**（例如用户名、域名显示部分、证书持有者名称等）**MUST**，在赋值给 JSON 对象并传入 JCS 序列化器之前，先转换为 **Unicode 规范化形式 C（Normalization Form Composition，简称 NFC）**。
   - **执行顺序**：实现 **MUST** 遵循 `原始输入 → NFC 归一化 → UTF-8 编码 → 作为JSON相应字段的值 → JCS 序列化` 的严格顺序。
   - **实现约束**：**MUST NOT** 依赖 JSON 库或 JCS 库内部的隐式归一化（大多数库并不提供此功能）；归一化 **MUST** 由应用层作为显式的预处理步骤完成。
   - **例外情况**：对于仅包含 ASCII 字符（`U+0000` - `U+007F`）的字符串，NFC 归一化操作是幂等的（无变化），实现可跳过处理以提升性能，但结果必须等价。

3. **后续用途**：
   - 后续用途必须直接对 JSON 序列化之后的字节流（UTF-8编码）进行操作，**MUST NOT**修改编码或字节。
   - 对于签名计算任务，**MUST** 对经过上述**完整流程**（格式规范化 + Unicode 归一化）序列化后的字节流（UTF-8 编码）直接进行签名（如 Ed25519）。
   - 验证端 **MUST** 使用完全相同的流程重新生成字节流以验证签名。
   - 其他情况下，建议可以先对字节流计算 SHA-256，然后使用SHA-256替代JSON字节流以避免编码问题。

---

# 第 11 章 Generation（新增 11.4 节）

## 11.4 密码生成（Password Generation）

### 11.4.1 目的与范围

本规范定义了一种从 PCA 主密钥中确定性派生网站登录密码的方法，使用户无需依赖第三方密码管理器、无需跨设备同步密码，即可在不同设备、不同时间重现完全一致的密码字符串。

派生的密码 **MUST** 可重现，**SHOULD NOT** 长期存储，且 **MUST NOT** 用于任何加密目的（如文件加密或数字签名）。

---

### 11.4.2 密码种子根（Password Root）

密码生成的逻辑根路径**必须**为：

```text
Encrypt/V1/Generation/PasswordRoot1
```

注：若 `PasswordRoot1` 泄漏，可更换为 `Encrypt/V1/Generation/PasswordRoot2`，以此类推。

**MUST** 按照第 6 章规定的 HKDF 派生方式，从 `TrustRootKey` 沿此完整路径派生一个 **32 字节**的 `PasswordRootKey`：

```text
PasswordRootKey = HKDF-SHA-512(
  IKM  = HKDF node at Encrypt/V1/Generation,
  salt = Namespace ID,
  info = "Encrypt/V1/Generation/PasswordRoot1",
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
  `Encrypt/V1/Generation/PasswordRoot1/<JSON Hash>`  
  例如：`Encrypt/V1/Generation/PasswordRoot1/8E...`
- 执行 `HKDF-SHA-512`，输出长度 `L = 64` 字节，记为 `RawPasswordKey`。

伪代码：

```text
RawPasswordKey = HKDF-SHA-512(
  IKM  = PasswordRootKey,
  salt = Namespace ID,
  info = "Encrypt/V1/Generation/PasswordRoot1/<JSON Hash>",
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
   HKDF-Stream(
       IKM =  HKDF node at Encrypt/V1/Generation/PasswordRoot1/<JSON Hash>,
       path = "Encrypt/V1/Generation/PasswordRoot1/<JSON Hash>"
   )

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

   **桶遍历顺序**：**MUST** 按照表 1 中**自上而下**的顺序进行遍历（先列出第一个桶，再第二个，以此类推）。`MandatoryChars` 数组必须按此顺序依次存放每个桶选出的字符，例如"aba111@*!"。

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
