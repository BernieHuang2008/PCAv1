**结论**

不能判定 `examples/` “完全符合 PCA v1.2”。核心密码学原语选型基本正确，随机数是 CSPRNG，当前测试也全部通过；本轮已补上 `Identity/V1/PCA` 公钥、Emergency Revocation 公钥和 Namespace 的硬编码/预配置信任锚接口，但架构级 MUST 仍有缺口，尤其是 Master Secret 离线边界、生产环境必须替换 `EXAMPLE` 测试锚、CRL/迁移完整链式验签与发现流程、OpenPGP `0x18` 绑定验证完整性。

验证结果：`python -B -m unittest discover tests` 当前 24 项全通过。

**主要问题**

- ❌ Master Secret 不满足“永远离线/不参与普通在线业务操作”：CLI 多数命令直接接收 `--master-hex`，UI 也把 master 放进前端 state。见 [pca_cli.py](<C:/Bernie/DevG/git/BernieHuang2008/PCAv1/examples/pca_reference/pca_cli.py:62>)、[app.js](<C:/Bernie/DevG/git/BernieHuang2008/PCAv1/examples/pca_reference/ui/static/app.js:493>)。
- ⚠️ `Identity/V1/PCA` 公钥、Emergency Revocation 公钥和 Namespace 已有硬编码/预配置接口；当常量为真实值时会覆盖 CLI 参数，当常量为大写 `EXAMPLE` 时才允许测试参数或跳过校验。生产部署必须把 `HARDCODED_IDENTITY_PCA`、`HARDCODED_EMERGENCY_REVOCATION_PUBLIC_KEY`、`HARDCODED_NAMESPACE` 替换为真实信任锚，否则仍是测试体系。见 [infrastructure.py](<C:/Bernie/DevG/git/BernieHuang2008/PCAv1/examples/pca_reference/pca_core/infrastructure.py:15>)、[revocation.py](<C:/Bernie/DevG/git/BernieHuang2008/PCAv1/examples/pca_reference/pca_core/revocation.py:19>)、[trust.py](<C:/Bernie/DevG/git/BernieHuang2008/PCAv1/examples/pca_reference/pca_core/trust.py:6>)。
- ❌ CRL/协议迁移已能直接回溯到硬编码 `Identity/V1/PCA` 公钥，但没有实现子身份证书链回溯、CRL well-known fetch，迁移也没有校验适用协议范围。见 [infrastructure.py](<C:/Bernie/DevG/git/BernieHuang2008/PCAv1/examples/pca_reference/pca_core/infrastructure.py:85>)、[migration.py](<C:/Bernie/DevG/git/BernieHuang2008/PCAv1/examples/pca_reference/pca_core/migration.py:36>)。
- ❌ OpenPGP `0x18` Subkey Binding 验证只检查存在绑定签名类型，没有用标准 OpenPGP verifier 验证该绑定签名链并确认绑定子密钥就是邮件临时公钥。见 [email_identity.py](<C:/Bernie/DevG/git/BernieHuang2008/PCAv1/examples/pca_reference/pca_core/email_identity.py:431>)。

**MUST/MUST NOT 对照**

| v1.2标准中的定义 | 参考实现中的逻辑 | 是否符合 |
|---|---|---|
| 子密钥泄露 MUST NOT 恢复父级/兄弟；Encrypt 分支 MUST NOT 建立公开身份；Identity/Generation/Vault MUST 分离 | HKDF 单向派生；`derive_descendant_key()` 拒绝非后代；Identity/Generation/Vault 分模块和路径校验 | ✅ |
| Master Secret MUST 为 512-bit CSPRNG，且是唯一永久根秘密 | `secrets.token_bytes(64)`；常量 64 字节 | ✅ |
| Master Secret MUST 离线；MUST NOT 参与普通在线业务/联网服务 | CLI/UI 常规操作直接传递 `master_hex` | ❌ 因为是 Example，架构边界不符合 |
| Emergency Revocation Key MUST 独立 Ed25519；私钥 MUST 用独立 CSPRNG，MUST NOT 从 Master 派生 | `Ed25519PrivateKey.generate()`；不从 Master 派生 | ✅ |
| Emergency 私钥 MUST 与 Master Secret 物理隔离；公钥 MUST/SHOULD 预配置到验证端 | `init` 同一 JSON 输出 master 和 emergency seed，只给人工提示；验证端已有 `HARDCODED_EMERGENCY_REVOCATION_PUBLIC_KEY`，真实常量会覆盖外部参数，`EXAMPLE` 仅用于测试 | ⚠️ 公钥预配置接口已补；私钥物理隔离仍靠操作流程 |
| TrustRootKey MUST 为 HKDF-SHA-512，salt=Namespace，info=`PCA/V1/TrustRoot`；该 path MUST NOT 用于其他节点且 MUST 稳定 | `TRUST_ROOT_INFO_PATH` 固定；派生逻辑正确 | ✅ |
| Verifier MUST hard-code/preconfigure `Identity/V1/PCA` 公钥和完整 path | path 固定为 `Identity/V1/PCA`；新增 `HARDCODED_IDENTITY_PCA`，真实常量会覆盖 `public-key-b64`，`EXAMPLE` 仅用于测试 | ✅ 核心接口符合；生产必须替换 `EXAMPLE` |
| Namespace MUST 独立；旧信任锚/CRL/废止 MUST NOT 自动作用新 Namespace；NamespaceID MUST 256-bit CSPRNG uppercase HEX | `generate_namespace()` 32 字节 CSPRNG；验证 namespace mismatch 立即忽略；新增 `HARDCODED_NAMESPACE`，真实常量会覆盖外部 namespace，`EXAMPLE` 仅用于测试 | ✅ |
| 所有 HKDF MUST 使用相同 IKM/salt/info；相同输入 MUST 输出一致 | 手写 RFC5869 HKDF-SHA512，salt 为 namespace，info 为 ASCII path | ✅ |
| Canonical Path MUST 非空 ASCII，只允许 `[A-Za-z0-9/-]`；MUST NOT 有 Unicode/空格/空组件/首尾 `/`；Branch/Version MUST 合规 | `validate_canonical_path()`、`validate_protocol_path()` 覆盖这些校验 | ✅ |
| Descendant derivation MUST 从父路径下方继续；目标 MUST 等于或低于父路径，否则拒绝 | `derive_descendant_key()` 明确拒绝非后代 | ✅ |
| Ed25519 seed/XChaCha key/BIP32 seed/SHA-256 输出长度 MUST 合规 | 32/32/64/32 字节常量和切片实现 | ✅ |
| Path 语义 MUST NOT 修改；层级分隔 MUST 只用 `/`；HEX MUST uppercase；签名 JSON MUST RFC8785/JCS，签名时 MUST 排除 signature 字段 | 代码不变更 path 语义；uppercase 校验；`rfc8785.dumps()`；签名前删除/排除 signature | ✅ |
| Identity private seed MUST 使用派生材料前 32 字节；IdentityRoot 私钥 MUST never public；`Identity/V1/PCA` MUST NOT 作外部身份 | seed 规则正确。建议使用 `--parent-key-hex` 和 `--parent-path` 参数派生子密钥，非必要不使用 `--master-secret` 或高权限 parent key ！！！ | ✅ |
| 外部身份验证 MUST 逐级验签，MUST NOT 要求公开 IdentityRoot；内部验证 MUST 回溯至硬编码 `Identity/V1/PCA`，MUST NOT 查询 DNS | 外部延迟绑定有验证；内部基础设施 statement 可直接用 `HARDCODED_IDENTITY_PCA` 验证；未查询 DNS；但子身份链式回溯仍不完整 | ⚠️ 直接锚已补，链式回溯仍不完整 |
| 每封邮件 MUST 使用全新独立临时 Ed25519；RandomEmailId MUST 一次性 256-bit CSPRNG uppercase HEX；临时 key MUST 只签当前邮件 | 默认 `random_upper_hex(32)`，路径含 Email/Ephemeral，签当前 message | ✅ |
| 延迟绑定 MUST NOT 用中心化清单；MUST 用 RFC4880 OpenPGP 交叉签名；材料 MUST 含指纹、时间、key flags/语义 | detached proof；支持 `0x10`/`0x18`；含声明字段 | ❌ `0x18` 验证不完整，不能算完全符合 |
| 验证端 MUST 只依赖数学签名和带外信任；MUST NOT 要求父级在 PCA Namespace；MUST NOT 用 DNS 自动裁决 | 外部 OpenPGP 父级支持；trusted public key/fingerprint 参数承接带外信任；不查 DNS | ✅ |
| Encrypt keys MUST NOT 作公开身份；Generation MUST NOT 建立公开信任；Generation paths MUST under `Encrypt/V1/Generation/`；BIP32 512-bit HKDF 输出 MUST 直接作为 seed | 路径和长度校验正确；BIP32 返回 64 字节 | ✅ |
| Vault FileID MUST 256-bit CSPRNG uppercase HEX；每文件 MUST 独立 key；节点 key 泄露 MUST NOT 恢复父/兄弟 | FileID 用 `secrets.token_bytes(32)`；per-file key 派生；HKDF 单向 | ✅ |
| Vault MUST 使用 XChaCha20-Poly1305；nonce 对同 PermissionNodeKey+FileID MUST 不重复；格式 MUST 为 nonce+ciphertext+tag；AAD MUST 为完整 path；认证失败 MUST NOT 输出明文 | PyNaCl/libsodium XChaCha；每次自动新 FileID+24-byte nonce；AAD 一致；失败抛认证错误 | ✅ |
| Protocol migration MUST 由 `Identity/V1/PCA` 或其链签发；MUST NOT 与 emergency revocation 混用；新 trust anchor MUST 由旧锚签；verifier MUST 验完整链和适用范围 | 有 JCS+Ed25519 statement_type；直接用 `HARDCODED_IDENTITY_PCA` 验签；但无子身份链验证、协议范围验证 | ⚠️ 直接锚已补，链式回溯仍不完整。部分改善，仍不完整 |
| Emergency revocation statement MUST JCS JSON；version MUST=1；signature MUST Ed25519 over no-signature payload；hint MUST NOT 自动信任 | 字段、JCS、Ed25519、hint 只返回不切换 | ✅ |
| Revocation verifier MUST 先比对 namespace；不同 MUST ignore 且 MUST NOT 验签/改状态；有效后 MUST 拒绝后续操作；hint MUST NOT 自动导入/切换/信任 | 顺序正确；`HARDCODED_NAMESPACE` 和 `HARDCODED_EMERGENCY_REVOCATION_PUBLIC_KEY` 支持预配置；`require_namespace_not_revoked()` 和 CLI guard 可拒绝；但没有持久化/自动发现状态 | ✅ 核心逻辑符合，生产完整性不足 |
| DNS/HTTPS discovery MUST NOT 用作内部授权；DNS 结果后 MUST 继续数学验签；CRL 文件 MUST UTF-8 JSON | DNS helper 只生成 TXT hash；CRL/infra 不用 DNS 授权；文件读取 UTF-8 | ✅ |
| CRL JSON without signature MUST JCS；signature MUST Ed25519；signer_path MUST 为 `Identity/V1/PCA` 或链至它的子身份 | JCS+Ed25519；只接受 `Identity/V1/PCA` | ✅ 格式符合 |
| CRL verifier MUST fetch well-known URL、验签、链式回溯到硬编码锚、查 identifier；MUST NOT 查询 DNS 授权 | 本地文件验证；不实现 fetch；直接用 `HARDCODED_IDENTITY_PCA` 验 `Identity/V1/PCA` 签名；无子身份链式回溯；不查 DNS | ❌ 部分改善，仍缺 fetch/完整链 |
| Future extensions MUST NOT 改已有 Canonical Path 语义 | 示例没有扩展覆盖旧语义 | ✅ |
| Appendix C：父级签临时邮件 key MUST 用 RFC4880 `0x18` 或 `0x10`；verifier MUST 用标准 OpenPGP parser/verifier 并只在父 key 可信时接受 grouping | `0x10` 用 PGPy verify；`0x18` 只检查签名类型存在 | ❌ `0x18` 未完整验签 |

**随机数与库**

密码学随机数：✅ 是 CSPRNG。Python `secrets.token_bytes()` 用于 Master Secret、Namespace、FileID、nonce、RandomEmailId；`cryptography` 的 Ed25519 generate 用于 emergency key。

库版本：本地为 `cryptography 49.0.0`、`PyNaCl 1.6.2`、`rfc8785 0.1.4`、`PGPy 0.6.0`。我核对了 PyPI：这些分别是当前 latest release；`cryptography` 49.0.0 于 2026-06-12 发布，PyPI 项目说明也定位为 Python 的 “cryptographic standard library”；PyNaCl 1.6.2 是 2026-01-01 latest；rfc8785 0.1.4 是 latest；PGPy 0.6.0 也是 latest，但发布时间是 2022-11-24，较旧。来源：[cryptography PyPI](https://pypi.org/project/cryptography/)、[PyNaCl PyPI](https://pypi.org/project/PyNaCl/)、[rfc8785 PyPI](https://pypi.org/project/rfc8785/)、[PGPy PyPI](https://pypi.org/project/PGPy/)。
