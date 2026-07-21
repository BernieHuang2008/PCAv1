**Summary of Changes to PCA v1.2 - patch1**

This patch introduces three normative additions and one revision to the base PCA v1.2 specification, all fully backward‑compatible:

- **New Section 6.5 – HKDF‑Stream**  
  Defines a lazy, block‑wise deterministic byte stream generator (`HKDF‑Stream(IKM, CanonicalInfoPath)`) for algorithms requiring sequential random bytes, such as rejection sampling and Fisher‑Yates shuffling. The stream is seamless, byte‑granular, and stateful, with block generation via `HKDF‑Expand`.

- **Revised Section 7.3 – JSON Canonicalization**  
  Strengthens JCS signing rules by requiring **Unicode Normalization Form C (NFC)** for all human‑readable JSON string values before serialization. This ensures byte‑identical signatures across platforms with different default normalization (e.g., macOS NFD vs. Linux/Windows NFC).

- **New Section 11.4 – Password Generation**  
  Adds a complete deterministic password derivation framework under the Generation branch:
  - A `PasswordRoot1` path with rotation support.
  - Account‑specific JSON objects (service, username, counter, charset, length) canonicalized via JCS and hashed to form unique derivation paths.
  - Predefined character sets (`PRINTABLE‑88`, `BASE‑62`, `BASE‑32`, `BASE‑16`, `BASE‑10`) with bucket shuffling to guarantee at least one character from each category.
  - Deterministic Fisher‑Yates shuffle using the HKDF‑Stream for unbiased selection.
  - Mandatory user notification of generation parameters; strength estimation is optional and non‑blocking.

Full Changes in table:
| Chapter # | Title | Modification |
| :--- | :--- | :--- |
| **6.5** | HKDF‑Stream Derivation for Deterministic Byte Streams | Remove origin 6.5, Added |
| **7.3** | JSON Canonicalization | Modified |
| **11.4.1** | Purpose and Scope | Added |
| **11.4.2** | Password Root | Added |
| **11.4.3** | Account Derivation Path | Added |
| **11.4.4** | Character Sets and Bucket Shuffling Algorithm | Added |
| **11.4.5** | Password Strength Notification | Added |

All changes are fully compatible with existing PCA v1.2 deployments and do not alter any previously defined derivation paths or security semantics.