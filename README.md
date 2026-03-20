<div align="center">

<img src="LephyCrypt/icons.jpg" width="96" height="96" alt="Lephy Crypt Logo" style="border-radius:20px"/>

# Lephy Crypt

**Military-grade file encryption for everyone.**  
AES-256-GCM · scrypt · HMAC-SHA256 · Chunk-level AAD

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![PyQt5](https://img.shields.io/badge/GUI-PyQt5-41CD52?style=flat-square&logo=qt&logoColor=white)](https://riverbankcomputing.com/software/pyqt/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![Security Audit](https://img.shields.io/badge/Security%20Audit-AI%20Reviewed-8B5CF6?style=flat-square)](#-ai-powered-security-audit)
[![Version](https://img.shields.io/badge/Version-3.8-0EA5E9?style=flat-square)](#)

</div>

---

## What is Lephy Crypt?

Lephy Crypt is a **local, open-source file and folder encryption application** with a clean desktop GUI. It encrypts any file or directory using a password — no cloud, no accounts, no telemetry. Everything stays on your machine.

It was designed with one principle: **if the cryptography is wrong, everything is wrong.** Every algorithm choice, every parameter, and every design decision was reviewed, challenged, and verified by multiple independent AI security systems before release.

---

## Table of Contents

- [Features](#-features)
- [Password Brute-Force Time Calculator](#-password-brute-force-time-calculator)
- [Security Architecture](#-security-architecture)
  - [Encryption Algorithm](#encryption-algorithm-aes-256-gcm)
  - [Key Derivation](#key-derivation-scrypt)
  - [Integrity Protection](#integrity-protection-hmac-sha256)
  - [Nonce Management](#nonce-management)
  - [File Format](#file-format)
  - [Memory Security](#memory-security)
  - [Filesystem Security](#filesystem-security)
- [Adaptive Security Profiles](#-adaptive-security-profiles)
- [AI-Powered Security Audit](#-ai-powered-security-audit)
- [Installation](#-installation)
- [Usage](#-usage)
- [File Format Specification](#-file-format-specification)
- [Threat Model](#-threat-model)
- [Known Limitations](#-known-limitations)
- [Security Report](#-security-report)

---

## ✨ Features

| Feature | Details |
|---|---|
| **Authenticated Encryption** | AES-256-GCM — every byte is both encrypted and authenticated |
| **Memory-Hard KDF** | scrypt with auto-selected profile — resistant to GPU/ASIC brute-force |
| **File + Folder support** | Single files and entire directory trees (ZIP-then-encrypt) |
| **Streaming engine** | O(1) RAM usage — encrypts 100 GB files with a 16 MB working set |
| **Two-pass decryption** | HMAC verified before any plaintext is written to disk |
| **Crash-safe temp files** | atexit + SIGTERM handlers wipe temp data on unexpected exit |
| **Adaptive profiles** | Auto-benchmarks your system; picks strongest affordable profile |
| **Zero telemetry** | Fully offline — no network calls, ever |
| **Secure deletion** | 3-pass overwrite before unlink on all temporary plaintext files |
| **Atomic output files** | Output created with O_CREAT\|O_EXCL at 0600 — never world-readable |

---

## 🔐 Password Brute-Force Time Calculator

Models real brute-force cracking times based on scrypt KDF parameters. 
**No data is sent to any server.**


|Site                |   [LephyCrypt](https://seesternn.github.io/LephyCrypt/)    |
| -------------------- | ----------------------------------------------- |


-----------------------------


## 🔐 Security Architecture

### Encryption Algorithm: AES-256-GCM

Lephy Crypt uses **AES-256-GCM** (Advanced Encryption Standard, 256-bit key, Galois/Counter Mode).

GCM is an **Authenticated Encryption with Associated Data (AEAD)** mode. This means it simultaneously provides:

- **Confidentiality** — ciphertext reveals nothing about plaintext without the key
- **Integrity** — any modification to the ciphertext is detected with overwhelming probability (2⁻¹²⁸ forgery chance)
- **Authentication** — decryption proves the data came from someone who held the correct key

This is the same algorithm used by TLS 1.3, Signal, and WhatsApp for message encryption. It is standardized by **NIST SP 800-38D**.

#### Why not AES-CBC or AES-CTR?

| Mode | Confidentiality | Integrity | Authentication |
|---|---|---|---|
| AES-CBC | ✅ | ❌ | ❌ |
| AES-CTR | ✅ | ❌ | ❌ |
| **AES-GCM** | **✅** | **✅** | **✅** |

CBC and CTR modes are malleable — an attacker can flip specific plaintext bits by modifying the ciphertext without detection. GCM catches any tampering immediately.

#### Chunk-Level Associated Data (AAD)

For large files, encryption is done in **16 MiB chunks**. Each chunk's GCM authentication tag is bound to the file header via **Associated Data**:

```
AAD = MAGIC + VERSION + SCRYPT_IDX + SALT + BASE_NONCE + CHUNK_COUNT
```

This means:
- Chunks cannot be reordered between files
- The scrypt profile cannot be silently downgraded
- The chunk count cannot be forged
- Any header modification invalidates all chunk authentication tags

---

### Key Derivation: scrypt

Passwords are never used directly as encryption keys. Lephy Crypt uses **scrypt** (RFC 7914) to derive a 256-bit key from your password.

scrypt is a **memory-hard** key derivation function. Unlike PBKDF2 or bcrypt, scrypt requires a large amount of RAM in addition to CPU time. This makes it exponentially more expensive to attack with GPU farms or custom ASICs, because memory bandwidth is the bottleneck — not raw compute.

#### Adaptive Profile System

Lephy Crypt benchmarks your hardware at startup and automatically selects the strongest profile your machine can handle:

| Profile | N | RAM Required | Approx. Time | Use Case |
|---|---|---|---|---|
| 🐢 **Light** | 2¹⁴ = 16 384 | 16 MB | ~0.4 s | Low-power / embedded |
| ⚖️ **Balanced** | 2¹⁵ = 32 768 | 32 MB | ~0.8 s | Standard laptops |
| 🔒 **Strong** | 2¹⁶ = 65 536 | 64 MB | ~1.5 s | Modern desktops |
| 🛡️ **Ultra** | 2¹⁷ = 131 072 | 128 MB | ~3–5 s | High-security systems |

The selected profile index is stored in the encrypted file header so decryption works correctly on any machine regardless of its hardware.

> ⚠️ If your system can only support the **Light** profile, Lephy Crypt displays a visible warning banner. You are never silently downgraded without notification.

---

### Integrity Protection: HMAC-SHA256

In addition to GCM's per-chunk authentication, Lephy Crypt computes an **outer HMAC-SHA256** over the entire file:

```
HMAC_key  = scrypt(password, salt)
HMAC_data = MAGIC + VERSION + SCRYPT_IDX + SALT + BASE_NONCE +
            STREAM_TAG + CHUNK_COUNT + all(chunk_length + chunk_ciphertext)
```

This outer MAC is verified in a **first pass before any decryption begins**. The key security property of this design:

> No plaintext byte is ever written to disk unless the entire file has already been authenticated.

This is the **Encrypt-then-MAC** construction, which is provably secure. Contrast this with MAC-then-Encrypt (used by older protocols like SSL 3.0), which is vulnerable to padding oracle attacks.

---

### Nonce Management

GCM security depends critically on **never reusing a (key, nonce) pair**.

- The **base nonce** is generated with `os.urandom(12)` — 96 bits of cryptographic randomness
- Per-chunk nonces are derived using **HKDF-Expand (RFC 5869)**:

```
chunk_nonce[i] = HKDF-Expand(key, info = base_nonce ‖ "chunk" ‖ uint64_be(i))[:12]
```

This deterministic derivation from a random base guarantees:
- All chunk nonces are unique within a file
- Nonce reuse across different files is negligible probability (2⁻⁹⁶ per pair)

---

### File Format

```
┌─────────────────────────────────────────────────┐
│  MAGIC      (4 bytes)  "LPHY"                   │
│  VERSION    (1 byte)   0x04                     │
│  SCRYPT_IDX (1 byte)   profile index 0–3        │
│  SALT       (32 bytes) os.urandom(32)           │
│  BASE_NONCE (12 bytes) os.urandom(12)           │
│  HMAC       (32 bytes) outer HMAC-SHA256        │
│  STREAM_TAG (4 bytes)  "STRM"                   │
│  CHUNK_COUNT(8 bytes)  uint64 big-endian        │
├─────────────────────────────────────────────────┤
│  CHUNK_LEN  (4 bytes)  uint32 big-endian        │  ─┐
│  CHUNK_DATA (N+16 bytes) AES-256-GCM ciphertext │   │ × n
│  ...                                            │  ─┘
└─────────────────────────────────────────────────┘
```

Every field in the header is covered by either the outer HMAC, the per-chunk AAD, or both. There is no unprotected metadata in the file.

---

### Memory Security

Key material is handled with explicit lifecycle management throughout the codebase:

| Material | Storage | Zeroed? | Method |
|---|---|---|---|
| Password (Worker) | `bytearray` | ✅ Yes | Slice assignment `buf[:] = b"\x00" * n` |
| Derived key | `bytearray` | ✅ Yes | `_zero_key()` in every `finally` block |
| Immutable `bytes` copy | `bytes` | ✅ Yes | `ctypes.memset()` before `del` |
| Qt password field | `QString` (C++) | ✅ Best-effort | 4-pass overwrite (0x00, 0xFF, 0xAA, space) |

The `ctypes.memset` approach for zeroing immutable Python `bytes` objects was identified as a necessary gap-filler during the AI security audit and implemented specifically in response to that finding.

---

### Filesystem Security

| Item | Protection |
|---|---|
| Output files | Created with `O_CREAT\|O_EXCL\|0o600` — atomically, never world-readable |
| Temp ZIP (folder mode) | Written to `~/.lephy_crypt/` (mode 0700) with 0600 permissions |
| Temp plaintext (decrypt) | Same secure directory, registered for crash-safe cleanup |
| Secure deletion | 3-pass random overwrite + `fsync` before `unlink` |
| Crash safety | `atexit` + `SIGTERM`/`SIGINT` handlers wipe all registered temp files |

> ⚠️ **SSD / CoW filesystem note:** On SSDs, APFS, btrfs, and ZFS, the operating system's flash translation layer or copy-on-write mechanism may retain physical copies of data even after overwrite. Lephy Crypt's 3-pass delete is a defence-in-depth measure. For maximum security, enable full-disk encryption (BitLocker, FileVault, LUKS) on your system.

---

## 🛡️ Adaptive Security Profiles

Lephy Crypt automatically detects the strongest scrypt profile your hardware supports by running a short benchmark at startup. You can also override the selection manually from the encryption page.

```
System benchmark result: Strong (64 MB) — ~1.4 s per operation
┌──────────────────────────────────────────────────────────┐
│  Security Profile                                        │
│  ○ 🐢 Light     ~0.4 s  · 16 MB  [⚠️ Not recommended]  │
│  ● ⚖️  Balanced  ~0.8 s  · 32 MB                        │
│  ○ 🔒 Strong    ~1.4 s  · 64 MB  [Recommended]          │
│  ○ 🛡️  Ultra     ~4.2 s  · 128 MB [Maximum security]     │
└──────────────────────────────────────────────────────────┘
```

The profile you select is embedded in the `.lcrypt` file header, protected by the outer HMAC. When you (or anyone) decrypts the file on a different machine, the exact same scrypt parameters are used — ensuring the password verification always works correctly regardless of the decrypting machine's hardware.

---

## 🤖 AI-Powered Security Audit

Lephy Crypt's security was not just designed — it was **adversarially reviewed** by multiple large language models acting as independent security auditors before any code was published.

### Audit Process

Four AI systems were used across multiple review rounds:

| AI System | Role |
|---|---|
| **Google Gemini** | Initial threat modelling, cryptographic primitive review |
| **OpenAI ChatGPT** | Code logic analysis, authentication flow review |
| **Claude Sonnet 4.6** | Deep static analysis, memory lifecycle audit, filesystem security |
| **Claude Opus 4.6** | Final adversarial review, finding verification, patch validation |

Each AI was given the full source code and asked to act as a penetration tester performing static code analysis — tasked to find real, evidence-based vulnerabilities, not theoretical concerns.

### Findings and Fixes

Across multiple audit rounds, the AI systems identified and the following were fixed:

#### Cryptographic Findings
| Finding | Description | Fix Applied |
|---|---|---|
| Missing chunk AAD | Chunks were not cryptographically bound to file header | Added AAD = header fields to every GCM chunk |
| Weak HMAC scope | Outer HMAC didn't cover MAGIC/VERSION/SCRYPT_IDX | Extended HMAC input to cover all header fields |
| No AAD on in-memory path | `encrypt_bytes` passed `None` AAD to GCM | Constructed AAD from `MAGIC + VERSION + SALT + NONCE` |
| Non-standard nonce derivation | Custom HMAC-truncate for chunk nonces | Upgraded to HKDF-Expand (RFC 5869) |

#### Memory Security Findings
| Finding | Description | Fix Applied |
|---|---|---|
| Immutable `bytes` key in heap | `bytes(key)` copy couldn't be zeroed via normal Python | `ctypes.memset(id(b) + header, 0, len(b))` before `del` |
| Password stored as `str` | Python strings are immutable and heap-persistent | Password immediately converted to `bytearray` on receipt |
| GUI password field not wiped | `QLineEdit.clear()` doesn't zero the C++ heap | 4-pass overwrite (0x00 / 0xFF / 0xAA / space) before clear |

#### Filesystem Security Findings
| Finding | Description | Fix Applied |
|---|---|---|
| TOCTOU race on output file | `open(dst,"wb")` + `chmod` — world-readable during write | Replaced with `os.open(O_CREAT\|O_EXCL, 0o600)` |
| No crash-safe temp cleanup | Temp plaintext ZIP persisted on power loss | `atexit` + `SIGTERM`/`SIGINT` registry wipes all temps |
| Single-pass secure delete | One overwrite is insufficient on HDDs | 3-pass random overwrite + `fsync` |
| Symlink traversal in folders | `is_file()` follows symlinks outside source dir | Added `not fp.is_symlink()` filter |

#### Authentication Findings
| Finding | Description | Fix Applied |
|---|---|---|
| Brute-force counter bypassable | Counter keyed on file path — reset by copying file | Re-keyed on `SHA256(salt)` — path-independent identity |
| Unbounded BF counter dict | Memory exhaustion via many distinct paths | Capped at 1024 entries with 1-hour TTL eviction |
| Strip/encode mismatch | `_check()` validated stripped pw; `_run()` sent unstripped bytes | Consistent `.strip()` before `.encode()` throughout |

### Audit Reports

The complete audit reports are included in this repository:

- 📄 [`SECURITY_ANALYSIS.md`](SECURITY_ANALYSIS.md) — Initial full static analysis (v1.0)

The final patch review was produced by **Claude Sonnet 4.6** and verified finding-by-finding against the updated source code. It confirmed 14 of 17 original findings were correctly resolved and identified remaining items for the next patch cycle.

---

## 📦 Installation

### Requirements

- Python 3.10 or newer
- pip

### Install dependencies

```bash
pip install PyQt5 cryptography
```

### Run

```bash
python main.py
```

### Optional: build a standalone executable

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name "LephyCrypt" --icon "icons.ico" main.py
```

---

## 🖥️ Usage

### Encrypting a file

1. Launch Lephy Crypt (`python main.py`)
2. Select the **Encrypt** tab
3. Drop your file onto the drop zone (or click to browse)
4. Choose an output path for the `.lcrypt` file
5. Enter and confirm your password
6. Select a security profile (or leave on auto-detected default)
7. Click **Encrypt Now**

### Encrypting a folder

1. Switch the mode toggle to **Folder**
2. Drop or browse to select a directory
3. Follow the same steps as file encryption
4. The entire directory tree is compressed and encrypted as a single `.lcrypt` archive

### Decrypting

1. Select the **Decrypt** tab
2. Drop your `.lcrypt` file onto the drop zone
3. Choose an output destination
4. Enter your password
5. Click **Decrypt Now**

File vs. folder archives are auto-detected — no manual mode selection needed for decryption.

---

## 📋 File Format Specification

Encrypted files use the extension `.lcrypt`. The binary format is:

```
Offset  Size  Field         Description
──────  ────  ─────────     ──────────────────────────────────────────
0       4     MAGIC         ASCII "LPHY" — identifies the format
4       1     VERSION       0x04 for current format
5       1     SCRYPT_IDX    scrypt profile index (0=Ultra … 3=Light)
6       32    SALT          cryptographic random salt for key derivation
38      12    BASE_NONCE    cryptographic random base nonce
50      32    HMAC          HMAC-SHA256 over the entire file (placeholder during write)
82      4     STREAM_TAG    ASCII "STRM"
86      8     CHUNK_COUNT   number of encrypted chunks (uint64 big-endian)
94      …     CHUNKS        repeated: CHUNK_LEN(4) + CHUNK_CIPHERTEXT(N+16)
```

The HMAC at offset 50 covers:
```
MAGIC + VERSION + SCRYPT_IDX + SALT + BASE_NONCE + STREAM_TAG + CHUNK_COUNT
+ concat(CHUNK_LEN[i] + CHUNK_CIPHERTEXT[i]) for i in 0..n
```

---

## 🎯 Threat Model

Lephy Crypt is designed to protect against:

| Threat | Protected? | Mechanism |
|---|---|---|
| Attacker reads encrypted file | ✅ Yes | AES-256-GCM confidentiality |
| Attacker modifies encrypted file | ✅ Yes | GCM authentication tags + outer HMAC |
| Attacker replaces chunks between files | ✅ Yes | Chunk-level AAD binds chunks to their header |
| Attacker downgrades scrypt profile | ✅ Yes | SCRYPT_IDX covered by outer HMAC |
| Brute-force via copied file path | ✅ Yes | Counter keyed on file salt, not path |
| Plaintext in temp files on crash | ✅ Yes | atexit + signal handlers, registered cleanup |
| Plaintext visible to other users | ✅ Yes | O_EXCL + 0600 atomic file creation |
| Memory scraping after decryption | ✅ Best-effort | ctypes zeroing, multi-pass GUI clear |
| Weak password chosen by user | ⚠️ Warned | Strength meter + minimum length enforcement |
| Full-disk access by attacker | ❌ Out of scope | Requires OS-level full-disk encryption |
| Keylogger / screen capture | ❌ Out of scope | Requires OS-level endpoint security |
| Quantum computing (future) | ❌ Not yet | AES-256 is quantum-resistant; scrypt is not post-quantum |

---

## ⚠️ Known Limitations

- **SSD / CoW filesystems:** Secure deletion is best-effort only. On SSDs, APFS, btrfs, or ZFS, physical block remanence may persist. Use full-disk encryption as your primary control.
- **AESGCM C-extension key copy:** The `cryptography` library copies the key into an OpenSSL C-level buffer that cannot be zeroed from Python. This is an architectural limitation of Python cryptography libraries, not a bug.
- **Windows file permissions:** POSIX 0600 permissions have limited effect on Windows. Windows ACLs are not currently set by Lephy Crypt.
- **Legacy format (v2/v3):** Files encrypted with earlier Lephy Crypt versions are supported for decryption but use weaker integrity protection (no chunk AAD). Re-encrypting with v3.8 is recommended.

---

## 📄 Security Report

The complete, unedited security reports from the AI audit are included in this repository:

| Document | Description |
|---|---|
| [`SECURITY_ANALYSIS.md`](SECURITY_ANALYSIS.md) | Full initial static analysis — all 17 findings with evidence, impact, and fixes |


These reports were produced by Claude Sonnet 4.6 performing manual static code analysis across all source files. They are published unedited to provide full transparency about the security posture of this application.

---

## 📜 License

Apache License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Lephy Crypt** — Because your files are yours.

*Built with Python · Secured with scrypt + AES-256-GCM · Audited by AI*

</div>
