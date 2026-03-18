# Security Analysis — Lephy Crypt

> **Analyst:** AI Static Code Review
> **Date:** 2026-03-19
> **Files analyzed:** `crypto.py`, `gui.py`, `main.py`, `worker.py`
> **Method:** Manual static code analysis
> **Scope:** Full source review — cryptography, memory, filesystem, input handling, authentication, dependency usage

---

## Executive Summary

Lephy Crypt v3.9 demonstrates a high level of security maturity for a file-encryption desktop application. The codebase implements encrypt-then-MAC correctly, constant-time comparisons throughout, atomic file creation with O_EXCL|O_NOFOLLOW, a bounded brute-force delay mechanism, crash-safe temp-file cleanup via atexit and signal handlers, and best-effort key zeroing at both Python and C levels. Three low-severity findings and four informational observations were identified; no critical or medium vulnerabilities were found in the reviewed code.

**Overall score: 8.5 / 10**
**Verdict:** Safe to use with minor hardening recommended.

---

## Findings Overview

| ID | Title | Severity | File | Line(s) | Status |
|----|-------|----------|------|---------|--------|
| LOW-01 | Double file open in `_read_file_header` creates TOCTOU window | 🟡 Low | `crypto.py` | 631–685 | 🔓 Open |
| LOW-02 | `threading.Lock` acquired inside signal handler — potential deadlock | 🟡 Low | `crypto.py` | 352–366 | 🔓 Open |
| LOW-03 | `PwField.clear_secure()` cannot zero Qt C++ heap allocation | 🟡 Low | `gui.py` | 216–232 | 🔓 Open |
| INFO-01 | `benchmark_default_profile()` executes multiple scrypt calls at import time | ℹ️ Info | `crypto.py` | 228 | 🔓 Open |
| INFO-02 | Legacy `FILE_FORMAT_BYTES` path applies redundant double-authentication | ℹ️ Info | `crypto.py` | 435–497 | 🔓 Open |
| INFO-03 | Brute-force counter falls back to raw path string when file is unreadable | ℹ️ Info | `worker.py` | 21–34 | 🔓 Open |
| INFO-04 | Operational benchmark results logged at `WARNING` severity | ℹ️ Info | `crypto.py` | 229–234 | 🔓 Open |

---

## Detailed Findings

### [LOW-01] — Double file open in `_read_file_header` creates TOCTOU window

**Severity:** 🟡 Low
**File:** `crypto.py` — Lines 631–685
**Impact:** An attacker with concurrent write access to the encrypted file could substitute a crafted file between the two `open()` calls, causing the header fields used for HMAC verification (salt, nonce, stored_mac) to be read from a different file than the one whose chunk_count drives decryption iteration.

**Vulnerable Code**
```python
# First open — reads magic, version, salt, nonce, stored_mac, peek (4 bytes)
with open(src, "rb") as f:
    magic   = f.read(4)
    ...
    peek    = f.read(4)

# --- window: file could be replaced here ---

# Second open — seeks to count_offset to read chunk_count
with open(src, "rb") as f:
    f.seek(count_offset)
    count_field = f.read(8)
```

**Explanation**
The function opens `src` twice with separate file descriptors, and does not keep a single file descriptor open across both reads. Between the two `open()` calls an adversary with write access (or a racing process) could replace the file, leading to a mismatch between the header fields (salt/nonce/mac) used to derive the key and verify integrity and the chunk_count used to iterate during decryption. In practice exploitation requires write access to the file, but the fix is trivial.

**Recommended Fix**
```python
def _read_file_header(src: str) -> dict:
    try:
        with open(src, "rb") as f:
            magic   = f.read(4)
            version = f.read(1)
            # ... (all existing validation) ...
            peek    = f.read(4)

            # Read chunk_count in the SAME open context — no second open needed
            if peek == STREAM_TAG:
                count_field = f.read(8)
                if len(count_field) < 8:
                    raise StructuralCorruptionError(
                        "File is truncated — chunk count field is incomplete.")
                chunk_count = struct.unpack(">Q", count_field)[0]
                if chunk_count > MAX_CHUNK_COUNT:
                    raise StructuralCorruptionError(
                        f"Chunk count {chunk_count:,} exceeds safety limit "
                        f"({MAX_CHUNK_COUNT:,}).")
                stream_offset = f.tell()
            # ... rest of existing logic
    except StructuralCorruptionError:
        raise
    except OSError as e:
        raise StructuralCorruptionError(f"Cannot read file: {e}")
```

---

### [LOW-02] — `threading.Lock` acquired inside signal handler — potential deadlock

**Severity:** 🟡 Low
**File:** `crypto.py` — Lines 352–366
**Impact:** If SIGTERM or SIGINT is delivered to the main thread while `_temp_registry_lock` is held (e.g., between the `with` entry and exit in `_register_temp`), the signal handler will block indefinitely trying to acquire the same non-reentrant lock, freezing the process and preventing cleanup.

**Vulnerable Code**
```python
def _cleanup_all_temps(signum=None, frame=None) -> None:
    with _temp_registry_lock:          # non-reentrant lock — deadlocks if
        paths = list(_temp_registry)   # main thread already holds it
    for p in paths:
        _secure_delete(p)
        _deregister_temp(p)

atexit.register(_cleanup_all_temps)
signal.signal(signal.SIGTERM, _cleanup_all_temps)
signal.signal(signal.SIGINT,  _cleanup_all_temps)
```

**Explanation**
`threading.Lock` is not reentrant. In CPython, signal handlers run in the main thread between bytecode instructions. If a signal arrives while `_register_temp` or `_deregister_temp` has the lock held, the signal handler calls `_cleanup_all_temps` which immediately tries to acquire the same lock, resulting in a deadlock. The window is narrow (a few bytecodes) but non-zero, especially under OS signal pressure.

**Recommended Fix**
```python
def _cleanup_all_temps(signum=None, frame=None) -> None:
    # Use non-blocking acquire in signal-handler context to avoid deadlock.
    # If the lock is held, take a best-effort snapshot or skip.
    acquired = _temp_registry_lock.acquire(blocking=False)
    try:
        paths = list(_temp_registry)
    finally:
        if acquired:
            _temp_registry_lock.release()
    for p in paths:
        try:
            _secure_delete(p)
        except Exception:
            pass
        _deregister_temp(p)
```

---

### [LOW-03] — `PwField.clear_secure()` cannot zero Qt C++ heap allocation

**Severity:** 🟡 Low
**File:** `gui.py` — Lines 216–232
**Impact:** After `clear_secure()` returns, the original password string remains in the Qt C++ heap (a `QString` allocation) until the Qt garbage-collector reclaims or overwrites it. A memory-scraping attack or swap-file analysis may recover the password.

**Vulnerable Code**
```python
def clear_secure(self):
    self.edit.setEchoMode(QLineEdit.Password)
    n = len(self.edit.text())
    if n:
        for filler in (
            b"\x00" * n, b"\xff" * n, b"\xaa" * n, b" " * n,
        ):
            self.edit.setText(filler.decode("latin-1"))
    self.edit.clear()
    # Qt C++ heap still holds the original password — not zeroed
```

**Explanation**
`setText()` allocates a new `QString` on the C++ heap each call; it does not overwrite the buffer of the previous `QString` in place. Calling `setText` four times with filler strings creates four new heap allocations while the original password `QString` persists until Qt's allocator reuses the block. The code comment at line 221 acknowledges this ("Qt C++ heap cannot be guaranteed zeroed from Python"). This is a documented limitation of the PyQt5 binding layer, not a code defect — however it is a residual risk that consumers of this library should understand.

**Recommended Fix**

There is no fully reliable fix within PyQt5 Python bindings. The strongest available mitigation is to use a `QLineEdit` subclass that sets the `inputMethodHints` to prevent IME caching, and to hold passwords in `bytearray` objects passed via `bytes`/`ctypes` interop rather than `str`. Document explicitly that this widget does not meet Controlled Cryptographic Item (CCI) memory-hygiene requirements and that full-disk encryption (LUKS/BitLocker/FileVault) must be relied upon as the primary control.

```python
def clear_secure(self):
    """
    Best-effort overwrite. The Qt C++ QString heap allocation for the
    original password CANNOT be zeroed from Python. Rely on FDE as the
    primary control for password-in-memory confidentiality.
    """
    self.edit.setEchoMode(QLineEdit.Password)
    n = len(self.edit.text())
    if n:
        for filler in (b"\x00" * n, b"\xff" * n, b"\xaa" * n, b" " * n):
            self.edit.setText(filler.decode("latin-1"))
    self.edit.clear()
    # Note: original QString remains on Qt heap until allocator reclaims it.
    # No fix available at the PyQt5 binding layer.
```

---

### [INFO-01] — `benchmark_default_profile()` executes multiple scrypt calls at module import time

**Severity:** ℹ️ Info
**File:** `crypto.py` — Line 228
**Impact:** Any `import crypto` (including in tests, tooling, or scripted decryption pipelines) runs up to 7 scrypt KDF operations before returning, adding 0.1–8 s of latency without caller awareness.

**Vulnerable Code**
```python
# Module scope — executes unconditionally at import time
DEFAULT_USER_PROFILE_IDX: int = benchmark_default_profile()
```

**Explanation**
`benchmark_default_profile()` iterates `USER_PROFILES` from strongest to weakest and runs `_scrypt_derive_raw` for each until one finishes within one second. In the worst case (fast machine, all profiles succeed quickly) all 7 profiles are attempted. For automated test suites, CI pipelines, or scripted use of the module, this is unexpectedly expensive and cannot be opted out of.

**Recommended Fix**
```python
# Lazy-init: benchmark runs only on first access, not on import.
_DEFAULT_USER_PROFILE_IDX: int | None = None

def get_default_user_profile_idx() -> int:
    global _DEFAULT_USER_PROFILE_IDX
    if _DEFAULT_USER_PROFILE_IDX is None:
        _DEFAULT_USER_PROFILE_IDX = benchmark_default_profile()
    return _DEFAULT_USER_PROFILE_IDX

# Replace all references to DEFAULT_USER_PROFILE_IDX with
# get_default_user_profile_idx() — or expose as a module property.
```

---

### [INFO-02] — Legacy `FILE_FORMAT_BYTES` path applies redundant double-authentication

**Severity:** ℹ️ Info
**File:** `crypto.py` — Lines 435–497
**Impact:** No security weakness; increases complexity and minor CPU overhead. Could cause maintenance confusion about which MAC is authoritative.

**Vulnerable Code**
```python
# In encrypt_bytes / _decrypt_bytes_raw:
ct  = AESGCM(kb).encrypt(nonce, data, aad)   # GCM provides AEAD tag
mac = hmac.new(kb, salt + nonce + ct, hashlib.sha256).digest()  # outer MAC
# Both the GCM tag and the outer HMAC protect integrity/authenticity.
```

**Explanation**
AES-256-GCM is an AEAD cipher: every `AESGCM.encrypt()` call appends a 16-byte authentication tag that is verified on `decrypt()`. Adding an outer HMAC-SHA256 over `salt + nonce + ct` (where `ct` includes the GCM tag) is correct and provides defense in depth, but is architecturally redundant. The only risk is that future maintainers might mistakenly remove the outer HMAC believing the GCM tag is sufficient, or vice versa, without understanding both layers are present.

**Recommended Fix**
No code change required. Add a code comment explaining the intentional layering:

```python
# Dual authentication is intentional:
# 1. AESGCM.encrypt() appends a 16-byte GCM authentication tag (AEAD).
# 2. The outer HMAC-SHA256 over (salt ‖ nonce ‖ ciphertext+GCM_tag)
#    provides a second independent authentication layer and commits the
#    key derivation inputs (salt) into the integrity proof.
# DO NOT remove either layer without updating both encrypt and decrypt paths.
ct  = AESGCM(kb).encrypt(nonce, data, aad)
mac = hmac.new(kb, salt + nonce + ct, hashlib.sha256).digest()
```

---

### [INFO-03] — Brute-force counter falls back to raw path string when file is unreadable

**Severity:** ℹ️ Info
**File:** `worker.py` — Lines 21–34
**Impact:** When a file is unreadable at the OS level, brute-force delay tracking keys on path string instead of the cryptographic salt. Renamed or copied files using the same path would share one counter; files at different paths would have independent counters.

**Vulnerable Code**
```python
def _get_file_salt_id(path: str) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(6)
            salt = f.read(32)
        if len(salt) == 32:
            return hashlib.sha256(salt).hexdigest()
    except OSError:
        pass
    return path   # fallback: raw path string
```

**Explanation**
The salt-based ID is the correct cryptographic identity because it survives renames and copies. The path fallback activates only when the file is unreadable (permission denied, network loss, etc.). In such cases the brute-force counter is scoped to the path, not the file identity. An adversary who moves a file to a new path after accumulating failures could, in the fallback scenario, reset the effective counter. This is an edge case with minimal practical impact since an unreadable file also cannot be decrypted.

**Recommended Fix**
```python
def _get_file_salt_id(path: str) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(6)   # MAGIC(4) + VERSION(1) + SCRYPT_IDX(1)
            salt = f.read(32)
        if len(salt) == 32:
            return hashlib.sha256(salt).hexdigest()
    except OSError:
        pass
    # Fallback: hash the path to avoid storing a raw filesystem path in the
    # in-memory counter dict, which could leak path information in a heap dump.
    return hashlib.sha256(path.encode("utf-8", errors="replace")).hexdigest()
```

---

### [INFO-04] — Operational benchmark results logged at `WARNING` severity

**Severity:** ℹ️ Info
**File:** `crypto.py` — Lines 229–234
**Impact:** If a log aggregator or SIEM ingests these logs, the scrypt profile selection and weak-profile flag will generate false-positive warnings in alerting pipelines.

**Vulnerable Code**
```python
logging.warning(
    "benchmark default user profile: %s (user_idx=%d, scrypt_idx=%d)",
    USER_PROFILES[DEFAULT_USER_PROFILE_IDX]["label"],
    DEFAULT_USER_PROFILE_IDX,
    USER_PROFILES[DEFAULT_USER_PROFILE_IDX]["scrypt_idx"],
)
```

**Explanation**
A comment in the source (`INFO-04: root logger is WARNING; logging.info() here would be a no-op`) explains the choice: the root logger is capped at WARNING so `logging.info()` would be silently dropped. However, using WARNING for routine operational messages conflates operational events with genuine warnings, and any connected log aggregator will treat these as warning-level alerts.

**Recommended Fix**
```python
# Use a named logger instead of the root logger so it can be configured
# independently, allowing INFO messages to be routed without the WARNING cap.
_logger = logging.getLogger("lephy_crypt")
_logger.setLevel(logging.DEBUG)   # module logger; root logger still caps externals

_logger.info(
    "Benchmark default user profile: %s (user_idx=%d, scrypt_idx=%d)",
    USER_PROFILES[DEFAULT_USER_PROFILE_IDX]["label"],
    DEFAULT_USER_PROFILE_IDX,
    USER_PROFILES[DEFAULT_USER_PROFILE_IDX]["scrypt_idx"],
)
if SCRYPT_WEAK_PROFILE:
    _logger.warning(
        "Low scrypt profile active (N=%d) — brute-force resistance reduced.",
        SCRYPT_PARAMS["N"])
```

---

## Cryptographic Assessment

| Component | Algorithm | Standard | Verdict |
|-----------|-----------|----------|---------|
| Symmetric encryption | AES-256-GCM | NIST SP 800-38D | ✅ |
| Key derivation | scrypt (N≥2¹⁴, r=8, p≥1) | RFC 7914 | ✅ |
| Integrity / authentication (streaming) | HMAC-SHA256 over full ciphertext stream | FIPS 198-1 | ✅ |
| Integrity / authentication (legacy) | HMAC-SHA256 + AES-GCM AEAD tag | FIPS 198-1 | ✅ |
| Chunk nonce derivation | HMAC-SHA256(key, base_nonce ‖ "chunk" ‖ uint64_be(i))[:12] | HKDF-like (RFC 5869 inspired) | ✅ |
| Random salt/nonce generation | `os.urandom(32)` / `os.urandom(12)` | NIST SP 800-90B | ✅ |
| Constant-time MAC comparison | `hmac.compare_digest()` | FIPS 198-1 | ✅ |

**Key derivation** uses scrypt via `hashlib.scrypt` with a transparent fallback to `EVP_PBE_scrypt` via ctypes when OpenSSL 3.x's 32 MB memory cap fires. The ctypes bypass passes `maxmem=UINT64_MAX`, which removes the cap correctly; error return codes are checked. The default profile (chosen by runtime benchmark) targets ≤1 s and a minimum of N=2¹⁴ (16 MB). Profiles are stored in the file header as a single-byte index, preventing cross-machine decryption failures.

**Nonce management** is sound: `base_nonce` (12 bytes of `os.urandom`) is unique per encryption operation; per-chunk nonces are derived deterministically via HMAC so they are unique-per-chunk without requiring storage. The chunk index is encoded as a big-endian uint64, eliminating counter overflow for any file up to ~295 EB at 16 MiB chunks.

**Integrity scheme** follows encrypt-then-MAC: the outer HMAC is committed to the full ciphertext byte stream (length fields + encrypted chunks) before any decryption output is written. HMAC verification passes before Pass 2 begins, preventing any plaintext from being written to disk unless the MAC matches.

**Chunk count binding** — the `chunk_count` field is included in the HMAC input from the first update, preventing a truncation attack where an attacker removes trailing chunks and a verifier accepts the shortened ciphertext as authentic.

---

## Memory & Secrets Handling

**Password encoding** — passwords enter the system as `str` (PyQt5 GUI) and are encoded to `bytes` via `.encode("utf-8")` at a single point (`_run()` / `_run_verify()`) immediately before the `Worker` constructor. The Worker constructor converts to `bytearray(self._pw_buf)` immediately, discarding the intermediate `bytes` object (which is subject to Python interning and GC but not directly zeroable).

**Key material lifecycle** — `derive_key()` returns a `bytearray`; all encryption and decryption functions hold the derived key as both a `bytearray` (for slice-zeroing via `_zero_key`) and a short-lived `bytes` copy (`kb = bytes(key)`) passed to `AESGCM()`. The `bytes` copy is zeroed best-effort via `_zero_bytes_obj` (ctypes `memset` directly onto the CPython object's data buffer) in a `finally` block. This addresses the AESGCM constructor retaining an internal copy of the key bytes, though the AESGCM internal buffer itself cannot be zeroed from Python.

**Leak points (residual risk):**

| Point | Material | Mitigation | Residual risk |
|-------|----------|-----------|---------------|
| Qt `QLineEdit` C++ heap | Password string | `clear_secure()` multi-pass `setText()` | Cannot zero Qt allocations from Python (LOW-03) |
| `AESGCM` internal key buffer | AES-256 key | `_zero_bytes_obj(kb)` on outer bytes; `del key` | AESGCM C buffer not directly accessible |
| `pw_bytes = bytes(self._pw_buf)` in `Worker.run()` | Password bytes | `_zero_bytes_obj(pw_bytes)` in `finally` | CPython-specific; not portable to PyPy |
| Log file `~/.lephy_crypt/lephy_crypt.log` | No secrets logged | Secrets never written to log | None observed |
| Swap / hibernation | Any heap material | Outside scope — use FDE | OS-level control required |

The `finally` blocks in `Worker.run()`, `encrypt_file()`, `decrypt_file()`, and `_decrypt_bytes_raw()` all consistently zero both the `bytearray` key and the `bytes` copy before deletion. No code path was found where a successful or failed operation exits without attempting zeroing.

---

## Filesystem & Permissions

| File | Location | Permissions | Cleanup strategy | Crash-safe? |
|------|----------|-------------|-----------------|-------------|
| Encrypted output `.lcrypt` | Caller-specified | 0600 (`_open_secure` O_CREAT\|O_EXCL) | `_secure_delete` on failure (MED-08) | ✅ Yes |
| Decrypted temp `.lcpart` | `~/.lephy_crypt/` (0700 dir) | 0600 (`_open_secure`) | `_secure_delete` in `finally`; `atexit` + SIGTERM/SIGINT | ✅ Yes |
| Folder ZIP temp `.zip` | `~/.lephy_crypt/` (0700 dir) | 0600 (`os.chmod` post-create) | `_secure_delete` in `finally`; `atexit` + SIGTERM/SIGINT | ✅ Yes |
| Log file `lephy_crypt.log` | `~/.lephy_crypt/` (0700 dir) | 0600 (post-create `os.chmod`) | RotatingFileHandler (1 MiB × 3 backups) | N/A |

`_secure_delete` performs a 3-pass overwrite (random bytes × 3, with `fsync` between passes) before unlinking. The function opens with `O_RDWR|O_NOFOLLOW` to prevent symlink-redirect attacks where a temp file is replaced with a symlink between stat and open. `O_NOFOLLOW` is conditionally included via `getattr(os, "O_NOFOLLOW", 0)` for Windows portability.

`_secure_move()` preserves 0600 permissions on cross-device moves by using `os.open(O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW, 0o600)` explicitly, bypassing `shutil.copy2()` which applies the process umask (typically 0o644).

The code explicitly documents that 3-pass overwrite cannot guarantee physical data erasure on SSDs, APFS, btrfs, ZFS, or NTFS-with-VSS, and recommends full-disk encryption as the primary control. This is technically accurate and appropriately disclosed.

---

## What Was NOT Changed / Out of Scope

- **Windows O_NOFOLLOW gap** — `getattr(os, "O_NOFOLLOW", 0)` falls back to `0` on Windows, meaning symlink protection in `_open_secure`, `_secure_delete`, and `_secure_move` is silently absent on Windows. This is documented behaviour but represents a meaningful security difference between platforms that is not surfaced to the user.
- **PyPy / non-CPython runtime support** — `_zero_bytes_obj` silently fails on non-CPython runtimes; there is no runtime check or warning. Out of scope for this review.
- **`sys.argv` parsing in `main.py`** — The `DEFAULT=` argument is parsed with a simple string comparison; no injection surface was identified. No findings.
- **Third-party dependency versions** — PyQt5 and `cryptography` package versions are not pinned in the reviewed files. Supply-chain risk from unpinned dependencies is out of scope.

---

## Improvement Roadmap

| Priority | Action | Effort | Impact |
|----------|--------|--------|--------|
| 🔴 Immediate | Consolidate `_read_file_header` to a single `open()` (LOW-01) | Low | Medium |
| 🔴 Immediate | Replace blocking `threading.Lock` acquire in signal handler with `acquire(blocking=False)` (LOW-02) | Low | Low |
| 🟠 Short-term | Convert `benchmark_default_profile()` to lazy initialization (INFO-01) | Low | Medium |
| 🟠 Short-term | Replace `_bf_counts` path fallback with hashed path (INFO-03) | Low | Low |
| 🟠 Short-term | Introduce a named `logging.getLogger("lephy_crypt")` and use `INFO` for operational messages (INFO-04) | Low | Low |
| 🟡 Long-term | Investigate a C extension or ctypes shim to overwrite Qt `QString` buffers in `clear_secure()` (LOW-03) | High | Medium |
| 🟡 Long-term | Surface a visible warning in the GUI when running on Windows (O_NOFOLLOW unavailable, overwrite ineffective on SSDs) | Medium | Medium |
| 🟡 Long-term | Pin `cryptography` and `PyQt5` dependency versions and add a `requirements.txt` with hash verification | Low | High |

---

## Changelog

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-03-19 | Initial automated static analysis |

---

> _Analysis method: Automated static code analysis — no code was executed._
