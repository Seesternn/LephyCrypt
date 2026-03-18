"""
Lephy Crypt — Cryptographic Engine  (v3.9)
==========================================
Security fixes from patch review:
  NEW-CRIT-01 : _temp_path() generates path without creating file — fixes O_EXCL clash
  NEW-MED-01  : (gui.py) MIN_PASSWORD_LENGTH=8 restored
  NEW-MED-02  : Legacy decrypt path uses _open_secure()
  NEW-MED-03  : _secure_move() restored for cross-device temp file moves
  NEW-MED-04  : Probe salt restored to os.urandom(32)
  NEW-LOW-01  : encrypt_bytes binds kb; _zero_bytes_obj(kb) in finally
  NEW-LOW-02  : RotatingFileHandler restored (1 MiB × 3 backups)
  NEW-LOW-03  : Symlink filter restored in encrypt_folder

File format FILE_FORMAT_STREAM (0x03):
  MAGIC(4) VERSION(1) SCRYPT_IDX(1) SALT(32) BASE_NONCE(12) HMAC(32)
  STREAM_TAG(4) CHUNK_COUNT(8)
  [ CHUNK_LEN(4) + CHUNK_DATA(N+16) ] × n

File format FILE_FORMAT_BYTES (0x02) — in-memory / legacy:
  MAGIC(4) VERSION(1) SALT(32) NONCE(12) HMAC(32) CIPHERTEXT+TAG
"""

import os
import re
import sys
import math
import hmac
import stat
import struct
import ctypes
import atexit
import signal
import logging
import hashlib
import zipfile
import shutil
import tempfile
import threading
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Typed integrity exceptions ────────────────────────────────────────────────
# Subclass ValueError so existing `except ValueError` callers keep working,
# but GUI and Worker can now catch specific categories independently.

class StructuralCorruptionError(ValueError):
    """File header is structurally invalid — wrong magic, truncated header,
    unknown version, out-of-range scrypt index, impossible chunk_count.
    These checks require NO password.  Almost always means truncation,
    bit-rot in transfer, or not a .lcrypt file at all."""

class AuthenticationError(ValueError):
    """File structure is valid and KDF succeeded but HMAC does not match.
    Either the password is wrong OR the ciphertext was tampered with after
    encryption.  We cannot distinguish the two by design (oracle prevention)."""

class ContentCorruptionError(ValueError):
    """HMAC passed (password correct) but an individual AES-GCM chunk tag
    failed.  Indicates partial in-place modification or storage-layer bit-flip
    AFTER the outer HMAC was verified.  Carries chunk index in self.chunk."""
    def __init__(self, message: str, chunk: int):
        super().__init__(message)
        self.chunk = chunk


# ── Version (LOW-05) ──────────────────────────────────────────────────────────
APP_VERSION          = "3.9"

# LOW-12: separate version bytes so streaming and in-memory formats can never
# be confused by a parser that reads the wrong layout.
FILE_FORMAT_STREAM  = b"\x03"   # streaming v3: SCRYPT_IDX in header
FILE_FORMAT_BYTES   = b"\x02"   # in-memory / legacy: no SCRYPT_IDX
FILE_FORMAT_VERSION = FILE_FORMAT_STREAM   # alias used by encrypt_file
FILE_FORMAT_V2      = FILE_FORMAT_BYTES    # alias for legacy decrypt path

# ── Secure log directory (LOW-03) ─────────────────────────────────────────────
from logging.handlers import RotatingFileHandler as _RotatingFileHandler

_log_dir  = Path.home() / ".lephy_crypt"
_log_dir.mkdir(mode=0o700, exist_ok=True)
_log_path = _log_dir / "lephy_crypt.log"

# NEW-LOW-02: RotatingFileHandler — prevents unbounded log growth (max 1 MiB × 3)
_log_handler = _RotatingFileHandler(
    str(_log_path), maxBytes=1 * 1024 * 1024, backupCount=3, encoding="utf-8")
_log_handler.setFormatter(
    logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
_root_logger = logging.getLogger()
if not any(isinstance(h, _RotatingFileHandler) for h in _root_logger.handlers):
    _root_logger.addHandler(_log_handler)
_root_logger.setLevel(logging.WARNING)

try:
    if _log_path.exists():
        os.chmod(_log_path, stat.S_IRUSR | stat.S_IWUSR)   # 0600
except OSError:
    pass

# ── Constants ─────────────────────────────────────────────────────────────────
SCRYPT_PROFILES = [
    {"N": 2 ** 17, "r": 8, "p": 1, "label": "Ultra (128 MB)"},
    {"N": 2 ** 16, "r": 8, "p": 1, "label": "High (64 MB)"},
    {"N": 2 ** 15, "r": 8, "p": 1, "label": "Standard (32 MB)"},
    {"N": 2 ** 14, "r": 8, "p": 2, "label": "Balanced (16 MB)"},
    # Indices 4-6: appended after v3.9 — existing files (idx 0-3) unaffected
    {"N": 2 ** 18, "r": 8, "p": 1, "label": "Extreme (256 MB)"},
    {"N": 2 ** 19, "r": 8, "p": 1, "label": "Insane (512 MB)"},
    {"N": 2 ** 20, "r": 8, "p": 1, "label": "Max (1 GB)"},
]

# PROFILE-1: User-facing profiles ordered ascending by strength (Light → Max).
# scrypt_idx maps into SCRYPT_PROFILES[] — those indices are stored in the file
# header and MUST NOT be reordered (would break decryption of existing archives).
# Why not higher than 1 GB? scrypt memory = N × r × 128 B.  N=2²⁰ → 1 GB already
# takes ~8 s per KDF call on a mid-range CPU; anything beyond that is impractical
# for interactive use and typically slower than a well-configured Argon2id.
USER_PROFILES: list[dict] = [
    {"label": "Light",   "scrypt_idx": 3, "desc": "N=2¹⁴  16 MB RAM  ~0.1 s  Fastest"},
    {"label": "Balanced","scrypt_idx": 2, "desc": "N=2¹⁵  32 MB RAM  ~0.2 s"},
    {"label": "Strong",  "scrypt_idx": 1, "desc": "N=2¹⁶  64 MB RAM  ~0.5 s"},
    {"label": "Ultra",   "scrypt_idx": 0, "desc": "N=2¹⁷  128 MB RAM  ~1 s"},
    {"label": "Extreme", "scrypt_idx": 4, "desc": "N=2¹⁸  256 MB RAM  ~2 s"},
    {"label": "Insane",  "scrypt_idx": 5, "desc": "N=2¹⁹  512 MB RAM  ~4 s"},
    {"label": "Max",     "scrypt_idx": 6, "desc": "N=2²⁰  1 GB RAM  ~8 s  Strongest"},
]

# ── OpenSSL 3.x scrypt cap bypass ────────────────────────────────────────────
# Python's hashlib.scrypt calls EVP_PBE_scrypt(maxmem=0) which OpenSSL 3.x
# resolves to ~32 MB.  Profiles above Balanced (32 MB) fail with
# ValueError("memory limit exceeded").  We call EVP_PBE_scrypt directly via
# ctypes with maxmem=UINT64_MAX to remove the cap.  hashlib is tried first
# for portability; ctypes path is only used when the cap fires.

import ctypes as _ctypes
import ctypes.util as _ctypes_util

_UINT64_MAX  = (1 << 64) - 1
_EVP_scrypt  = None   # lazy-loaded


def _load_evp_scrypt():
    """
    Lazy-load EVP_PBE_scrypt from the system's libcrypto.

    FIX-LIBCRYPTO-01: ctypes.util.find_library("crypto") returns None on many
    Windows installations and some Linux setups where OpenSSL ships under a
    versioned name (e.g. libcrypto-3-x64.dll, libcrypto.so.3).  We now try a
    prioritised candidate list that covers all common platform layouts before
    giving up.  Security properties are unchanged — we still call the same
    EVP_PBE_scrypt symbol with the same arguments; only the library-discovery
    path is widened.
    """
    global _EVP_scrypt
    if _EVP_scrypt is not None:
        return _EVP_scrypt

    # Build candidate list: start with what find_library says (may be None),
    # then add known platform-specific names.
    candidates: list[str] = []

    found = _ctypes_util.find_library("crypto")
    if found:
        candidates.append(found)

    if sys.platform == "win32":
        # OpenSSL 3.x (default since ~2022) and 1.1.x installer filenames
        candidates += [
            "libcrypto-3-x64.dll",
            "libcrypto-3.dll",
            "libcrypto-1_1-x64.dll",
            "libcrypto-1_1.dll",
        ]
    elif sys.platform == "darwin":
        candidates += [
            "libcrypto.3.dylib",
            "libcrypto.1.1.dylib",
            "/usr/local/lib/libcrypto.dylib",
            "/opt/homebrew/lib/libcrypto.dylib",
        ]
    else:
        # Linux / other POSIX
        candidates += [
            "libcrypto.so.3",
            "libcrypto.so.1.1",
            "libcrypto.so",
        ]

    # Also try extracting the path from Python's own _ssl extension — it is
    # linked against the same libcrypto that we need, so its DT_NEEDED / load
    # path is a reliable last-resort hint.
    try:
        import _ssl as _ssl_ext, ctypes.util as _cu
        _ssl_path = getattr(_ssl_ext, "__file__", None)
        if _ssl_path:
            # On Windows the DLL sits next to python3xx.dll; on Linux/macOS
            # CDLL(None) gives the process handle which also exports the syms.
            candidates.append(None)   # type: ignore[arg-type]  # process handle
    except Exception:
        pass

    for name in candidates:
        try:
            lib = _ctypes.CDLL(name)
            fn  = lib.EVP_PBE_scrypt
            fn.restype  = _ctypes.c_int
            fn.argtypes = [
                _ctypes.c_char_p, _ctypes.c_size_t,
                _ctypes.c_char_p, _ctypes.c_size_t,
                _ctypes.c_uint64, _ctypes.c_uint64, _ctypes.c_uint64,
                _ctypes.c_uint64,
                _ctypes.c_char_p, _ctypes.c_size_t,
            ]
            # Smoke-test: call with a tiny N to confirm the symbol actually
            # works before caching it.  Uses a fresh random salt to avoid
            # any caching artefacts.
            _test_out = _ctypes.create_string_buffer(32)
            _test_salt = os.urandom(16)
            _rc = fn(b"test", 4, _test_salt, 16,
                     2**14, 8, 1, _UINT64_MAX, _test_out, 32)
            if _rc != 1:
                continue   # symbol present but call failed — try next
            _ctypes.memset(_test_out, 0, 32)   # wipe test key material
            _EVP_scrypt = fn
            logging.warning(
                "libcrypto loaded via ctypes candidate %r — "
                "OpenSSL memory cap bypassed for high-RAM scrypt profiles.", name)
            return fn
        except (OSError, AttributeError):
            continue

    return None


def _scrypt_ctypes(password: bytes, salt: bytes,
                   n: int, r: int, p: int, dklen: int) -> bytes:
    """Call EVP_PBE_scrypt with maxmem=UINT64_MAX — no memory cap."""
    fn  = _load_evp_scrypt()
    if fn is None:
        raise RuntimeError("libcrypto not available for ctypes scrypt call.")
    out = _ctypes.create_string_buffer(dklen)
    ret = fn(password, len(password), salt, len(salt),
             n, r, p, _UINT64_MAX, out, dklen)
    if ret != 1:
        raise RuntimeError(f"EVP_PBE_scrypt returned {ret}.")
    return bytes(out)


def _scrypt_derive_raw(password: bytes, salt: bytes,
                       n: int, r: int, p: int, dklen: int) -> bytes:
    """Derive scrypt key, transparently bypassing the OpenSSL ~32 MB cap.
    Tries hashlib first (portable/fast path); falls through to ctypes only
    when 'memory limit' ValueError fires.  Any other ValueError (bad params)
    is re-raised immediately."""
    try:
        return hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=dklen)
    except ValueError as exc:
        if "memory limit" in str(exc).lower():
            return _scrypt_ctypes(password, salt, n, r, p, dklen)
        raise
    except MemoryError:
        raise MemoryError(
            f"Not enough RAM for scrypt N=2^{n.bit_length()-1} "
            f"({n * r * 128 // 1024**2} MB required).")


# PROFILE-2: Target: strongest profile that completes one scrypt call in ≤1 s.
# Tries Ultra → Light so the returned default is as strong as the machine allows.
_BENCHMARK_TARGET_S = 1.0


def benchmark_default_profile() -> int:
    """
    PROFILE-2: Returns the user_profile_idx (0=Light … 6=Max) of the strongest
    scrypt profile that finishes within _BENCHMARK_TARGET_S on this machine.
    Uses _scrypt_derive_raw so the OpenSSL cap does not artificially limit the
    benchmark result to Light on high-RAM machines.
    Falls back to 0 (Light) if nothing else works.
    """
    import time
    probe = os.urandom(32)
    for ui in range(len(USER_PROFILES) - 1, -1, -1):   # Max → Light
        sp = SCRYPT_PROFILES[USER_PROFILES[ui]["scrypt_idx"]]
        try:
            t0 = time.monotonic()
            _scrypt_derive_raw(b"bench", probe,
                               sp["N"], sp["r"], sp["p"], 32)
            if time.monotonic() - t0 <= _BENCHMARK_TARGET_S:
                return ui
        except (ValueError, MemoryError, RuntimeError):
            continue
    return 0   # PROFILE-2: Light is always the final fallback


# PROFILE-3: Run benchmark once at import time (reuses the system probe already
# executed by _get_scrypt_params so total startup overhead ≤ 2 × scrypt calls).
DEFAULT_USER_PROFILE_IDX: int = benchmark_default_profile()
logging.warning(
    "benchmark default user profile: %s (user_idx=%d, scrypt_idx=%d)",
    USER_PROFILES[DEFAULT_USER_PROFILE_IDX]["label"],
    DEFAULT_USER_PROFILE_IDX,
    USER_PROFILES[DEFAULT_USER_PROFILE_IDX]["scrypt_idx"],
)

SALT_SIZE  = 32
NONCE_SIZE = 12
KEY_SIZE   = 32
MAGIC      = b"LPHY"
CHUNK_SIZE = 16 * 1024 * 1024              # 16 MiB
STREAM_TAG = b"STRM"

# MED-04: cap chunk_count to prevent OOM via crafted file.
# 100 GiB / 16 MiB ≈ 6 553 chunks.
# For files >100 GiB, increase this constant or raise CHUNK_SIZE.
MAX_CHUNK_COUNT = (100 * 1024 ** 3) // CHUNK_SIZE

# ── Header layout (v3.2) ──────────────────────────────────────────────────────
# MAGIC(4) VERSION(1) SCRYPT_IDX(1) SALT(32) NONCE(12) HMAC(32)
# STREAM_TAG(4) COUNT(8) → chunks start at byte 94
_HMAC_OFFSET    = 4 + 1 + 1 + SALT_SIZE + NONCE_SIZE   # = 50
_STREAM_OFFSET  = _HMAC_OFFSET + 32 + 4 + 8            # = 94


# ── KDF ───────────────────────────────────────────────────────────────────────

def _derive_chunk_nonce(key: bytes, base_nonce: bytes, chunk_index: int) -> bytes:
    """HKDF-lite: HMAC-SHA256(key, base_nonce ‖ 'chunk' ‖ uint64_be(i))[:12]"""
    info   = base_nonce + b"chunk" + struct.pack(">Q", chunk_index)
    digest = hmac.new(key, info, hashlib.sha256).digest()
    return digest[:NONCE_SIZE]


def _get_scrypt_params() -> tuple[dict, int]:
    """Auto-detect best scrypt profile. Returns (profile_dict, index)."""
    probe_salt = os.urandom(32)   # NEW-MED-04: random probe salt (not all-zero)
    for idx, profile in enumerate(SCRYPT_PROFILES):
        try:
            hashlib.scrypt(b"probe", salt=probe_salt,
                           n=profile["N"], r=profile["r"], p=profile["p"], dklen=32)
            return profile, idx
        except (ValueError, MemoryError):
            continue
    raise RuntimeError("scrypt not available on this system.")


SCRYPT_PARAMS, SCRYPT_IDX = _get_scrypt_params()

# MED-05: export flag so GUI can show a warning banner on low-security systems
SCRYPT_WEAK_PROFILE = SCRYPT_PARAMS["N"] < 2 ** 15

# INFO-04: root logger is WARNING; logging.info() here would be a no-op — use warning
logging.warning("scrypt profile selected: %s (idx=%d)", SCRYPT_PARAMS["label"], SCRYPT_IDX)
if SCRYPT_WEAK_PROFILE:
    logging.warning(
        "Low scrypt profile active (N=%d) — brute-force resistance reduced.",
        SCRYPT_PARAMS["N"])


def derive_key(password_bytes: bytes, salt: bytes, profile: dict | None = None) -> bytearray:
    """
    Derive 256-bit key via scrypt from pre-encoded password bytes.

    MED-12: accepts bytes directly — no extra .encode() copy here.
    MED-03: caller may pass a specific profile dict (used during decryption).
    Returns mutable bytearray for safe zeroing.

    OpenSSL cap fix: delegates to _scrypt_derive_raw which transparently
    switches to ctypes EVP_PBE_scrypt when hashlib hits the ~32 MB maxmem wall.
    """
    p   = profile if profile is not None else SCRYPT_PARAMS
    raw = _scrypt_derive_raw(
        password_bytes, salt,
        n=p["N"], r=p["r"], p=p["p"], dklen=KEY_SIZE,
    )
    return bytearray(raw)


def _zero_key(key: bytearray) -> None:
    """
    Overwrite key bytes with zeros.
    LOW-18: slice assignment executes at C level in CPython and cannot be
    optimised away by JIT (unlike a Python-level dead-store loop).
    """
    key[:] = b"\x00" * len(key)


def _zero_bytes_obj(b: bytes) -> None:
    """
    CRIT-01: Best-effort zeroing of an immutable bytes object's internal buffer
    via ctypes.  CPython bytes layout: ob_refcnt(8) ob_type(8) ob_hash(8)
    ob_size(8) ob_shash(8) → data starts after sys.getsizeof(b'') - 1 bytes
    (the -1 accounts for the null terminator included in getsizeof).
    This does NOT zero copies held by other objects (e.g. AESGCM internal
    buffer — see MED-01), but it does wipe the primary Python-heap copy.
    """
    if not b:
        return
    try:
        header = sys.getsizeof(b"") - 1  # bytes before the char data
        ctypes.memset(id(b) + header, 0, len(b))
    except Exception:
        pass   # best-effort; never raise from a security helper


# ── LOW-02: Temp-file registry for crash-safe cleanup ────────────────────────

_temp_registry: set[str] = set()
_temp_registry_lock = threading.Lock()


def _register_temp(path: str) -> None:
    with _temp_registry_lock:
        _temp_registry.add(path)


def _deregister_temp(path: str) -> None:
    with _temp_registry_lock:
        _temp_registry.discard(path)


def _cleanup_all_temps(signum=None, frame=None) -> None:
    """LOW-02: called by atexit and signal handlers to wipe orphaned temp files."""
    with _temp_registry_lock:
        paths = list(_temp_registry)
    for p in paths:
        _secure_delete(p)
        _deregister_temp(p)


atexit.register(_cleanup_all_temps)
try:
    signal.signal(signal.SIGTERM, _cleanup_all_temps)
    signal.signal(signal.SIGINT,  _cleanup_all_temps)
except (OSError, ValueError):
    pass  # signal registration can fail in non-main threads; ignore


# ── CRIT-02: Atomic secure file creation ────────────────────────────────────

def _open_secure(path: str, mode: int = 0o600):
    """
    CRIT-02: Atomically create `path` with 0600 permissions.
    Raises FileExistsError if path exists (use _temp_path() for fresh paths).

    FIX-01: O_NOFOLLOW added — if `path` is a symlink the call fails with
    ELOOP/ENOTDIR rather than following the link.  Consistent with
    _secure_delete() which already uses O_NOFOLLOW.  On platforms where
    O_NOFOLLOW is unavailable (getattr returns 0) the behaviour is unchanged.
    """
    # FIX-01: O_NOFOLLOW prevents symlink-redirect attack in the TOCTOU window
    # between _temp_path() and _open_secure(); mirrors _secure_delete() practice.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    return os.fdopen(fd, "wb")


def _temp_path(suffix: str) -> str:
    """
    NEW-CRIT-01: Generate a unique path inside the secure temp dir WITHOUT
    creating the file.  Use this instead of NamedTemporaryFile when the path
    will be passed to _open_secure() (which requires O_EXCL / non-existing).
    """
    import uuid
    return str(_log_dir / (uuid.uuid4().hex + suffix))


# ── MED-02: Secure temp-file deletion ────────────────────────────────────────

def _secure_delete(path: str) -> None:
    """
    LOW-01: 3-pass overwrite before unlink for defence-in-depth on HDDs.
    NOTE: On SSDs, APFS, btrfs, ZFS and NTFS-with-VSS, physical data
    remanence cannot be guaranteed regardless of pass count. Use full-disk
    encryption (BitLocker / LUKS / FileVault) as the primary control.

    FIX-01: Open file descriptor first, then fstat() inside the context to
    eliminate the TOCTOU race between os.path.getsize() and open().
    O_NOFOLLOW (where available — POSIX) prevents a symlink-redirect attack
    where an attacker replaces the temp file with a symlink between the two
    calls, causing the overwrite to clobber an unrelated target.
    """
    try:
        # FIX-01: O_RDWR | O_NOFOLLOW — atomic open, no symlink follow
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        fd    = os.open(path, flags)
        with os.fdopen(fd, "r+b") as f:
            size = os.fstat(f.fileno()).st_size   # FIX-01: size from open fd, not a separate stat
            for _ in range(3):   # LOW-01: 3 passes
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
    except Exception:
        pass
    finally:
        try:
            os.remove(path)
        except Exception:
            pass


# ── In-memory encrypt/decrypt (small data, folder ZIP) ───────────────────────

def encrypt_bytes(data: bytes, password: str, progress_cb=None) -> bytes:
    salt  = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    if progress_cb: progress_cb(8, "Deriving key…")
    key = derive_key(password.encode("utf-8"), salt)
    kb  = bytes(key)   # NEW-LOW-01: single named copy so _zero_bytes_obj can wipe it
    try:
        if progress_cb: progress_cb(55, "Encrypting data…")
        aad = MAGIC + FILE_FORMAT_BYTES + salt + nonce
        ct  = AESGCM(kb).encrypt(nonce, data, aad)
        if progress_cb: progress_cb(80, "Computing integrity hash…")
        mac = hmac.new(kb, salt + nonce + ct, hashlib.sha256).digest()
    finally:
        _zero_key(key); del key
        _zero_bytes_obj(kb); del kb   # CRIT-01 + NEW-LOW-01
    if progress_cb: progress_cb(100, "Complete")
    return MAGIC + FILE_FORMAT_BYTES + salt + nonce + mac + ct


def decrypt_bytes(data: bytes, password: str, progress_cb=None) -> bytes:
    """
    Public str API kept for backwards compatibility.
    INFO-09: internally delegates to _decrypt_bytes_raw to avoid double encode.
    """
    return _decrypt_bytes_raw(data, password.encode("utf-8"), progress_cb)


def _decrypt_bytes_raw(data: bytes, password_bytes: bytes, progress_cb=None) -> bytes:
    """
    MED-14: Internal bytes API — no str copy created.
    Called by decrypt_file legacy path directly with password_bytes.
    """
    off = 0
    if data[off:off+4] != MAGIC:
        raise ValueError("Invalid file — not a Lephy Crypt archive.")
    off += 4
    ver = data[off:off+1]; off += 1
    if ver not in (FILE_FORMAT_STREAM, FILE_FORMAT_BYTES):
        raise ValueError("Unsupported file version.")
    salt  = data[off:off+SALT_SIZE];  off += SALT_SIZE
    nonce = data[off:off+NONCE_SIZE]; off += NONCE_SIZE
    stored = data[off:off+32];        off += 32
    ct     = data[off:]
    if progress_cb: progress_cb(8, "Deriving key…")
    key = derive_key(password_bytes, salt)
    kb  = bytes(key)
    try:
        if progress_cb: progress_cb(55, "Verifying integrity…")
        if not hmac.compare_digest(
                stored, hmac.new(kb, salt + nonce + ct, hashlib.sha256).digest()):
            raise ValueError("Authentication failed — incorrect password or file tampered.")
        if progress_cb: progress_cb(75, "Decrypting data…")
        # LOW-05: reconstruct AAD from header for GCM authentication
        aad = MAGIC + ver + salt + nonce
        try:
            pt = AESGCM(kb).decrypt(nonce, ct, aad)
        except Exception:
            raise ValueError("Decryption error — file may be corrupted.")
    finally:
        _zero_key(key); del key
        _zero_bytes_obj(kb); del kb   # CRIT-01: zero immutable bytes copy
    if progress_cb: progress_cb(100, "Complete")
    return pt


# ── Streaming file encryption — MED-03 + MED-05 fixes ────────────────────────

def encrypt_file(src: str, dst: str, password_bytes: bytes,
                 progress_cb=None,
                 scrypt_idx: int | None = None) -> dict:
    """
    Single-pass stream-encrypt src → dst.

    MED-05 fix: no temporary file. Header is written with a 32-byte zero
    HMAC placeholder; after all chunks are written the file is seeked back
    to _HMAC_OFFSET and the real HMAC is overwritten.  Disk usage = output
    size only (no 2× overhead).

    MED-03 fix: SCRYPT_IDX (1 byte) written into header so decryption on
    any machine can use the exact same scrypt parameters.

    LOW-08 fix: actual_count is compared to chunk_count after the loop;
    mismatch (source changed mid-encryption) raises RuntimeError.

    FIX-02: kb is bound before the try block so the finally clause never
    hits a NameError when attempting _zero_bytes_obj(kb) on an unset name.

    PROFILE-4: accepts optional scrypt_idx (SCRYPT_PROFILES index) so the
    caller can override the auto-selected profile. Defaults to module-level
    SCRYPT_IDX when None.
    """
    # PROFILE-4: resolve profile; None → auto-selected system default
    use_sidx    = scrypt_idx if scrypt_idx is not None else SCRYPT_IDX
    if not (0 <= use_sidx < len(SCRYPT_PROFILES)):
        raise ValueError(f"Invalid scrypt_idx {use_sidx!r}.")
    use_profile = SCRYPT_PROFILES[use_sidx]   # PROFILE-4

    src_size = os.path.getsize(src)
    if progress_cb: progress_cb(3, "Deriving key…")

    salt       = os.urandom(SALT_SIZE)
    base_nonce = os.urandom(NONCE_SIZE)
    # LOW-21: password_bytes passed directly — no encode copy
    key = derive_key(password_bytes, salt, profile=use_profile)   # PROFILE-4: use chosen profile
    kb  = bytes(key)   # FIX-02: bound before try — _zero_bytes_obj(kb) in finally is always safe

    try:
        # CRIT-01: pre-calculate so count enters HMAC from the start
        chunk_count = math.ceil(src_size / CHUNK_SIZE) if src_size > 0 else 0
        count_field = struct.pack(">Q", chunk_count)

        mac_ctx = hmac.new(kb, digestmod=hashlib.sha256)
        mac_ctx.update(salt)
        mac_ctx.update(base_nonce)
        mac_ctx.update(STREAM_TAG)
        mac_ctx.update(count_field)

        aesgcm       = AESGCM(kb)
        actual_count = 0
        bytes_done   = 0
        success      = False   # MED-08: track whether encryption completed cleanly

        # CRIT-02: atomically create output file with 0600 perms — never world-readable
        with _open_secure(dst) as fout:
            # Header — HMAC field is a placeholder (32 zero bytes)
            fout.write(MAGIC + FILE_FORMAT_STREAM)
            fout.write(bytes([use_sidx]))            # PROFILE-4: write chosen profile index
            fout.write(salt + base_nonce)
            fout.write(b"\x00" * 32)                 # HMAC placeholder
            fout.write(STREAM_TAG + count_field)

            with open(src, "rb") as fin:
                while True:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk: break
                    nonce_i   = _derive_chunk_nonce(kb, base_nonce, actual_count)
                    enc_chunk = aesgcm.encrypt(nonce_i, chunk, None)
                    len_field = struct.pack(">I", len(enc_chunk))
                    mac_ctx.update(len_field)
                    mac_ctx.update(enc_chunk)
                    fout.write(len_field); fout.write(enc_chunk)
                    actual_count += 1; bytes_done += len(chunk)
                    if progress_cb and src_size > 0:
                        pct = 10 + int((bytes_done / src_size) * 85)
                        progress_cb(pct,
                            f"Encrypting… {bytes_done//(1<<20)} / {src_size//(1<<20)} MB")

        # LOW-08: verify no source-file race condition
        if actual_count != chunk_count:
            _secure_delete(dst)   # MED-08: use _secure_delete, not os.remove
            raise RuntimeError(
                f"Chunk count mismatch: expected {chunk_count}, got {actual_count}. "
                "Source file may have changed during encryption — output deleted.")

        final_mac = mac_ctx.digest()

        # MED-05: seek back and overwrite HMAC placeholder
        # FIX-TOCTOU-01: _open_secure(dst) kapandıktan sonra dst sembolik bağa
        # dönüştürülürse open(dst,"r+b") bağı takip ederek HMAC materyalini
        # başka bir dosyaya yazardı (TOCTOU/symlink-redirect).  os.open ile
        # O_NOFOLLOW eklenerek bu pencere kapatılıyor; POSIX dışı platformlarda
        # (Windows) getattr fallback 0 döndürerek mevcut davranış korunuyor.
        _hmac_fd = os.open(
            dst,
            os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        )
        with os.fdopen(_hmac_fd, "r+b") as f:
            f.seek(_HMAC_OFFSET)
            f.write(final_mac)

        success = True   # MED-08: only set True after HMAC written
        if progress_cb: progress_cb(100, "Complete")

    finally:
        _zero_key(key)
        _zero_bytes_obj(kb)   # CRIT-01: zero immutable bytes copy before del
        del key, kb
        # MED-08: if encryption didn't complete cleanly, wipe partial output
        if not success and os.path.exists(dst):
            _secure_delete(dst)

    return {
        "mode": "file",
        "original_size": src_size,
        "output_size": os.path.getsize(dst),
        "profile": use_profile["label"],   # PROFILE-4: reflect actually-used profile
        "chunks": actual_count,
    }


def _read_file_header(src: str) -> dict:
    """
    Read and structurally validate the .lcrypt header WITHOUT a password.
    Returns a populated dict on success.
    Raises StructuralCorruptionError on any structural problem.
    """
    try:
        with open(src, "rb") as f:
            magic   = f.read(4)
            version = f.read(1)

            if magic != MAGIC:
                raise StructuralCorruptionError(
                    "Not a Lephy Crypt archive — magic bytes missing or incorrect.\n"
                    "The file may have been renamed, or it was never encrypted with Lephy Crypt.")
            if version not in (FILE_FORMAT_STREAM, FILE_FORMAT_BYTES):
                raise StructuralCorruptionError(
                    f"Unsupported file version (0x{version.hex()}).\n"
                    "The file may have been created by a newer version of Lephy Crypt.")

            if version == FILE_FORMAT_STREAM:
                scrypt_idx_byte = f.read(1)
                if not scrypt_idx_byte:
                    raise StructuralCorruptionError(
                        "File is truncated — scrypt profile index is missing.")
                scrypt_idx = scrypt_idx_byte[0]
            else:
                scrypt_idx = SCRYPT_IDX

            salt       = f.read(SALT_SIZE)
            base_nonce = f.read(NONCE_SIZE)
            stored_mac = f.read(32)
            peek       = f.read(4)

            if len(salt) < SALT_SIZE or len(base_nonce) < NONCE_SIZE or len(stored_mac) < 32:
                raise StructuralCorruptionError(
                    "File is truncated — header fields are incomplete.")

    except StructuralCorruptionError:
        raise
    except OSError as e:
        raise StructuralCorruptionError(f"Cannot read file: {e}")

    if not (0 <= scrypt_idx < len(SCRYPT_PROFILES)):
        raise StructuralCorruptionError(
            f"Unknown scrypt profile index ({scrypt_idx}) — "
            "file was encrypted with a newer version of Lephy Crypt.")

    profile = SCRYPT_PROFILES[scrypt_idx]

    if peek == STREAM_TAG:
        count_offset  = (_HMAC_OFFSET + 32 + 4) if version == FILE_FORMAT_STREAM \
                        else (4 + 1 + SALT_SIZE + NONCE_SIZE + 32 + 4)
        stream_offset = _STREAM_OFFSET if version == FILE_FORMAT_STREAM \
                        else (4 + 1 + SALT_SIZE + NONCE_SIZE + 32 + 4 + 8)
        try:
            with open(src, "rb") as f:
                f.seek(count_offset)
                count_field = f.read(8)
        except OSError as e:
            raise StructuralCorruptionError(f"Cannot seek in file: {e}")

        if len(count_field) < 8:
            raise StructuralCorruptionError(
                "File is truncated — chunk count field is incomplete.")
        chunk_count = struct.unpack(">Q", count_field)[0]
        if chunk_count > MAX_CHUNK_COUNT:
            raise StructuralCorruptionError(
                f"Chunk count {chunk_count:,} exceeds safety limit "
                f"({MAX_CHUNK_COUNT:,}) — file header appears malformed or malicious.")
    elif peek == b"" or version == FILE_FORMAT_BYTES:
        # Legacy bytes format — no STREAM_TAG
        count_field   = b""
        chunk_count   = 0
        stream_offset = 0
    else:
        raise StructuralCorruptionError(
            "Stream marker missing — file may be truncated or corrupted.")

    src_size = os.path.getsize(src)
    return dict(
        version=version, scrypt_idx=scrypt_idx, profile=profile,
        salt=salt, base_nonce=base_nonce, stored_mac=stored_mac,
        peek=peek, stream_offset=stream_offset,
        chunk_count=chunk_count, count_field=count_field,
        src_size=src_size,
    )


def inspect_file(src: str) -> dict:
    """
    Password-free structural inspection.  Returns a summary dict on success;
    raises StructuralCorruptionError if anything looks wrong.

    GUI calls this immediately after the user drops a file to give early
    feedback before they even type a password.
    """
    h = _read_file_header(src)
    return {
        "ok":           True,
        "version":      h["version"].hex(),
        "profile":      h["profile"]["label"],
        "scrypt_idx":   h["scrypt_idx"],
        "chunks":       h["chunk_count"],
        "file_size":    h["src_size"],
        "file_size_mb": round(h["src_size"] / (1024 ** 2), 2),
        "legacy":       h["peek"] != STREAM_TAG,
    }


def verify_file(src: str, password_bytes: bytes, progress_cb=None) -> dict:
    """
    HMAC-only integrity check (Pass 1 of decrypt_file) without writing output.
    Use this to confirm a file is intact and the password is correct without
    producing a decrypted copy.

    Raises StructuralCorruptionError, AuthenticationError, or RuntimeError.
    Returns {verified, profile, chunks, file_size}.
    """
    if progress_cb: progress_cb(3, "Inspecting file structure…")
    h = _read_file_header(src)   # raises StructuralCorruptionError if bad

    # Legacy format: full load + _decrypt_bytes_raw for HMAC check
    if h["peek"] != STREAM_TAG:
        if progress_cb: progress_cb(10, "Legacy format — verifying…")
        with open(src, "rb") as f:
            data = f.read()
        key = derive_key(password_bytes, h["salt"], profile=h["profile"])
        kb  = bytes(key)
        try:
            _decrypt_bytes_raw(data, password_bytes, progress_cb)
            return {"verified": True, "profile": h["profile"]["label"],
                    "chunks": 0, "file_size": h["src_size"], "legacy": True}
        except ValueError as e:
            if "authentication failed" in str(e).lower():
                raise AuthenticationError(str(e)) from e
            raise
        finally:
            _zero_key(key); _zero_bytes_obj(kb); del key, kb

    if progress_cb: progress_cb(8, "Deriving key…")
    key = derive_key(password_bytes, h["salt"], profile=h["profile"])
    kb  = bytes(key)
    try:
        mac_ctx = hmac.new(kb, digestmod=hashlib.sha256)
        mac_ctx.update(h["salt"])
        mac_ctx.update(h["base_nonce"])
        mac_ctx.update(STREAM_TAG)
        if h["version"] == FILE_FORMAT_STREAM:
            mac_ctx.update(h["count_field"])

        bytes_read = 0
        with open(src, "rb") as f:
            f.seek(h["stream_offset"])
            for i in range(h["chunk_count"]):
                lf = f.read(4)
                if len(lf) < 4:
                    raise StructuralCorruptionError(
                        f"File truncated inside chunk {i} — length field missing.")
                clen = struct.unpack(">I", lf)[0]
                ec   = f.read(clen)
                if len(ec) < clen:
                    raise StructuralCorruptionError(
                        f"File truncated inside chunk {i} — "
                        f"expected {clen} bytes, got {len(ec)}.")
                mac_ctx.update(lf)
                mac_ctx.update(ec)
                bytes_read += clen
                if progress_cb and h["src_size"] > 0:
                    progress_cb(12 + int((bytes_read / h["src_size"]) * 85),
                                f"Verifying… {i+1}/{h['chunk_count']} chunks")

        computed = mac_ctx.digest()
        if not hmac.compare_digest(h["stored_mac"], computed):
            raise AuthenticationError(
                "Integrity check failed — password is incorrect, or the file "
                "has been modified since it was encrypted.")

        if progress_cb: progress_cb(100, "Verified ✓")
        return {
            "verified":  True,
            "profile":   h["profile"]["label"],
            "chunks":    h["chunk_count"],
            "file_size": h["src_size"],
            "legacy":    False,
        }
    finally:
        _zero_key(key); _zero_bytes_obj(kb); del key, kb


# ── Streaming file decryption — MED-03 + CRIT-01 + CRIT-02 ──────────────────

def decrypt_file(src: str, dst: str, password_bytes: bytes, progress_cb=None) -> dict:
    """
    Two-pass streaming decryption (O(1) RAM).

    MED-03 fix: reads SCRYPT_IDX from header and passes the matching profile
    to derive_key so cross-machine decryption works correctly.

    v2 legacy fallback: no SCRYPT_IDX in header → uses local SCRYPT_PARAMS.

    Raises StructuralCorruptionError, AuthenticationError, or ContentCorruptionError
    for the three distinct failure modes so callers can show targeted messages.
    Returns dict including sha256 fingerprint of the decrypted output.
    """
    if progress_cb: progress_cb(3, "Reading header…")
    h = _read_file_header(src)   # raises StructuralCorruptionError if bad

    # LOW-04: legacy single-shot format (FILE_FORMAT_BYTES without STREAM_TAG)
    if h["peek"] != STREAM_TAG:
        if progress_cb: progress_cb(5, "Legacy format — loading file…")
        legacy_success = False
        try:
            with open(src, "rb") as f: data = f.read()
            try:
                pt = _decrypt_bytes_raw(data, password_bytes, progress_cb)
            except ValueError as e:
                if "authentication failed" in str(e).lower():
                    raise AuthenticationError(str(e)) from e
                raise
            # NEW-MED-02: use _open_secure for 0600 atomic creation
            with _open_secure(dst) as f: f.write(pt)
            legacy_success = True
            fp = hashlib.sha256(pt).hexdigest()
            return {"mode": "file", "output_size": len(pt),
                    "profile": h["profile"]["label"],
                    "sha256": fp, "legacy": True}
        finally:
            if not legacy_success and os.path.exists(dst):
                _secure_delete(dst)

    if progress_cb: progress_cb(8, "Deriving key…")
    # LOW-21: password_bytes passed directly — no encode copy
    key = derive_key(password_bytes, h["salt"], profile=h["profile"])
    kb  = bytes(key)
    success = False   # MED-11: track clean completion; wipe dst on failure

    try:
        src_size = h["src_size"]

        # ── Pass 1: HMAC verification — O(1) RAM ─────────────────────────────
        if progress_cb: progress_cb(12, "Verifying integrity…")

        mac_ctx = hmac.new(kb, digestmod=hashlib.sha256)
        mac_ctx.update(h["salt"])
        mac_ctx.update(h["base_nonce"])
        mac_ctx.update(STREAM_TAG)
        if h["version"] == FILE_FORMAT_STREAM:
            mac_ctx.update(h["count_field"])   # CRIT-01: count bound from start

        bytes_read = 0
        with open(src, "rb") as f:
            f.seek(h["stream_offset"])
            for i in range(h["chunk_count"]):
                lf = f.read(4)
                if len(lf) < 4:
                    raise StructuralCorruptionError(
                        f"File truncated — chunk {i} length field missing.")
                clen = struct.unpack(">I", lf)[0]
                ec   = f.read(clen)
                if len(ec) < clen:
                    raise StructuralCorruptionError(
                        f"File truncated — chunk {i}: "
                        f"expected {clen} bytes, got {len(ec)}.")
                mac_ctx.update(lf)
                mac_ctx.update(ec)
                # CRIT-02: ec NOT stored — O(1) RAM
                bytes_read += clen
                if progress_cb and src_size > 0:
                    progress_cb(12 + int((bytes_read / src_size) * 33),
                                f"Verifying… {i+1}/{h['chunk_count']} chunks")

        if h["version"] == FILE_FORMAT_STREAM:
            computed = mac_ctx.digest()
        else:
            computed = hmac.new(kb, mac_ctx.digest() + h["count_field"],
                                hashlib.sha256).digest()

        if not hmac.compare_digest(h["stored_mac"], computed):
            raise AuthenticationError(
                "Integrity check failed — password is incorrect, or the file "
                "has been modified since it was encrypted.")

        # ── Pass 2: streaming decrypt ─────────────────────────────────────────
        if progress_cb: progress_cb(50, "Decrypting…")
        aesgcm  = AESGCM(kb)
        sha_ctx = hashlib.sha256()   # plaintext fingerprint
        output_size = 0

        # CRIT-02: create dst atomically with 0600 perms, never world-readable
        with open(src, "rb") as fin, _open_secure(dst) as fout:
            fin.seek(h["stream_offset"])
            for i in range(h["chunk_count"]):
                lf   = fin.read(4)
                clen = struct.unpack(">I", lf)[0]
                ec   = fin.read(clen)
                ni   = _derive_chunk_nonce(kb, h["base_nonce"], i)
                try:
                    pc = aesgcm.decrypt(ni, ec, None)
                except Exception:
                    raise ContentCorruptionError(
                        f"Chunk {i} failed AES-GCM authentication — the file "
                        "appears to have been partially modified after encryption.\n"
                        f"Chunks 0–{i-1} were intact; chunk {i} is corrupted.",
                        chunk=i)
                fout.write(pc)
                sha_ctx.update(pc)
                output_size += len(pc)
                if progress_cb:
                    progress_cb(50 + int(((i+1) / h["chunk_count"]) * 48),
                                f"Decrypting… {i+1}/{h['chunk_count']} chunks")

        success = True   # MED-11: only set after all chunks written cleanly

    finally:
        _zero_key(key)
        _zero_bytes_obj(kb)   # CRIT-01: zero immutable bytes copy before del
        del key, kb
        # MED-11: if decryption didn't complete cleanly, wipe partial plaintext dst
        if not success and os.path.exists(dst):
            _secure_delete(dst)

    if progress_cb: progress_cb(100, "Complete")
    return {
        "mode":        "file",
        "output_size": output_size,
        "chunks":      h["chunk_count"],
        "profile":     h["profile"]["label"],
        "sha256":      sha_ctx.hexdigest(),
    }


# ── Folder encryption ─────────────────────────────────────────────────────────

def encrypt_folder(src: str, dst: str, password_bytes: bytes,
                   progress_cb=None,
                   scrypt_idx: int | None = None) -> dict:
    """
    Zip folder → stream-encrypt the zip.

    LOW-19: temp ZIP is written to ~/.lephy_crypt/ (0700 dir) with 0600
    perms so other users/processes cannot read plaintext folder contents
    while compression is in progress.

    PROFILE-5: scrypt_idx forwarded to encrypt_file unchanged so the
    user-selected profile is honoured end-to-end for folder archives.
    """
    tmp_fd = tempfile.NamedTemporaryFile(
        suffix=".zip", delete=False,
        dir=str(_log_dir),   # ~/.lephy_crypt — already 0700
    )
    tmp = tmp_fd.name; tmp_fd.close()
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)   # LOW-19: 0600
    _register_temp(tmp)   # LOW-02: ensure crash-safe cleanup
    try:
        if progress_cb: progress_cb(3, "Compressing folder…")
        # LOW-22: explicit try/finally so ZipFile is closed before _secure_delete.
        # On Windows, os.remove() fails if the file handle is still open.
        zf = zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED)
        try:
            base  = Path(src)
            # NEW-LOW-03: exclude symlinks — fp.is_file() follows them, risking traversal
            files = [fp for fp in base.rglob("*")
                     if fp.is_file() and not fp.is_symlink()]
            for i, fp in enumerate(files):
                zf.write(fp, fp.relative_to(base.parent))
                if progress_cb:
                    progress_cb(3 + int((i / max(len(files), 1)) * 25),
                                f"Compressing {fp.name}…")
        finally:
            zf.close()   # ensure handle released before _secure_delete
        orig = sum(fp.stat().st_size for fp in Path(src).rglob("*") if fp.is_file())
        def _cb(p, m):
            if progress_cb: progress_cb(28 + int(p * 0.70), m)
        r = encrypt_file(tmp, dst, password_bytes, _cb,
                         scrypt_idx=scrypt_idx)   # PROFILE-5: forward chosen profile
        r["mode"] = "folder"; r["original_size"] = orig
        return r
    finally:
        _secure_delete(tmp)   # MED-02
        _deregister_temp(tmp)


def _safe_extractall(zf: zipfile.ZipFile, dst_base: str) -> None:
    """ZIP Slip prevention."""
    resolved = os.path.realpath(dst_base) + os.sep
    for m in zf.infolist():
        if not os.path.realpath(os.path.join(dst_base, m.filename)).startswith(resolved):
            raise ValueError(f"Unsafe ZIP path — extraction aborted: {m.filename!r}")
    zf.extractall(dst_base)


def _secure_move(src: str, dst: str) -> None:
    """
    NEW-MED-03: Atomic rename if same filesystem; copy + _secure_delete on
    cross-device move so the source is wiped, not just unlinked.

    FIX-02: Replace shutil.copy2() with an explicit os.open(O_CREAT|O_WRONLY,
    0o600) so the plaintext destination file is never created with world-
    readable permissions regardless of the caller's umask.  shutil.copy2()
    applies the process umask (typically 0o022 → 0o644), which would make
    decrypted plaintext readable by other users on multi-user systems.
    """
    try:
        os.rename(src, dst)
    except OSError:
        # FIX-02: explicit 0600 perms — bypasses umask unlike shutil.copy2
        fd = os.open(
            dst,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with open(src, "rb") as fsrc, os.fdopen(fd, "wb") as fdst:
            shutil.copyfileobj(fsrc, fdst)
        _secure_delete(src)


def smart_decrypt(src: str, dst_base: str, password_bytes: bytes, progress_cb=None) -> dict:
    """Decrypt .lcrypt and auto-detect file vs folder archive.
    Propagates StructuralCorruptionError, AuthenticationError, ContentCorruptionError.
    Return dict includes sha256 fingerprint for file mode."""
    # NEW-CRIT-01: generate path without creating the file so _open_secure
    # inside decrypt_file won't hit O_EXCL / FileExistsError.
    tmp = _temp_path(".lcpart")
    _register_temp(tmp)   # LOW-02: crash-safe cleanup
    try:
        def _cb(p, m):
            if progress_cb: progress_cb(int(p * 0.85), m)
        result = decrypt_file(src, tmp, password_bytes, _cb)
        with open(tmp, "rb") as f: peek = f.read(4)
        if peek == b"PK\x03\x04":
            if progress_cb: progress_cb(88, "Detected folder archive — extracting…")
            os.makedirs(dst_base, exist_ok=True)
            with zipfile.ZipFile(tmp, "r") as zf:
                _safe_extractall(zf, dst_base)
            fc = sum(1 for _ in Path(dst_base).rglob("*") if _.is_file())
            if progress_cb: progress_cb(100, "Complete")
            return {"mode": "folder", "output_dir": dst_base, "file_count": fc,
                    "profile": result.get("profile", ""),
                    "sha256":  result.get("sha256", "")}
        else:
            if progress_cb: progress_cb(90, "Saving file…")
            _secure_move(tmp, dst_base)   # NEW-MED-03: secure cross-device move
            tmp = None   # signal finally: file was moved, nothing to delete
            if progress_cb: progress_cb(100, "Complete")
            return {"mode": "file", "output_size": os.path.getsize(dst_base),
                    "profile": result.get("profile", ""),
                    "sha256":  result.get("sha256", "")}
    finally:
        if tmp and os.path.exists(tmp):
            _secure_delete(tmp)
            _deregister_temp(tmp)


# ── Password strength ─────────────────────────────────────────────────────────

def password_strength(pw: str):
    """
    Entropy-based scoring. LOW-02: len < 8 → score 0.
    Returns (score 0–100, label, hex_color).
    """
    if not pw: return 0, "", "#aaaaaa"
    if len(pw) < 8: return 0, "Too Short", "#e05252"

    # LOW-15: cap input length to prevent ReDoS via pathological regex input
    if len(pw) > 512:
        pw = pw[:512]

    pool = 0
    if any(c.islower() for c in pw): pool += 26
    if any(c.isupper() for c in pw): pool += 26
    if any(c.isdigit() for c in pw): pool += 10
    if any(c in r"!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in pw): pool += 32
    bits = len(pw) * math.log2(max(pool, 1))
    pen  = 0
    for r in re.findall(r'(.)\1{2,}', pw): pen += len(r) * 8
    for row in ["qwertyuiop","asdfghjkl","zxcvbnm","1234567890",
                "abcdefghijklmnopqrstuvwxyz"]:
        for rl in range(5, 2, -1):
            for i in range(len(row) - rl + 1):
                if row[i:i+rl] in pw.lower(): pen += rl * 6
    leet = pw.lower().translate(str.maketrans("@0!13$", "aoiles"))
    for frag in ["password","pass","secret","qwerty","letmein",
                 "admin","login","welcome","master"]:
        if frag in leet: pen += 40
    classes = sum([any(c.islower() for c in pw), any(c.isupper() for c in pw),
                   any(c.isdigit() for c in pw),
                   any(c in r"!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in pw)])
    if classes == 1: pen += 20
    score = int(min(100, max(0, (max(0.0, bits - pen) - 20) / 60 * 100)))
    if score < 25: return score, "Very Weak",  "#e05252"
    if score < 45: return score, "Weak",       "#e07832"
    if score < 65: return score, "Moderate",   "#d4a820"
    if score < 82: return score, "Strong",     "#3ab97a"
    return score,               "Very Strong", "#22d492"