"""
Lephy Crypt — Background Worker Thread  (v3.9)
"""

import time
import logging
import threading

from PyQt5.QtCore import QThread, pyqtSignal

from crypto import (encrypt_file, encrypt_folder, smart_decrypt,
                    verify_file, inspect_file,
                    USER_PROFILES, DEFAULT_USER_PROFILE_IDX,
                    _zero_bytes_obj,
                    StructuralCorruptionError, AuthenticationError, ContentCorruptionError)

_MAX_DELAY   = 8.0
_DELAY_STEP  = 0.75

# ── MED-02 + MED-03: Bounded brute-force counter keyed on file salt ──────────
_bf_lock        = threading.Lock()
_BF_MAX_ENTRIES = 1024
_BF_TTL_SECONDS = 3600   # 1 hour

# value: (fail_count: int, last_failure_monotonic: float)
_bf_counts: dict[str, tuple[int, float]] = {}


def _get_file_salt_id(path: str) -> str:
    """
    MED-02: Read the 32-byte salt from the file header as a stable
    cryptographic identity — cannot be reset by copying to a new path.
    Falls back to path string if the file is unreadable.
    """
    import hashlib
    try:
        with open(path, "rb") as f:
            f.seek(6)   # MAGIC(4) + VERSION(1) + SCRYPT_IDX(1)
            salt = f.read(32)
        if len(salt) == 32:
            return hashlib.sha256(salt).hexdigest()
    except OSError:
        pass
    return path   # fallback


def _bf_increment(key: str) -> int:
    """MED-03: increment counter; evict stale entries if dict is full."""
    with _bf_lock:
        now = time.monotonic()
        # Prune stale entries when at capacity
        if len(_bf_counts) >= _BF_MAX_ENTRIES:
            stale = [k for k, (_, ts) in _bf_counts.items()
                     if now - ts > _BF_TTL_SECONDS]
            for k in stale:
                del _bf_counts[k]
            # FIX-BF-01: stale temizliği sonrası dict hâlâ dolu ise en eski
            # (en küçük monotonic timestamp'li) girişi çıkar.  Bu olmadan
            # _BF_MAX_ENTRIES taze girişle dolduğunda sözlük sınırsız büyür
            # ve ilk deneme için bekleme sayacı sıfırdan başlar (0.75s bypass).
            if len(_bf_counts) >= _BF_MAX_ENTRIES:
                oldest_key = min(_bf_counts, key=lambda k: _bf_counts[k][1])
                del _bf_counts[oldest_key]
        count, _ = _bf_counts.get(key, (0, 0.0))
        count += 1
        _bf_counts[key] = (count, now)
        return count


def _bf_reset(key: str) -> None:
    with _bf_lock:
        _bf_counts.pop(key, None)


class Worker(QThread):
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(dict)
    # error carries (message, error_type)
    # error_type: "structural" | "auth" | "content" | "other"
    error    = pyqtSignal(str, str)

    def __init__(self, task: str, src: str, dst: str,
                 password, is_folder: bool = False,
                 profile_idx: int | None = None):   # PROFILE-6: user-selected profile
        super().__init__()
        self.task      = task
        self.src       = src
        self.dst       = dst
        self.is_folder = is_folder

        # PROFILE-6: resolve to a valid user_profile_idx; fall back to benchmark default
        if profile_idx is not None and 0 <= profile_idx < len(USER_PROFILES):
            self._user_profile_idx = profile_idx
        else:
            self._user_profile_idx = DEFAULT_USER_PROFILE_IDX   # PROFILE-6

        # MED-01 + MED-10: store as mutable bytearray immediately
        if isinstance(password, (bytes, bytearray)):
            self._pw_buf = bytearray(password)
        else:
            self._pw_buf = bytearray(str(password).encode("utf-8"))

    def run(self):
        pw_bytes = bytes(self._pw_buf)
        try:
            cb = lambda p, m: self.progress.emit(p, m)

            # PROFILE-7: convert user-facing index to file-header scrypt_idx
            sidx = USER_PROFILES[self._user_profile_idx]["scrypt_idx"]

            # LOW-06: explicit dispatch — unknown task raises immediately
            if self.task == "encrypt":
                r = encrypt_folder(self.src, self.dst, pw_bytes, cb,
                                   scrypt_idx=sidx) \
                    if self.is_folder else \
                    encrypt_file(self.src, self.dst, pw_bytes, cb,
                                 scrypt_idx=sidx)   # PROFILE-7
            elif self.task == "decrypt":
                r = smart_decrypt(self.src, self.dst, pw_bytes, cb)
            elif self.task == "verify":
                r = verify_file(self.src, pw_bytes, cb)
            else:
                raise ValueError(
                    f"Unknown task {self.task!r}. "
                    "Must be 'encrypt', 'decrypt', or 'verify'.")

            # Success → clear failure counter for this file
            _bf_reset(_get_file_salt_id(self.src))
            self.finished.emit(r)

        except StructuralCorruptionError as e:
            self.error.emit(str(e), "structural")

        except AuthenticationError as e:
            salt_key   = _get_file_salt_id(self.src)
            fail_count = _bf_increment(salt_key)
            delay      = min(fail_count * _DELAY_STEP, _MAX_DELAY)
            logging.warning(
                "Auth failure #%d (key=%s…) — applying %.1fs delay",
                fail_count, salt_key[:8], delay)
            time.sleep(delay)
            self.error.emit(str(e), "auth")

        except ContentCorruptionError as e:
            self.error.emit(str(e), "content")

        except MemoryError as e:
            # Raised by _scrypt_derive_raw when the system lacks enough RAM
            # for the selected scrypt profile (e.g. N=2^20 → 1 GB required).
            self.error.emit(str(e), "other")

        except RuntimeError as e:
            # Raised by _scrypt_ctypes when libcrypto cannot be loaded or
            # EVP_PBE_scrypt returns an error code — happens on profiles that
            # exceed OpenSSL's ~32 MB hashlib cap and the ctypes path fails.
            self.error.emit(str(e), "other")

        except ValueError as e:
            msg = str(e)
            # Legacy un-typed auth errors (e.g. from _decrypt_bytes_raw)
            if "authentication failed" in msg.lower() or "incorrect password" in msg.lower():
                salt_key   = _get_file_salt_id(self.src)
                fail_count = _bf_increment(salt_key)
                delay      = min(fail_count * _DELAY_STEP, _MAX_DELAY)
                logging.warning(
                    "Auth failure #%d (key=%s…) — applying %.1fs delay",
                    fail_count, salt_key[:8], delay)
                time.sleep(delay)
                self.error.emit(msg, "auth")
            else:
                self.error.emit(msg, "other")

        except Exception as e:
            logging.error("Worker task=%s unexpected: %s", self.task, e, exc_info=True)
            self.error.emit(
                "Operation failed. Please check the file and password.", "other")

        finally:
            try:
                _zero_bytes_obj(pw_bytes)   # FIX-01: C-level zero before del
                del pw_bytes
            except NameError:
                pass
            # LOW-24: slice assignment — C-level zeroing
            if hasattr(self, "_pw_buf"):
                self._pw_buf[:] = b"\x00" * len(self._pw_buf)
                del self._pw_buf