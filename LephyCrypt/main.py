"""Lephy Crypt — Entry Point

Usage:
    python main.py              → English default (splash pre-selects EN)
    python main.py DEFAULT=t    → Turkish default (splash pre-selects TR)
    python main.py DEFAULT=e    → English default (explicit)
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Parse DEFAULT= argument ───────────────────────────────────────────────────
_DEFAULT_LANG = "en"   # fallback

for _arg in sys.argv[1:]:
    if _arg.upper().startswith("DEFAULT="):
        _val = _arg.split("=", 1)[1].strip().lower()
        if _val == "t":
            _DEFAULT_LANG = "tr"
        elif _val == "e":
            _DEFAULT_LANG = "en"
        break   # first matching arg wins

# ── Launch ────────────────────────────────────────────────────────────────────
from gui import run

if __name__ == "__main__":
    run(default_lang=_DEFAULT_LANG)