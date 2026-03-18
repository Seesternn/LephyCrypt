"""
Lephy Crypt — GUI  (v3.9, frameless, rounded corners)
======================================================
Security fixes from patch review:
  NEW-MED-01 : MIN_PASSWORD_LENGTH = 8 restored in EncryptPage._check()
"""

import os
import sys
import hmac
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QFrame, QStackedWidget,
    QFileDialog, QProgressBar, QScrollArea, QSizeGrip, QMessageBox,
)
from PyQt5.QtCore  import Qt, pyqtSignal, QRectF, QTimer, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui   import QIcon, QPixmap, QPainterPath, QRegion, QPainter, QLinearGradient, QColor
from PyQt5.QtWidgets import QGraphicsOpacityEffect

from crypto import (SCRYPT_PARAMS, APP_VERSION, SCRYPT_WEAK_PROFILE,
                    password_strength, USER_PROFILES, DEFAULT_USER_PROFILE_IDX,
                    inspect_file, StructuralCorruptionError)
from worker import Worker

# ── Paths ─────────────────────────────────────────────────────────────────────
DOWNLOADS  = os.path.join(os.path.expanduser("~"), "Downloads")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ICO_PATH   = os.path.join(SCRIPT_DIR, "icons.ico")
JPG_PATH   = os.path.join(SCRIPT_DIR, "icons.jpg")

# ── Design tokens ─────────────────────────────────────────────────────────────
BG     = "#f8f9fc"
WHITE  = "#ffffff"
BRD    = "#e4e7f0"
BRD2   = "#cdd2e8"
BLUE   = "#4361ee"
BLUEL  = "#6478f5"
BLUEBG = "rgba(67,97,238,0.06)"
TXT    = "#181c2e"
TXTD   = "#6b738f"
TXTM   = "#b0b7cc"
TXTMM  = "#d4d8e8"
GREEN  = "#10b981"

QSS = f"""
* {{ font-family:"Segoe UI","SF Pro Text",sans-serif; font-size:13px; outline:none; }}
QWidget {{ background:{BG}; color:{TXT}; border:none; }}

QWidget#tbar {{ background:{WHITE}; border-bottom:1px solid {BRD}; }}
QLabel#appN  {{ color:{TXT}; font-size:14px; font-weight:700; background:transparent; letter-spacing:0.2px; }}

QPushButton#t {{
    background:transparent; border:none; border-bottom:2px solid transparent;
    color:{TXTD}; font-size:13px; font-weight:500; padding:0 24px; height:46px;
}}
QPushButton#t:hover {{ color:{TXT}; }}
QPushButton#tOn {{
    background:transparent; border:none; border-bottom:2px solid {BLUE};
    color:{BLUE}; font-size:13px; font-weight:700; padding:0 24px; height:46px;
}}

QPushButton#wMin {{
    background:transparent; border:none; color:{TXTM}; font-size:16px;
    padding:0; border-radius:6px; min-width:32px; max-width:32px;
    min-height:32px; max-height:32px;
}}
QPushButton#wMin:hover {{ background:{BG}; color:{TXTD}; }}
QPushButton#wClose {{
    background:transparent; border:none; color:{TXTM}; font-size:14px;
    padding:0; border-radius:6px; min-width:32px; max-width:32px;
    min-height:32px; max-height:32px;
}}
QPushButton#wClose:hover {{ background:#fde8e8; color:#e84040; }}

QLabel#ph {{ color:{TXT}; font-size:22px; font-weight:700; background:transparent; letter-spacing:-0.5px; }}
QLabel#ps {{ color:{TXTD}; font-size:12px; background:transparent; }}
QLabel#fl {{ color:{TXTD}; font-size:11px; font-weight:600; background:transparent; letter-spacing:0.3px; }}
QLabel#ht {{ color:{TXTM}; font-size:11px; background:transparent; }}

QFrame#dz {{
    background:{WHITE}; border:2px dashed {BRD2}; border-radius:12px;
}}
QLabel#di {{ color:{TXTMM}; font-size:30px; background:transparent; }}
QLabel#dm {{ color:{TXTD}; font-size:12px; font-weight:500; background:transparent; }}
QLabel#ds {{ color:{TXTM}; font-size:11px; background:transparent; }}

QLineEdit {{
    background:{WHITE}; border:1.5px solid {BRD};
    border-radius:9px; padding:9px 14px; color:{TXT}; font-size:13px;
}}
QLineEdit:focus {{ border-color:{BLUE}; }}
QLineEdit::placeholder {{ color:{TXTMM}; }}
QLineEdit:read-only {{
    background:{BG}; color:{TXTD}; font-family:monospace; font-size:11px;
}}

QPushButton {{
    background:{WHITE}; border:1.5px solid {BRD};
    border-radius:9px; color:{TXTD}; padding:8px 16px; font-weight:500;
}}
QPushButton:hover {{ background:{BG}; border-color:{BRD2}; color:{TXT}; }}

QPushButton#bp {{
    background:{BLUE}; color:white; border:none; border-radius:9px;
    font-size:13px; font-weight:700; padding:0;
}}
QPushButton#bp:hover {{ background:{BLUEL}; }}
QPushButton#bp:disabled {{ background:{BRD}; color:{TXTM}; }}

QPushButton#bg {{
    background:{GREEN}; color:white; border:none; border-radius:9px;
    font-size:13px; font-weight:700; padding:0;
}}
QPushButton#bg:hover {{ background:#12d499; }}
QPushButton#bg:disabled {{ background:{BRD}; color:{TXTM}; }}

QPushButton#bo {{
    background:transparent; border:1.5px solid {BRD2};
    color:{TXTD}; border-radius:9px; font-size:12px; padding:8px 16px;
}}
QPushButton#bo:hover {{ border-color:{BLUE}; color:{BLUE}; background:{BLUEBG}; }}

QPushButton#eye {{
    background:transparent; border:none; color:{TXTM};
    font-size:15px; padding:4px 7px; border-radius:7px;
}}
QPushButton#eye:hover {{ color:{BLUE}; background:{BLUEBG}; }}

QFrame#mf {{ background:{BG}; border:1.5px solid {BRD}; border-radius:9px; }}
QPushButton#moff {{
    background:transparent; border:none; color:{TXTD};
    font-size:11px; font-weight:600; padding:4px 16px; border-radius:7px;
}}
QPushButton#moff:hover {{ color:{TXT}; }}
QPushButton#mon {{
    background:{WHITE}; border:1px solid {BRD}; color:{TXT};
    font-size:11px; font-weight:700; padding:4px 16px; border-radius:7px;
}}

QFrame#vdiv {{ background:{BRD}; border:none; max-width:1px; }}

QProgressBar {{ background:{BG}; border:none; border-radius:3px; }}
QProgressBar::chunk {{ background:{BLUE}; border-radius:3px; }}
QProgressBar#pbg::chunk {{ background:{GREEN}; border-radius:3px; }}

QScrollBar:vertical {{ background:transparent; width:4px; border:none; }}
QScrollBar::handle:vertical {{ background:{BRD}; border-radius:2px; min-height:24px; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height:0; }}
QSizeGrip {{ background:transparent; width:12px; height:12px; }}

QPushButton#profOff {{
    background:transparent; border:1.5px solid {BRD2};
    color:{TXTD}; border-radius:8px; font-size:11px; font-weight:600; padding:0 10px;
}}
QPushButton#profOff:hover {{ border-color:{BLUE}; color:{TXT}; background:{BLUEBG}; }}
QPushButton#profOn {{
    background:{BLUE}; color:white; border:none;
    border-radius:8px; font-size:11px; font-weight:700; padding:0 10px;
}}

QFrame#intOk   {{ background:#f0faf5; border:1.5px solid #3ab97a; border-radius:9px; }}
QFrame#intWarn {{ background:#fff8f0; border:1.5px solid #e07832; border-radius:9px; }}
QFrame#intErr  {{ background:#fff0f0; border:1.5px solid #e05252; border-radius:9px; }}
QLabel#intText {{ font-size:11px; font-weight:600; background:transparent; border:none; }}
QLabel#intSub  {{ font-size:10px; background:transparent; border:none; color:{TXTD}; }}
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def L(t, o=""):
    w = QLabel(t)
    if o: w.setObjectName(o)
    return w

def sp(n):
    w = QWidget(); w.setFixedHeight(n); return w

def hsp(n):
    w = QWidget(); w.setFixedWidth(n); return w

def vdiv():
    f = QFrame(); f.setObjectName("vdiv"); return f

def _clear_clipboard():
    """LOW-06: wipe clipboard so pasted passwords don't linger."""
    try:
        QApplication.clipboard().clear()
    except Exception:
        pass


# ── Password Field ────────────────────────────────────────────────────────────

class PwField(QWidget):
    textChanged = pyqtSignal()

    def __init__(self, ph=""):
        super().__init__()
        r = QHBoxLayout(self); r.setContentsMargins(0,0,0,0); r.setSpacing(5)
        self.edit = QLineEdit(); self.edit.setPlaceholderText(ph)
        self.edit.setEchoMode(QLineEdit.Password)
        self.edit.textChanged.connect(self.textChanged.emit)
        b = QPushButton("○"); b.setObjectName("eye")
        b.setFixedSize(36,36); b.setCheckable(True)
        b.toggled.connect(lambda v: (
            self.edit.setEchoMode(QLineEdit.Normal if v else QLineEdit.Password),
            b.setText("●" if v else "○")))
        r.addWidget(self.edit); r.addWidget(b)

    def text(self):       return self.edit.text()
    def setText(self, t): self.edit.setText(t)

    def clear_secure(self):
        """
        LOW-11 / LOW-03: Multi-pass overwrite before clearing.
        INFO-03: Echo mode set to Password first so fillers are never visible.
        Note: Qt C++ heap cannot be guaranteed zeroed from Python (see audit LOW-03).
        """
        self.edit.setEchoMode(QLineEdit.Password)
        n = len(self.edit.text())
        if n:
            for filler in (
                b"\x00" * n,
                b"\xff" * n,
                b"\xaa" * n,
                b" " * n,
            ):
                self.edit.setText(filler.decode("latin-1"))
        self.edit.clear()


# ── Strength Bar ──────────────────────────────────────────────────────────────

class StrBar(QWidget):
    COLS = ["#e84040", "#e87030", "#d4a820", GREEN, "#00d492"]

    def __init__(self):
        super().__init__(); self.setFixedHeight(24)
        r = QHBoxLayout(self); r.setContentsMargins(0,4,0,4); r.setSpacing(4)
        self.segs = []
        for _ in range(5):
            f = QFrame(); f.setFixedHeight(5)
            f.setStyleSheet(f"background:{BRD}; border-radius:3px;")
            r.addWidget(f,1); self.segs.append(f)
        self.lbl = QLabel("")
        self.lbl.setFixedWidth(68)
        self.lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.lbl.setStyleSheet(
            f"color:{TXTM}; font-size:10px; font-weight:700; background:transparent;")
        r.addWidget(self.lbl)

    def update_pw(self, pw):
        score, txt, color = password_strength(pw)
        filled = int(score / 20)
        for i, s in enumerate(self.segs):
            c = self.COLS[min(i,4)] if i < filled else BRD
            s.setStyleSheet(f"background:{c}; border-radius:3px;")
        self.lbl.setText(txt)
        self.lbl.setStyleSheet(
            f"color:{color}; font-size:10px; font-weight:700; background:transparent;")


# ── Mode Toggle ───────────────────────────────────────────────────────────────

class ModeToggle(QWidget):
    changed = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self._m = "file"
        o = QHBoxLayout(self); o.setContentsMargins(0,0,0,0)
        f = QFrame(); f.setObjectName("mf"); f.setFixedHeight(34)
        i = QHBoxLayout(f); i.setContentsMargins(3,3,3,3); i.setSpacing(0)
        self.bf = QPushButton(LangManager.t("mode_file"))
        self.bd = QPushButton(LangManager.t("mode_folder"))
        for b in (self.bf, self.bd):
            b.setFixedHeight(26); b.setCursor(Qt.PointingHandCursor)
        self.bf.clicked.connect(lambda: self._s("file"))
        self.bd.clicked.connect(lambda: self._s("folder"))
        i.addWidget(self.bf); i.addWidget(self.bd); o.addWidget(f)
        self._s("file")

    def _s(self, m):
        self._m = m
        self.bf.setObjectName("mon" if m=="file"   else "moff")
        self.bd.setObjectName("mon" if m=="folder" else "moff")
        for b in (self.bf, self.bd): b.style().unpolish(b); b.style().polish(b)
        self.changed.emit(m)

    def retranslate(self):
        self.bf.setText(LangManager.t("mode_file"))
        self.bd.setText(LangManager.t("mode_folder"))

    @property
    def mode(self): return self._m


# ── Drop Zone ─────────────────────────────────────────────────────────────────

class DropZone(QFrame):
    picked = pyqtSignal(str)

    def __init__(self, mode="file", hint=None, h=120):
        super().__init__()
        self.mode  = mode
        self._path = None
        self._custom_hint = hint   # if set, overrides LangManager for this instance
        self.setObjectName("dz"); self.setFixedHeight(h)
        self.setCursor(Qt.PointingHandCursor)
        self.setAcceptDrops(True)

        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(0,0,0,0)
        self._lay.setAlignment(Qt.AlignCenter)

        self._empty = QWidget()
        el = QVBoxLayout(self._empty); el.setContentsMargins(0,10,0,10); el.setSpacing(5)
        self._ico      = L("⬚","di"); self._ico.setAlignment(Qt.AlignCenter)
        self._mtxt = L(self._hint_text(),"dm"); self._mtxt.setAlignment(Qt.AlignCenter)
        self._sub  = L(LangManager.t("drop_all_types"),"ds"); self._sub.setAlignment(Qt.AlignCenter)
        el.addWidget(self._ico); el.addWidget(self._mtxt); el.addWidget(self._sub)

        self._filled = QWidget()
        fl = QHBoxLayout(self._filled); fl.setContentsMargins(18,0,14,0); fl.setSpacing(12)
        self._fIco = L("■","di"); self._fIco.setFixedWidth(28); self._fIco.setAlignment(Qt.AlignCenter)
        self._fIco.setStyleSheet(f"color:{BLUE}; font-size:20px; background:transparent;")
        tc = QVBoxLayout(); tc.setSpacing(3); tc.setContentsMargins(0,0,0,0)
        self._fName = L("","dm"); self._fPath = L("","ds")
        self._fPath.setStyleSheet(f"color:{TXTM}; font-size:10px; background:transparent;")
        tc.addWidget(self._fName); tc.addWidget(self._fPath)
        self._clr = QPushButton("✕"); self._clr.setObjectName("eye")
        self._clr.setFixedSize(28,28); self._clr.setCursor(Qt.PointingHandCursor)
        self._clr.clicked.connect(self.clear)
        fl.addWidget(self._fIco); fl.addLayout(tc,1); fl.addWidget(self._clr)
        self._filled.hide()

        self._lay.addWidget(self._empty)
        self._lay.addWidget(self._filled)

    def _hint_text(self) -> str:
        if self._custom_hint:
            return self._custom_hint
        if self.mode == "folder":
            return LangManager.t("drop_folder")
        return LangManager.t("drop_file")

    def retranslate(self):
        self._mtxt.setText(self._hint_text())
        self._sub.setText(LangManager.t("drop_all_types"))

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self.setStyleSheet(
                f"QFrame#dz {{ background:rgba(67,97,238,0.06); "
                f"border:2px solid {BLUE}; border-radius:12px; }}")

    def dragLeaveEvent(self, e): self.setStyleSheet("")

    def dropEvent(self, e):
        self.setStyleSheet("")
        urls = e.mimeData().urls()
        if urls:
            p = urls[0].toLocalFile()
            if   self.mode == "file"   and os.path.isfile(p): self.set_path(p)
            elif self.mode == "folder" and os.path.isdir(p):  self.set_path(p)

    def mousePressEvent(self, e):
        if self.mode == "file":
            p, _ = QFileDialog.getOpenFileName(self, "Select File")
        else:
            p = QFileDialog.getExistingDirectory(self, "Select Folder")
        if p: self.set_path(p)

    def set_path(self, path):
        self._path = path
        self._fName.setText(Path(path).name)
        self._fPath.setText(path)
        self.setStyleSheet(
            f"QFrame#dz {{ background:rgba(67,97,238,0.05); "
            f"border:2px solid {BLUE}; border-radius:12px; }}")
        self._empty.hide(); self._filled.show()
        self.picked.emit(path)

    def clear(self):
        self._path = None
        self.setStyleSheet("")
        self._empty.show(); self._filled.hide()

    def set_mode(self, mode):
        self.mode = mode
        self._custom_hint = None   # clear custom hint when mode changes
        self._mtxt.setText(self._hint_text())
        self.clear()

    @property
    def path(self): return self._path


# ══════════════════════════════════════════════════════════════════════════════
#  INTEGRITY BADGE
# ══════════════════════════════════════════════════════════════════════════════

class IntegrityBadge(QFrame):
    """
    Compact inline badge shown on the Decrypt page immediately after the user
    drops a file — password-free structural inspection result.
    States: hidden → ok (green) → warn (orange) → err (red).
    """
    def __init__(self):
        super().__init__()
        self.hide()
        lay = QHBoxLayout(self); lay.setContentsMargins(10, 7, 10, 7); lay.setSpacing(8)
        self._icon = QLabel()
        self._icon.setStyleSheet("font-size:16px; background:transparent; border:none;")
        self._text = QLabel(); self._text.setObjectName("intText")
        self._sub  = QLabel(); self._sub.setObjectName("intSub")
        self._sub.setWordWrap(True)
        right = QVBoxLayout(); right.setSpacing(1); right.setContentsMargins(0,0,0,0)
        right.addWidget(self._text); right.addWidget(self._sub)
        lay.addWidget(self._icon); lay.addLayout(right, 1)

    def set_ok(self, prof: str, chunks: int, mb: float):
        self.setObjectName("intOk")
        self._icon.setText("✓")
        self._icon.setStyleSheet("font-size:16px; color:#3ab97a; background:transparent; border:none;")
        self._text.setText(LangManager.t("int_ok_title"))
        self._text.setStyleSheet("color:#3ab97a; font-size:11px; font-weight:600; background:transparent; border:none;")
        self._sub.setText(LangManager.t("int_sub_ok").format(prof=prof, chunks=chunks, mb=mb))
        self._refresh(); self.show()

    def set_warn(self, msg: str):
        self.setObjectName("intWarn")
        self._icon.setText("⚠")
        self._icon.setStyleSheet("font-size:16px; color:#e07832; background:transparent; border:none;")
        self._text.setText(LangManager.t("int_warn_title"))
        self._text.setStyleSheet("color:#e07832; font-size:11px; font-weight:600; background:transparent; border:none;")
        self._sub.setText(msg)
        self._refresh(); self.show()

    def set_err(self, msg: str):
        self.setObjectName("intErr")
        self._icon.setText("✕")
        self._icon.setStyleSheet("font-size:16px; color:#e05252; background:transparent; border:none;")
        self._text.setText(LangManager.t("int_err_title"))
        self._text.setStyleSheet("color:#e05252; font-size:11px; font-weight:600; background:transparent; border:none;")
        self._sub.setText(msg)
        self._refresh(); self.show()

    def clear(self):
        self.hide()

    def _refresh(self):
        self.style().unpolish(self); self.style().polish(self)


# ══════════════════════════════════════════════════════════════════════════════
#  PROFILE SELECTOR  (PROFILE-9)
# ══════════════════════════════════════════════════════════════════════════════

class ProfileSelector(QWidget):
    """
    PROFILE-9: Two-row button grid (4 + 3) for 7 scrypt profiles.
    Row 1: Light / Balanced / Strong / Ultra
    Row 2: Extreme / Insane / Max
    Defaults to DEFAULT_USER_PROFILE_IDX chosen by the startup benchmark.
    Emits changed(int) with user_profile_idx on selection.
    """
    changed = pyqtSignal(int)

    def __init__(self, default_idx: int | None = None):
        super().__init__()
        self._idx = default_idx if default_idx is not None else DEFAULT_USER_PROFILE_IDX

        outer = QVBoxLayout(self); outer.setContentsMargins(0, 0, 0, 0); outer.setSpacing(4)

        row1 = QHBoxLayout(); row1.setContentsMargins(0,0,0,0); row1.setSpacing(5)
        row2 = QHBoxLayout(); row2.setContentsMargins(0,0,0,0); row2.setSpacing(5)
        self._btns: list[QPushButton] = []

        for i, up in enumerate(USER_PROFILES):
            b = QPushButton(up["label"])
            b.setObjectName("profOff")
            b.setFixedHeight(28)
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(lambda _, idx=i: self._select(idx))
            (row1 if i < 4 else row2).addWidget(b)
            self._btns.append(b)

        self._desc = QLabel("")
        self._desc.setStyleSheet(
            f"color:{TXTM}; font-size:10px; background:transparent;")

        outer.addLayout(row1)
        outer.addLayout(row2)
        outer.addWidget(self._desc)
        self._select(self._idx, silent=True)

    def _select(self, idx: int, silent: bool = False) -> None:
        self._idx = idx
        for i, b in enumerate(self._btns):
            b.setObjectName("profOn" if i == idx else "profOff")
            b.style().unpolish(b); b.style().polish(b)
        self._desc.setText(USER_PROFILES[idx]["desc"])
        if not silent:
            self.changed.emit(idx)

    @property
    def profile_idx(self) -> int:
        return self._idx


# ══════════════════════════════════════════════════════════════════════════════
#  ENCRYPT PAGE
# ══════════════════════════════════════════════════════════════════════════════

class EncryptPage(QWidget):
    def __init__(self):
        super().__init__(); self._worker = None; self._build()

    def _build(self):
        root   = QVBoxLayout(self); root.setContentsMargins(0,0,0,0)
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        body = QWidget()
        lay  = QVBoxLayout(body); lay.setContentsMargins(44,24,44,24); lay.setSpacing(18)

        hrow = QHBoxLayout(); hrow.setSpacing(0)
        htxt = QVBoxLayout(); htxt.setSpacing(4)
        self._lbl_title    = L(LangManager.t("enc_title"),    "ph")
        self._lbl_subtitle = L(LangManager.t("enc_subtitle"), "ps")
        htxt.addWidget(self._lbl_title)
        htxt.addWidget(self._lbl_subtitle)
        hrow.addLayout(htxt,1)
        self.tog = ModeToggle(); self.tog.changed.connect(self._on_mode)
        hrow.addWidget(self.tog,0,Qt.AlignVCenter)
        lay.addLayout(hrow)

        cols = QHBoxLayout(); cols.setSpacing(0)

        left = QVBoxLayout(); left.setSpacing(14)
        sl = QVBoxLayout(); sl.setSpacing(7)
        self._lbl_source = L(LangManager.t("enc_source"), "fl")
        sl.addWidget(self._lbl_source)
        self.drop = DropZone("file"); self.drop.picked.connect(self._on_src)
        sl.addWidget(self.drop); left.addLayout(sl)

        ol = QVBoxLayout(); ol.setSpacing(7)
        self._lbl_output = L(LangManager.t("enc_output_label"), "fl")
        ol.addWidget(self._lbl_output)
        or2 = QHBoxLayout(); or2.setSpacing(8)
        self.outE = QLineEdit(); self.outE.setReadOnly(True)
        self.outE.setPlaceholderText(DOWNLOADS)
        self._btn_browse = QPushButton(LangManager.t("browse"))
        self._btn_browse.setObjectName("bo"); self._btn_browse.setFixedWidth(84)
        self._btn_browse.clicked.connect(self._browse_out)
        or2.addWidget(self.outE); or2.addWidget(self._btn_browse)
        ol.addLayout(or2); left.addLayout(ol)

        # PROFILE-10: profile selector below Browse on the left
        pfl = QVBoxLayout(); pfl.setSpacing(5)
        self._lbl_strength = L(LangManager.t("enc_strength"), "fl")
        pfl.addWidget(self._lbl_strength)
        self.profSel = ProfileSelector()
        pfl.addWidget(self.profSel)
        left.addLayout(pfl)

        left.addStretch()
        cols.addLayout(left,5)

        cols.addWidget(hsp(36)); cols.addWidget(vdiv()); cols.addWidget(hsp(36))

        right = QVBoxLayout(); right.setSpacing(14)
        pl = QVBoxLayout(); pl.setSpacing(7)
        self._lbl_pw  = L(LangManager.t("enc_password"), "fl")
        pl.addWidget(self._lbl_pw)
        self.pw  = PwField(LangManager.t("enc_password_ph")); self.pw.textChanged.connect(self._pw_ch)
        pl.addWidget(self.pw)
        self._lbl_pw2 = L(LangManager.t("enc_confirm"), "fl")
        pl.addWidget(self._lbl_pw2)
        self.pw2 = PwField(LangManager.t("enc_confirm_ph")); self.pw2.textChanged.connect(self._pw_ch)
        pl.addWidget(self.pw2)
        self.strength = StrBar(); pl.addWidget(self.strength)
        right.addLayout(pl)

        right.addStretch()

        al = QVBoxLayout(); al.setSpacing(8)
        self.pb = QProgressBar(); self.pb.setRange(0,100); self.pb.setValue(0)
        self.pb.setFixedHeight(7); self.pb.setTextVisible(False)
        al.addWidget(self.pb)
        self.stLbl = L(LangManager.t("enc_fill"),"ht"); al.addWidget(self.stLbl)
        self.btn = QPushButton(LangManager.t("enc_btn"))
        self.btn.setObjectName("bp"); self.btn.setFixedHeight(44)
        self.btn.setEnabled(False); self.btn.setCursor(Qt.PointingHandCursor)
        self.btn.clicked.connect(self._run)
        al.addWidget(self.btn); right.addLayout(al)
        cols.addLayout(right,4)

        lay.addLayout(cols); lay.addStretch()
        scroll.setWidget(body); root.addWidget(scroll)

    def retranslate(self):
        """Update all visible strings to the current LangManager language."""
        self._lbl_title.setText(LangManager.t("enc_title"))
        self._lbl_subtitle.setText(LangManager.t("enc_subtitle"))
        self._lbl_source.setText(LangManager.t("enc_source"))
        self._lbl_output.setText(LangManager.t("enc_output_label"))
        self._lbl_strength.setText(LangManager.t("enc_strength"))
        self._lbl_pw.setText(LangManager.t("enc_password"))
        self._lbl_pw2.setText(LangManager.t("enc_confirm"))
        self.pw.edit.setPlaceholderText(LangManager.t("enc_password_ph"))
        self.pw2.edit.setPlaceholderText(LangManager.t("enc_confirm_ph"))
        self._btn_browse.setText(LangManager.t("browse"))
        self.stLbl.setText(LangManager.t("enc_fill"))
        # button text depends on current mode
        self.btn.setText(
            LangManager.t("enc_btn_folder") if self.tog.mode == "folder"
            else LangManager.t("enc_btn"))
        self.tog.retranslate()
        self.drop.retranslate()

    def _on_mode(self, m):
        self.drop.set_mode(m); self.outE.clear()
        self.btn.setText(LangManager.t("enc_btn_folder") if m=="folder"
                         else LangManager.t("enc_btn"))
        self._check()

    def _on_src(self, path):
        self.outE.setText(os.path.join(DOWNLOADS, Path(path).name + ".lcrypt"))
        self._check()

    def _browse_out(self):
        p, _ = QFileDialog.getSaveFileName(
            self, LangManager.t("save_enc_dialog"), DOWNLOADS,
            "Lephy Crypt (*.lcrypt);;All (*)")
        if p:
            if not p.endswith(".lcrypt"): p += ".lcrypt"
            self.outE.setText(p); self._check()

    def _pw_ch(self):
        self.strength.update_pw(self.pw.text()); self._check()

    def _check(self):
        pw  = self.pw.text().strip()
        pw2 = self.pw2.text().strip()
        MIN_PW_LEN = 8   # NEW-MED-01: enforce minimum length
        valid_length    = len(pw) >= MIN_PW_LEN
        # INFO-02: constant-time comparison to avoid timing side-channel
        passwords_match = valid_length and hmac.compare_digest(
            pw.encode("utf-8"), pw2.encode("utf-8"))
        ok = bool(self.drop.path and self.outE.text() and passwords_match)
        self.btn.setEnabled(ok)
        if not ok:
            if not self.drop.path:    self.stLbl.setText(LangManager.t("enc_select_src"))
            elif not pw:              self.stLbl.setText(LangManager.t("enc_enter_pw"))
            elif not valid_length:    self.stLbl.setText(
                                          LangManager.t("enc_pw_short").format(n=MIN_PW_LEN))
            elif not passwords_match: self.stLbl.setText(LangManager.t("enc_pw_mismatch"))
            else:                     self.stLbl.setText(LangManager.t("enc_fill"))

    def _run(self):
        _clear_clipboard()
        self.btn.setEnabled(False); self.pb.setValue(0)
        # MED-04: strip whitespace consistently before encoding
        pw_stripped = self.pw.text().strip()
        self._worker = Worker("encrypt", self.drop.path, self.outE.text(),
                              pw_stripped.encode("utf-8"),
                              self.tog.mode == "folder",
                              profile_idx=self.profSel.profile_idx)   # PROFILE-11
        self._worker.progress.connect(lambda v,m: (self.pb.setValue(v), self.stLbl.setText(m)))
        self._worker.finished.connect(self._done)
        self._worker.error.connect(lambda msg, _t: self._err(msg))   # two-arg signal adapter
        self._worker.start()

    def _done(self, info):
        self.pb.setValue(100)
        self.pb.setObjectName("pbg")
        self.pb.style().unpolish(self.pb); self.pb.style().polish(self.pb)
        self.stLbl.setText(LangManager.t("enc_done"))
        # LOW-11: clear password fields after successful operation
        self.pw.clear_secure(); self.pw2.clear_secure()
        self.strength.update_pw("")
        t = LangManager.t("enc_type_folder") if info["mode"] == "folder" \
            else LangManager.t("enc_type_file")
        QMessageBox.information(self, LangManager.t("enc_complete_title"),
            LangManager.t("enc_complete_body").format(
                t=t,
                orig=info['original_size'],
                enc=info['output_size'],
                prof=info['profile'],
                dst=self.outE.text()))
        self.btn.setEnabled(True)

    def _err(self, msg):
        self.pb.setValue(0); self.stLbl.setText(LangManager.t("enc_err_status"))
        # LOW-11: clear on error too
        self.pw.clear_secure(); self.pw2.clear_secure()
        self.strength.update_pw("")
        QMessageBox.critical(self, LangManager.t("enc_error_title"), msg)
        self.btn.setEnabled(True)


# ══════════════════════════════════════════════════════════════════════════════
#  DECRYPT PAGE
# ══════════════════════════════════════════════════════════════════════════════

class DecryptPage(QWidget):
    def __init__(self):
        super().__init__(); self._worker = None; self._build()

    def _build(self):
        root   = QVBoxLayout(self); root.setContentsMargins(0,0,0,0)
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        body = QWidget()
        lay  = QVBoxLayout(body); lay.setContentsMargins(44,24,44,24); lay.setSpacing(18)

        htxt = QVBoxLayout(); htxt.setSpacing(4)
        self._lbl_title    = L(LangManager.t("dec_title"),    "ph")
        self._lbl_subtitle = L(LangManager.t("dec_subtitle"), "ps")
        htxt.addWidget(self._lbl_title)
        htxt.addWidget(self._lbl_subtitle)
        lay.addLayout(htxt)

        cols = QHBoxLayout(); cols.setSpacing(0)

        left = QVBoxLayout(); left.setSpacing(14)
        sl = QVBoxLayout(); sl.setSpacing(7)
        self._lbl_enc_file = L(LangManager.t("dec_enc_file"), "fl")
        sl.addWidget(self._lbl_enc_file)
        self.drop = DropZone("file", LangManager.t("drop_lcrypt"))
        self.drop.picked.connect(self._on_src); sl.addWidget(self.drop)
        left.addLayout(sl)

        # Integrity badge — password-free structural check on file drop
        self.badge = IntegrityBadge()
        left.addWidget(self.badge)

        ol = QVBoxLayout(); ol.setSpacing(7)
        self._lbl_output = L(LangManager.t("dec_output"), "fl")
        ol.addWidget(self._lbl_output)
        or2 = QHBoxLayout(); or2.setSpacing(8)
        self.outE = QLineEdit(); self.outE.setReadOnly(True)
        self.outE.setPlaceholderText(DOWNLOADS)
        self._btn_browse = QPushButton(LangManager.t("browse"))
        self._btn_browse.setObjectName("bo"); self._btn_browse.setFixedWidth(84)
        self._btn_browse.clicked.connect(self._browse_out)
        or2.addWidget(self.outE); or2.addWidget(self._btn_browse)
        ol.addLayout(or2); left.addLayout(ol)
        left.addStretch()
        cols.addLayout(left,5)

        cols.addWidget(hsp(36)); cols.addWidget(vdiv()); cols.addWidget(hsp(36))

        right = QVBoxLayout(); right.setSpacing(14)
        pl = QVBoxLayout(); pl.setSpacing(7)
        self._lbl_pw = L(LangManager.t("dec_password"), "fl")
        pl.addWidget(self._lbl_pw)
        self.pw = PwField(LangManager.t("dec_password_ph"))
        self.pw.textChanged.connect(self._check)
        pl.addWidget(self.pw); right.addLayout(pl)

        self._note = QLabel(LangManager.t("dec_note"))
        self._note.setStyleSheet(
            f"color:{TXTD}; font-size:12px; background:transparent; border:none;")
        self._note.setWordWrap(True); right.addWidget(self._note)
        right.addStretch()

        al = QVBoxLayout(); al.setSpacing(8)
        self.pb = QProgressBar(); self.pb.setObjectName("pbg")
        self.pb.setRange(0,100); self.pb.setValue(0)
        self.pb.setFixedHeight(7); self.pb.setTextVisible(False)
        al.addWidget(self.pb)
        self.stLbl = L(LangManager.t("dec_fill"),"ht"); al.addWidget(self.stLbl)

        # Verify Only + Decrypt Now side by side
        btnRow = QHBoxLayout(); btnRow.setSpacing(8)
        self.verBtn = QPushButton(LangManager.t("verify_btn"))
        self.verBtn.setObjectName("bo"); self.verBtn.setFixedHeight(44)
        self.verBtn.setEnabled(False); self.verBtn.setCursor(Qt.PointingHandCursor)
        self.verBtn.setToolTip(LangManager.t("verify_tooltip"))
        self.verBtn.clicked.connect(self._run_verify)
        self.btn = QPushButton(LangManager.t("dec_btn"))
        self.btn.setObjectName("bg"); self.btn.setFixedHeight(44)
        self.btn.setEnabled(False); self.btn.setCursor(Qt.PointingHandCursor)
        self.btn.clicked.connect(self._run)
        btnRow.addWidget(self.verBtn, 2); btnRow.addWidget(self.btn, 3)
        al.addLayout(btnRow); right.addLayout(al)
        cols.addLayout(right,4)

        lay.addLayout(cols); lay.addStretch()
        scroll.setWidget(body); root.addWidget(scroll)

    def retranslate(self):
        """Update all visible strings to the current LangManager language."""
        self._lbl_title.setText(LangManager.t("dec_title"))
        self._lbl_subtitle.setText(LangManager.t("dec_subtitle"))
        self._lbl_enc_file.setText(LangManager.t("dec_enc_file"))
        self._lbl_output.setText(LangManager.t("dec_output"))
        self._lbl_pw.setText(LangManager.t("dec_password"))
        self.pw.edit.setPlaceholderText(LangManager.t("dec_password_ph"))
        self._note.setText(LangManager.t("dec_note"))
        self._btn_browse.setText(LangManager.t("browse"))
        self.stLbl.setText(LangManager.t("dec_fill"))
        self.btn.setText(LangManager.t("dec_btn"))
        self.verBtn.setText(LangManager.t("verify_btn"))
        self.verBtn.setToolTip(LangManager.t("verify_tooltip"))
        # update drop zone with translated lcrypt hint
        self.drop._custom_hint = LangManager.t("drop_lcrypt")
        self.drop.retranslate()

    def _on_src(self, path):
        name = Path(path).name
        base = name[:-7] if name.endswith(".lcrypt") else name + ".decrypted"
        self.outE.setText(os.path.join(DOWNLOADS, base))
        self._check()
        # Structural inspection — instant feedback, no password needed
        self.badge.clear()
        try:
            info = inspect_file(path)
            self.badge.set_ok(info["profile"], info["chunks"], info["file_size_mb"])
        except StructuralCorruptionError as e:
            self.badge.set_err(str(e))
        except Exception as e:
            self.badge.set_warn(str(e))

    def _browse_out(self):
        p, _ = QFileDialog.getSaveFileName(
            self, LangManager.t("output_dialog"), DOWNLOADS)
        if p: self.outE.setText(p); self._check()

    def _check(self):
        ok = bool(self.drop.path and self.outE.text() and self.pw.text())
        self.btn.setEnabled(ok)
        self.verBtn.setEnabled(bool(self.drop.path and self.pw.text()))

    def _set_busy(self, busy: bool):
        self.btn.setEnabled(not busy)
        self.verBtn.setEnabled(not busy)
        if busy: self.pb.setValue(0)

    def _run_verify(self):
        _clear_clipboard()
        self._set_busy(True)
        pw_stripped = self.pw.text().strip()
        self._worker = Worker("verify", self.drop.path, "",
                              pw_stripped.encode("utf-8"))
        self._worker.progress.connect(lambda v,m: (self.pb.setValue(v), self.stLbl.setText(m)))
        self._worker.finished.connect(self._verify_done)
        self._worker.error.connect(self._err)
        self._worker.start()

    def _verify_done(self, info):
        self.pb.setValue(100); self.stLbl.setText(LangManager.t("dec_done"))
        self.badge.set_ok(info.get("profile",""), info.get("chunks",0),
                          info.get("file_size",0) / (1024**2))
        QMessageBox.information(self, LangManager.t("verify_complete_title"),
            LangManager.t("verify_complete_body").format(
                prof=info.get("profile",""),
                chunks=info.get("chunks",0),
                sz=info.get("file_size",0)))
        self._set_busy(False)

    def _run(self):
        _clear_clipboard()
        self._set_busy(True)
        # MED-04: strip whitespace before encoding (consistent with _check)
        pw_stripped = self.pw.text().strip()
        self._worker = Worker("decrypt", self.drop.path,
                              self.outE.text(), pw_stripped.encode("utf-8"))
        self._worker.progress.connect(lambda v,m: (self.pb.setValue(v), self.stLbl.setText(m)))
        self._worker.finished.connect(self._done)
        self._worker.error.connect(self._err)
        self._worker.start()

    def _done(self, info):
        self.pb.setValue(100)
        self.pb.setObjectName("pbg")
        self.pb.style().unpolish(self.pb); self.pb.style().polish(self.pb)
        self.stLbl.setText(LangManager.t("dec_done"))
        # LOW-11: clear password field after success
        self.pw.clear_secure()
        sha = info.get("sha256", "")
        sha_line = (f"\n\n{LangManager.t('sha256_label')}\n"
                    f"{sha[:32]}\n{sha[32:]}") if sha else ""
        if info.get("mode") == "folder":
            msg = LangManager.t("dec_complete_folder").format(
                fc=info.get('file_count', 0),
                dst=info.get('output_dir', self.outE.text())) + sha_line
        else:
            msg = LangManager.t("dec_complete_file").format(
                sz=info.get('output_size', 0),
                dst=self.outE.text()) + sha_line
        QMessageBox.information(self, LangManager.t("dec_complete_title"), msg)
        self._set_busy(False)

    def _err(self, msg: str, error_type: str = "other"):
        self.pb.setValue(0)
        # LOW-11: clear on error too
        self.pw.clear_secure()

        if error_type == "structural":
            self.stLbl.setText(LangManager.t("dec_err_status"))
            self.badge.set_err(msg)
            QMessageBox.critical(self, LangManager.t("err_structural_title"),
                LangManager.t("err_structural_body").format(msg=msg))

        elif error_type == "auth":
            self.stLbl.setText(LangManager.t("dec_err_status"))
            # Badge stays green — structure is valid, only auth failed
            QMessageBox.critical(self, LangManager.t("err_auth_title"),
                LangManager.t("err_auth_body"))

        elif error_type == "content":
            self.stLbl.setText(LangManager.t("dec_err_status"))
            self.badge.set_err(msg)
            QMessageBox.critical(self, LangManager.t("err_content_title"),
                LangManager.t("err_content_body").format(msg=msg))

        else:
            self.stLbl.setText(LangManager.t("dec_err_status"))
            QMessageBox.critical(self, LangManager.t("dec_error_title"), msg)

        self._set_busy(False)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════════════════════════

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Lephy Crypt")   # INFO-01: version removed from title
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setMinimumSize(880, 420)
        self.resize(1040, 500)
        self._drag_pos = None
        self._set_icon()
        self._build()

    def _set_icon(self):
        if os.path.exists(ICO_PATH):
            self.setWindowIcon(QIcon(ICO_PATH))
        elif os.path.exists(JPG_PATH):
            pix  = QPixmap(JPG_PATH)
            icon = QIcon()
            for s in (16, 24, 32, 48, 64, 128, 256):
                icon.addPixmap(pix.scaled(s, s, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            self.setWindowIcon(icon)

    def _build(self):
        root = QWidget(); self.setCentralWidget(root)
        vl   = QVBoxLayout(root); vl.setContentsMargins(0,0,0,0); vl.setSpacing(0)

        self.tbar = QWidget(); self.tbar.setObjectName("tbar"); self.tbar.setFixedHeight(46)
        tl = QHBoxLayout(self.tbar); tl.setContentsMargins(0,0,12,0); tl.setSpacing(0)

        logo_w = QWidget(); logo_w.setStyleSheet("background:transparent;")
        ll = QHBoxLayout(logo_w); ll.setContentsMargins(16,0,16,0); ll.setSpacing(9)
        ico_lbl = QLabel(); ico_lbl.setFixedSize(26,26)
        ico_lbl.setStyleSheet("border:none; background:transparent; padding:0;")
        if os.path.exists(JPG_PATH):
            ico_lbl.setPixmap(
                QPixmap(JPG_PATH).scaled(26, 26, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        elif os.path.exists(ICO_PATH):
            ico_lbl.setPixmap(QIcon(ICO_PATH).pixmap(26, 26))
        else:
            ico_lbl.setText("LC"); ico_lbl.setAlignment(Qt.AlignCenter)
            ico_lbl.setStyleSheet(
                f"background:{BLUE}; color:white; font-weight:800; font-size:9px;"
                f"border-radius:7px; border:none;")
        ll.addWidget(ico_lbl); ll.addWidget(L("Lephy Crypt","appN"))
        tl.addWidget(logo_w)
        tl.addWidget(hsp(4))

        self._tabs = {}
        for key, lbl_key in [("enc", "tab_encrypt"), ("dec", "tab_decrypt")]:
            btn = QPushButton(LangManager.t(lbl_key)); btn.setObjectName("t")
            btn.setFixedHeight(46); btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _, k=key: self._sw(k))
            self._tabs[key] = btn; tl.addWidget(btn)

        tl.addStretch()

        b_min = QPushButton("—"); b_min.setObjectName("wMin")
        b_min.setCursor(Qt.PointingHandCursor); b_min.clicked.connect(self.showMinimized)
        b_cls = QPushButton("✕"); b_cls.setObjectName("wClose")
        b_cls.setCursor(Qt.PointingHandCursor); b_cls.clicked.connect(self.close)
        tl.addWidget(b_min); tl.addWidget(hsp(2)); tl.addWidget(b_cls)

        vl.addWidget(self.tbar)

        self._stack = QStackedWidget()
        self._pages = {"enc": EncryptPage(), "dec": DecryptPage()}
        for p in self._pages.values(): self._stack.addWidget(p)
        vl.addWidget(self._stack, 1)

        grip = QSizeGrip(self); grip.setFixedSize(14, 14)
        gl = QHBoxLayout(); gl.addStretch(); gl.addWidget(grip)
        gl.setContentsMargins(0, 0, 2, 2); vl.addLayout(gl)

        self._sw("enc")

    def retranslate(self, lang: str):
        """Switch UI language and update all visible strings."""
        LangManager.set(lang)
        # Tab bar
        tab_keys = {"enc": "tab_encrypt", "dec": "tab_decrypt"}
        for key, btn in self._tabs.items():
            btn.setText(LangManager.t(tab_keys[key]))
        # Pages
        self._pages["enc"].retranslate()
        self._pages["dec"].retranslate()

    def resizeEvent(self, e):
        path = QPainterPath()
        path.addRoundedRect(QRectF(self.rect()), 14, 14)
        self.setMask(QRegion(path.toFillPolygon().toPolygon()))
        super().resizeEvent(e)

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton and self.tbar.geometry().contains(e.pos()):
            self._drag_pos = e.globalPos() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if e.buttons() == Qt.LeftButton and self._drag_pos:
            self.move(e.globalPos() - self._drag_pos)

    def mouseReleaseEvent(self, e):
        self._drag_pos = None

    def _sw(self, k):
        self._stack.setCurrentWidget(self._pages[k])
        for x, b in self._tabs.items():
            b.setObjectName("tOn" if x==k else "t")
            b.style().unpolish(b); b.style().polish(b)


# ══════════════════════════════════════════════════════════════════════════════
#  LANGUAGE MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class LangManager:
    """Holds selected language and full string table for the entire app."""
    _lang = "en"

    _strings = {
        "en": {
            # ── splash ───────────────────────────────────────────────────────
            "tagline":            "Military-grade file encryption",
            "select_lang":        "Select language to continue",
            "loading":            "Loading…",
            # ── main window tabs ─────────────────────────────────────────────
            "tab_encrypt":        "Encrypt",
            "tab_decrypt":        "Decrypt",
            # ── encrypt page ─────────────────────────────────────────────────
            "enc_title":          "Encrypt",
            "enc_subtitle":       "Secure your files with AES-256-GCM authenticated encryption",
            "enc_source":         "SOURCE",
            "enc_output_label":   "OUTPUT  .lcrypt",
            "enc_strength":       "ENCRYPTION STRENGTH",
            "enc_password":       "PASSWORD",
            "enc_password_ph":    "Create a strong password",
            "enc_confirm":        "CONFIRM",
            "enc_confirm_ph":     "Repeat your password",
            "enc_fill":           "Fill in all fields to continue",
            "enc_btn":            "Encrypt Now",
            "enc_btn_folder":     "Encrypt Folder",
            "enc_done":           "Done ✓",
            "enc_err_status":     "Error",
            "enc_select_src":     "Select a source file or folder",
            "enc_enter_pw":       "Enter a password",
            "enc_pw_short":       "Password must be at least {n} characters",
            "enc_pw_mismatch":    "Passwords do not match",
            "enc_complete_title": "Encryption Complete",
            "enc_complete_body":  "Successfully encrypted.\n\nType       {t}\nOriginal   {orig:,} bytes\nEncrypted  {enc:,} bytes\nProfile    {prof}\n\nSaved to:\n{dst}",
            "enc_error_title":    "Encryption Error",
            "enc_type_file":      "File",
            "enc_type_folder":    "Folder",
            # ── decrypt page ─────────────────────────────────────────────────
            "dec_title":          "Decrypt",
            "dec_subtitle":       "Restore your files from a Lephy Crypt archive",
            "dec_enc_file":       "ENCRYPTED FILE  .lcrypt",
            "dec_output":         "OUTPUT DESTINATION",
            "dec_password":       "PASSWORD",
            "dec_password_ph":    "Enter your password",
            "dec_note":           "File type is automatically detected.\nSingle files and folder archives are both supported.",
            "dec_fill":           "Fill in all fields to continue",
            "dec_btn":            "Decrypt Now",
            "dec_done":           "Done ✓",
            "dec_err_status":     "Error",
            "dec_complete_title": "Decryption Complete",
            "dec_complete_folder":"Decryption successful.\n\nType     Folder archive\nFiles    {fc} extracted\n\nOutput:\n{dst}",
            "dec_complete_file":  "Decryption successful.\n\nType   Single file\nSize   {sz:,} bytes\n\nOutput:\n{dst}",
            "dec_error_title":    "Decryption Error",
            # ── integrity & verify (decrypt page) ────────────────────────────
            "verify_btn":              "Verify Only",
            "verify_tooltip":          "Check integrity and password without writing output",
            "verify_complete_title":   "Integrity Verified",
            "verify_complete_body":    "✓  File is intact and the password is correct.\n\nProfile    {prof}\nChunks     {chunks}\nFile size  {sz:,} bytes\n\nNo output file was written.",
            "int_ok_title":            "File structure valid",
            "int_warn_title":          "File may have issues",
            "int_err_title":           "File is corrupted or invalid",
            "int_sub_ok":              "Profile: {prof}  ·  {chunks} chunk(s)  ·  {mb:.1f} MB",
            "err_structural_title":    "File Corrupted or Invalid",
            "err_structural_body":     "⛔  The file cannot be opened.\n\n{msg}\n\nWhat to do:\n• Check the file was transferred without corruption\n• Verify it is a .lcrypt file\n• Try re-downloading from the source",
            "err_auth_title":          "Authentication Failed",
            "err_auth_body":           "🔑  Incorrect password, or the file has been modified.\n\nThe file structure is intact but the HMAC did not match.\n\nWhat to do:\n• Double-check the password (caps lock, keyboard layout)\n• If the file was transferred, check for corruption",
            "err_content_title":       "Content Corruption Detected",
            "err_content_body":        "⚠  The password is correct but the file content is damaged.\n\n{msg}\n\nWhat this means:\n• Outer HMAC passed — password is correct\n• An inner AES-GCM chunk tag failed — bytes were altered after encryption\n• Indicates storage-layer bit-rot or targeted tampering\n\nWhat to do:\n• Try a backup copy of the .lcrypt file\n• Check your storage medium for errors",
            "sha256_label":            "SHA-256",
            # ── shared ───────────────────────────────────────────────────────
            "browse":             "Browse",
            "mode_file":          "File",
            "mode_folder":        "Folder",
            "drop_file":          "Drop file here  ·  click to browse",
            "drop_folder":        "Drop folder here  ·  click to browse",
            "drop_lcrypt":        "Drop .lcrypt file  ·  click to browse",
            "drop_all_types":     "All file types supported",
            "save_enc_dialog":    "Save Encrypted File",
            "output_dialog":      "Output destination",
        },
        "tr": {
            # ── splash ───────────────────────────────────────────────────────
            "tagline":            "Askeri düzeyde dosya şifreleme",
            "select_lang":        "Devam etmek için dil seçin",
            "loading":            "Yükleniyor…",
            # ── main window tabs ─────────────────────────────────────────────
            "tab_encrypt":        "Şifrele",
            "tab_decrypt":        "Çöz",
            # ── encrypt page ─────────────────────────────────────────────────
            "enc_title":          "Şifrele",
            "enc_subtitle":       "Dosyalarınızı AES-256-GCM ile güvenle şifreleyin",
            "enc_source":         "KAYNAK",
            "enc_output_label":   "ÇIKTI  .lcrypt",
            "enc_strength":       "ŞİFRELEME GÜCÜ",
            "enc_password":       "PAROLA",
            "enc_password_ph":    "Güçlü bir parola oluşturun",
            "enc_confirm":        "ONAYLA",
            "enc_confirm_ph":     "Parolayı tekrarlayın",
            "enc_fill":           "Devam etmek için tüm alanları doldurun",
            "enc_btn":            "Şimdi Şifrele",
            "enc_btn_folder":     "Klasörü Şifrele",
            "enc_done":           "Tamamlandı ✓",
            "enc_err_status":     "Hata",
            "enc_select_src":     "Kaynak dosya veya klasör seçin",
            "enc_enter_pw":       "Bir parola girin",
            "enc_pw_short":       "Parola en az {n} karakter olmalıdır",
            "enc_pw_mismatch":    "Parolalar eşleşmiyor",
            "enc_complete_title": "Şifreleme Tamamlandı",
            "enc_complete_body":  "Başarıyla şifrelendi.\n\nTür        {t}\nOrijinal   {orig:,} bayt\nŞifreli    {enc:,} bayt\nProfil     {prof}\n\nKaydedildi:\n{dst}",
            "enc_error_title":    "Şifreleme Hatası",
            "enc_type_file":      "Dosya",
            "enc_type_folder":    "Klasör",
            # ── decrypt page ─────────────────────────────────────────────────
            "dec_title":          "Şifre Çöz",
            "dec_subtitle":       "Lephy Crypt arşivinden dosyalarınızı geri alın",
            "dec_enc_file":       "ŞİFRELİ DOSYA  .lcrypt",
            "dec_output":         "ÇIKTI KONUMU",
            "dec_password":       "PAROLA",
            "dec_password_ph":    "Parolanızı girin",
            "dec_note":           "Dosya türü otomatik algılanır.\nTek dosyalar ve klasör arşivleri desteklenir.",
            "dec_fill":           "Devam etmek için tüm alanları doldurun",
            "dec_btn":            "Şimdi Çöz",
            "dec_done":           "Tamamlandı ✓",
            "dec_err_status":     "Hata",
            "dec_complete_title": "Şifre Çözme Tamamlandı",
            "dec_complete_folder":"Başarıyla çözüldü.\n\nTür      Klasör arşivi\nDosya    {fc} dosya çıkarıldı\n\nÇıktı:\n{dst}",
            "dec_complete_file":  "Başarıyla çözüldü.\n\nTür     Tek dosya\nBoyut   {sz:,} bayt\n\nÇıktı:\n{dst}",
            "dec_error_title":    "Şifre Çözme Hatası",
            # ── integrity & verify (decrypt page) ────────────────────────────
            "verify_btn":              "Sadece Doğrula",
            "verify_tooltip":          "Çıktı dosyası oluşturmadan bütünlük ve parolayı kontrol et",
            "verify_complete_title":   "Bütünlük Doğrulandı",
            "verify_complete_body":    "✓  Dosya sağlam ve parola doğru.\n\nProfil     {prof}\nParça      {chunks}\nDosya boyutu  {sz:,} bayt\n\nHiçbir çıktı dosyası oluşturulmadı.",
            "int_ok_title":            "Dosya yapısı geçerli",
            "int_warn_title":          "Dosyada sorun olabilir",
            "int_err_title":           "Dosya bozuk veya geçersiz",
            "int_sub_ok":              "Profil: {prof}  ·  {chunks} parça  ·  {mb:.1f} MB",
            "err_structural_title":    "Dosya Bozuk veya Geçersiz",
            "err_structural_body":     "⛔  Dosya açılamıyor.\n\n{msg}\n\nNe yapabilirsiniz:\n• Dosyanın aktarım sırasında bozulmadığını kontrol edin\n• Gerçekten .lcrypt uzantılı olduğunu doğrulayın\n• Kaynaktan yeniden indirmeyi deneyin",
            "err_auth_title":          "Kimlik Doğrulama Başarısız",
            "err_auth_body":           "🔑  Yanlış parola veya dosya değiştirilmiş.\n\nDosya yapısı sağlam ancak HMAC eşleşmedi.\n\nNe yapabilirsiniz:\n• Parolayı kontrol edin (büyük harf kilidi, klavye dili)\n• Dosya aktarıldıysa bozulma olup olmadığını kontrol edin",
            "err_content_title":       "İçerik Bozulması Tespit Edildi",
            "err_content_body":        "⚠  Parola doğru ancak dosya içeriği zarar görmüş.\n\n{msg}\n\nBu ne anlama gelir:\n• Dış HMAC geçti — parola doğru\n• İç AES-GCM parça etiketi başarısız — şifrelemeden sonra baytlar değiştirilmiş\n• Depolama katmanı bit hatası veya hedefli müdahale\n\nNe yapabilirsiniz:\n• .lcrypt dosyasının yedeğini deneyin\n• Depolama ortamınızı hata açısından kontrol edin",
            "sha256_label":            "SHA-256",
            # ── shared ───────────────────────────────────────────────────────
            "browse":             "Gözat",
            "mode_file":          "Dosya",
            "mode_folder":        "Klasör",
            "drop_file":          "Dosyayı buraya bırakın  ·  tıklayarak seçin",
            "drop_folder":        "Klasörü buraya bırakın  ·  tıklayarak seçin",
            "drop_lcrypt":        ".lcrypt dosyasını bırakın  ·  tıklayarak seçin",
            "drop_all_types":     "Tüm dosya türleri desteklenir",
            "save_enc_dialog":    "Şifrelenmiş Dosyayı Kaydet",
            "output_dialog":      "Çıktı konumu",
        },
    }

    @classmethod
    def set(cls, lang: str):
        cls._lang = lang

    @classmethod
    def get(cls) -> str:
        return cls._lang

    @classmethod
    def t(cls, key: str) -> str:
        return cls._strings.get(cls._lang, cls._strings["en"]).get(key, key)


# ══════════════════════════════════════════════════════════════════════════════
#  SPLASH SCREEN
# ══════════════════════════════════════════════════════════════════════════════

class SplashScreen(QWidget):
    """
    Frameless splash screen shown for 3 seconds at startup.
    Displays logo, app name, tagline and EN/TR language selector.
    Emits `done` with selected language code after the delay.
    """
    done = pyqtSignal(str)   # emits language code "en" / "tr"

    _SPLASH_W = 520
    _SPLASH_H = 340
    _HOLD_MS  = 3000         # visible duration before main window opens

    # Colour palette (dark, matches brand blue accent)
    _BG_TOP   = QColor("#0d1021")
    _BG_BOT   = QColor("#131729")
    _ACCENT   = QColor("#4361ee")
    _ACCENT2  = QColor("#6478f5")
    _WHITE    = QColor("#ffffff")
    _MUTED    = QColor("#6b738f")
    _BORDER   = QColor(255, 255, 255, 18)

    def __init__(self, default_lang: str = "en"):
        super().__init__()
        self._selected_lang = default_lang
        self._anim          = None   # keep reference alive

        # ── window flags ──────────────────────────────────────────────────────
        self.setWindowFlags(
            Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setFixedSize(self._SPLASH_W, self._SPLASH_H)
        self._center_on_screen()

        # ── root layout ───────────────────────────────────────────────────────
        root = QVBoxLayout(self)
        root.setContentsMargins(48, 44, 48, 40)
        root.setSpacing(0)

        # ── logo + title row ──────────────────────────────────────────────────
        logo_row = QHBoxLayout(); logo_row.setSpacing(14)
        logo_row.setContentsMargins(0, 0, 0, 0)

        # Shield / lock icon drawn as a simple widget
        self._icon_lbl = QLabel()
        self._icon_lbl.setFixedSize(54, 54)
        self._icon_lbl.setStyleSheet("""
            background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
                stop:0 #4361ee, stop:1 #6478f5);
            border-radius: 14px;
            color: white;
            font-size: 26px;
        """)
        self._icon_lbl.setAlignment(Qt.AlignCenter)
        self._icon_lbl.setText("🔒")
        logo_row.addWidget(self._icon_lbl)

        title_col = QVBoxLayout(); title_col.setSpacing(2)
        title_col.setContentsMargins(0, 2, 0, 0)

        self._title_lbl = QLabel("Lephy Crypt")
        self._title_lbl.setStyleSheet(
            "color: #ffffff; font-size: 26px; font-weight: 800;"
            "letter-spacing: -0.5px; background: transparent;")
        title_col.addWidget(self._title_lbl)

        self._tagline_lbl = QLabel(LangManager.t("tagline"))
        self._tagline_lbl.setStyleSheet(
            "color: #6b738f; font-size: 12px; font-weight: 500;"
            "background: transparent;")
        title_col.addWidget(self._tagline_lbl)

        logo_row.addLayout(title_col)
        logo_row.addStretch()
        root.addLayout(logo_row)
        root.addSpacing(36)

        # ── divider ───────────────────────────────────────────────────────────
        div = QFrame(); div.setFixedHeight(1)
        div.setStyleSheet("background: rgba(255,255,255,0.07); border: none;")
        root.addWidget(div)
        root.addSpacing(32)

        # ── language selector label ───────────────────────────────────────────
        self._lang_hint = QLabel(LangManager.t("select_lang"))
        self._lang_hint.setStyleSheet(
            "color: #6b738f; font-size: 11px; font-weight: 600;"
            "letter-spacing: 0.4px; background: transparent;")
        self._lang_hint.setAlignment(Qt.AlignCenter)
        root.addWidget(self._lang_hint)
        root.addSpacing(14)

        # ── language buttons ──────────────────────────────────────────────────
        btn_row = QHBoxLayout(); btn_row.setSpacing(12)
        btn_row.setContentsMargins(0, 0, 0, 0)

        self._btn_en = self._make_lang_btn("🇬🇧  English", "en")
        self._btn_tr = self._make_lang_btn("🇹🇷  Türkçe",  "tr")
        btn_row.addStretch()
        btn_row.addWidget(self._btn_en)
        btn_row.addWidget(self._btn_tr)
        btn_row.addStretch()
        root.addLayout(btn_row)

        root.addStretch()

        # ── loading label + progress bar ──────────────────────────────────────
        self._loading_lbl = QLabel(LangManager.t("loading"))
        self._loading_lbl.setStyleSheet(
            "color: #6b738f; font-size: 11px; background: transparent;")
        self._loading_lbl.setAlignment(Qt.AlignCenter)
        root.addWidget(self._loading_lbl)
        root.addSpacing(10)

        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._bar.setFixedHeight(3)
        self._bar.setTextVisible(False)
        self._bar.setStyleSheet("""
            QProgressBar {
                background: rgba(255,255,255,0.08);
                border: none;
                border-radius: 2px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #4361ee, stop:1 #6478f5);
                border-radius: 2px;
            }
        """)
        root.addWidget(self._bar)

        # ── version badge ─────────────────────────────────────────────────────
        root.addSpacing(8)
        ver = QLabel(f"v{APP_VERSION}")
        ver.setStyleSheet(
            "color: rgba(107,115,143,0.55); font-size: 10px; background: transparent;")
        ver.setAlignment(Qt.AlignCenter)
        root.addWidget(ver)

        # ── opacity fade-in ───────────────────────────────────────────────────
        self._opacity_fx = QGraphicsOpacityEffect(self)
        self._opacity_fx.setOpacity(0.0)
        self.setGraphicsEffect(self._opacity_fx)

        # ── timer chain ───────────────────────────────────────────────────────
        # Fade in immediately
        QTimer.singleShot(0,   self._fade_in)
        # Start progress bar after a brief moment
        QTimer.singleShot(200, self._start_progress)

        self._select_lang(default_lang)   # pre-select language from argument

    # ── helpers ───────────────────────────────────────────────────────────────

    def _center_on_screen(self):
        from PyQt5.QtWidgets import QDesktopWidget
        geo = QDesktopWidget().screenGeometry()
        self.move(
            (geo.width()  - self._SPLASH_W) // 2,
            (geo.height() - self._SPLASH_H) // 2,
        )

    def _make_lang_btn(self, label: str, code: str) -> QPushButton:
        b = QPushButton(label)
        b.setFixedSize(148, 40)
        b.setCursor(Qt.PointingHandCursor)
        b.setProperty("lang_code", code)
        b.clicked.connect(lambda: self._select_lang(code))
        return b

    def _lang_btn_style(self, active: bool) -> str:
        if active:
            return (
                "QPushButton {"
                "  background: qlineargradient(x1:0,y1:0,x2:1,y2:1,"
                "    stop:0 #4361ee, stop:1 #6478f5);"
                "  color: #ffffff; border: none; border-radius: 10px;"
                "  font-size: 13px; font-weight: 700;"
                "}"
                "QPushButton:hover { background: #5470f0; }"
            )
        return (
            "QPushButton {"
            "  background: rgba(255,255,255,0.06);"
            "  color: #6b738f; border: 1.5px solid rgba(255,255,255,0.10);"
            "  border-radius: 10px; font-size: 13px; font-weight: 600;"
            "}"
            "QPushButton:hover {"
            "  background: rgba(255,255,255,0.10); color: #b0b7cc;"
            "}"
        )

    def _select_lang(self, code: str):
        self._selected_lang = code
        LangManager.set(code)
        self._btn_en.setStyleSheet(self._lang_btn_style(code == "en"))
        self._btn_tr.setStyleSheet(self._lang_btn_style(code == "tr"))
        # Update dynamic strings
        self._tagline_lbl.setText(LangManager.t("tagline"))
        self._lang_hint.setText(LangManager.t("select_lang"))
        self._loading_lbl.setText(LangManager.t("loading"))

    # ── animations ────────────────────────────────────────────────────────────

    def _fade_in(self):
        self._anim = QPropertyAnimation(self._opacity_fx, b"opacity")
        self._anim.setDuration(420)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)
        self._anim.start()

    def _start_progress(self):
        """Advances the progress bar over _HOLD_MS, then emits done."""
        self._progress_timer = QTimer(self)
        self._progress_timer.setInterval(30)   # ~33 fps
        self._elapsed = 0
        self._progress_timer.timeout.connect(self._tick_progress)
        self._progress_timer.start()

    def _tick_progress(self):
        self._elapsed += 30
        pct = int(min(self._elapsed / self._HOLD_MS * 100, 100))
        self._bar.setValue(pct)
        if self._elapsed >= self._HOLD_MS:
            self._progress_timer.stop()
            self._launch()

    def _launch(self):
        """Fade out then emit done."""
        self._anim = QPropertyAnimation(self._opacity_fx, b"opacity")
        self._anim.setDuration(280)
        self._anim.setStartValue(1.0)
        self._anim.setEndValue(0.0)
        self._anim.setEasingCurve(QEasingCurve.InCubic)
        self._anim.finished.connect(lambda: self.done.emit(self._selected_lang))
        self._anim.start()

    # ── painting ──────────────────────────────────────────────────────────────

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        # Rounded rect clip
        path = QPainterPath()
        path.addRoundedRect(QRectF(self.rect()), 18, 18)
        p.setClipPath(path)

        # Dark gradient background
        grad = QLinearGradient(0, 0, 0, self.height())
        grad.setColorAt(0.0, self._BG_TOP)
        grad.setColorAt(1.0, self._BG_BOT)
        p.fillPath(path, grad)

        # Subtle accent glow top-left
        glow = QLinearGradient(0, 0, self._SPLASH_W * 0.6, self._SPLASH_H * 0.5)
        glow.setColorAt(0.0, QColor(67, 97, 238, 28))
        glow.setColorAt(1.0, QColor(67, 97, 238, 0))
        p.fillPath(path, glow)

        # Border
        p.setPen(self._BORDER)
        p.drawRoundedRect(QRectF(0.5, 0.5, self.width()-1, self.height()-1), 18, 18)
        p.end()


# ══════════════════════════════════════════════════════════════════════════════
#  RUN
# ══════════════════════════════════════════════════════════════════════════════

def run(default_lang: str = "en"):
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    app = QApplication(sys.argv)
    app.setApplicationName("Lephy Crypt")
    app.setApplicationVersion(APP_VERSION)   # available via About dialog if added
    app.setStyleSheet(QSS)

    # ── Splash → MainWindow ────────────────────────────────────────────────────
    main_win = MainWindow()

    def _on_splash_done(lang: str):
        main_win.retranslate(lang)   # apply chosen language before showing
        splash.close()
        main_win.show()

    splash = SplashScreen(default_lang=default_lang)
    splash.done.connect(_on_splash_done)
    splash.show()

    sys.exit(app.exec_())