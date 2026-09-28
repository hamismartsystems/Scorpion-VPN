# -*- coding: utf-8 -*-
"""
Scorpion VPN — کلاینت ویندوز (تک‌فایل)
طراحی حرفه‌ای تاریک + پشتیبانی کانفیگ‌های استاندارد و اختصاصی scorpion://

اجرا:  pip install PyQt6 cryptography  +  xray.exe کنار همین فایل
آیکون: scorpion_icon.png کنار همین فایل (اختیاری)
"""
import os, sys, json, base64, hashlib, subprocess, tempfile, socket, time

# ───────────────────────── ۱) قالب اختصاصی scorpion:// ─────────────────────────
MAGIC = "scorpion://v1."
SECRET = b"HSS-SCORPION-VPN-2026-SECRET"

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False


def _key():
    return hashlib.sha256(SECRET).digest()


def is_scorpion(uri):
    return isinstance(uri, str) and uri.strip().startswith(MAGIC)


def encode_scorpion(plain):
    if not HAS_CRYPTO:
        raise RuntimeError("pip install cryptography")
    nonce = os.urandom(12)
    ct = AESGCM(_key()).encrypt(nonce, plain.strip().encode("utf-8"), None)
    return MAGIC + base64.urlsafe_b64encode(nonce + ct).decode()


def decode_scorpion(uri):
    uri = uri.strip()
    if not is_scorpion(uri):
        raise ValueError("این یک کانفیگ Scorpion نیست")
    raw = base64.urlsafe_b64decode(uri[len(MAGIC):])
    if len(raw) < 13:
        raise ValueError("قالب نامعتبر")
    return AESGCM(_key()).decrypt(raw[:12], raw[12:], None).decode("utf-8")


# ───────────────────────── ۲) تبدیل URI به کانفیگ xray ─────────────────────────
import urllib.parse as up


def _b64json(s):
    s = s.strip()
    return json.loads(base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8"))


def parse_uri(uri):
    uri = uri.strip()
    if "://" not in uri:
        raise ValueError("قالب ناشناخته")
    scheme, rest = uri.split("://", 1)
    scheme = scheme.lower()
    if scheme == "vless":
        frag = ""
        if "#" in rest:
            rest, frag = rest.split("#", 1)
        auth, _, hp = rest.partition("@")
        q = {}
        if "?" in hp:
            hp, qs = hp.split("?", 1)
            q = dict(up.parse_qsl(qs))
        host, _, port = hp.partition(":")
        return scheme, frag, {"uuid": auth, "host": host, "port": int(port or 443), "params": q}
    if scheme == "vmess":
        d = _b64json(rest)
        return scheme, str(d.get("ps", "")), {"uuid": d.get("id"), "host": d.get("add"),
                "port": int(d.get("port", 443)), "net": d.get("net", "tcp"), "tls": d.get("tls", ""),
                "sni": d.get("sni") or d.get("host", ""), "path": d.get("path", ""), "aid": int(d.get("aid", 0))}
    if scheme == "ss":
        frag = ""
        if "#" in rest:
            rest, frag = rest.split("#", 1)
        if "@" in rest:
            info, _, hp = rest.partition("@")
            mp = base64.b64decode(info + "=" * (-len(info) % 4)).decode()
            method, _, password = mp.partition(":")
            host, _, port = hp.partition(":")
        else:
            allb = base64.b64decode(rest + "=" * (-len(rest) % 4)).decode()
            method, _, tail = allb.partition(":")
            password, _, hp = tail.rpartition("@")
            host, _, port = hp.partition(":")
        return scheme, frag, {"method": method, "password": password, "host": host, "port": int(port or 8388)}
    if scheme == "trojan":
        frag = ""
        if "#" in rest:
            rest, frag = rest.split("#", 1)
        auth, _, hp = rest.partition("@")
        q = {}
        if "?" in hp:
            hp, qs = hp.split("?", 1)
            q = dict(up.parse_qsl(qs))
        host, _, port = hp.partition(":")
        return scheme, frag, {"password": auth, "host": host, "port": int(port or 443), "params": q}
    raise ValueError("پروتکل پشتیبانی نمی‌شود: " + scheme)


def _outbound(scheme, d):
    if scheme == "vless":
        q = d["params"]
        sec = q.get("security", "none")
        net = q.get("type", "tcp")
        user = {"id": d["uuid"], "encryption": "none"}
        if q.get("flow"):
            user["flow"] = q["flow"]
        ob = {"protocol": "vless", "settings": {"vnext": [{"address": d["host"], "port": d["port"], "users": [user]}]}}
        st = {"network": net}
        if net == "ws":
            st["wsSettings"] = {"path": q.get("path", "/"), "headers": {"Host": q.get("host", d["host"])}}
        if sec == "reality":
            st["security"] = "reality"
            st["realitySettings"] = {"serverName": q.get("sni", ""), "fingerprint": q.get("fp", "chrome"),
                                     "publicKey": q.get("pbk", ""), "shortId": q.get("sid", ""), "spiderX": ""}
        elif sec == "tls":
            st["security"] = "tls"
            st["tlsSettings"] = {"serverName": q.get("sni", d["host"]), "allowInsecure": False}
        ob["streamSettings"] = st
        return ob
    if scheme == "vmess":
        ob = {"protocol": "vmess", "settings": {"vnext": [{"address": d["host"], "port": d["port"],
              "users": [{"id": d["uuid"], "alterId": d.get("aid", 0)}]}]}}
        st = {"network": d.get("net", "tcp")}
        if d.get("net") == "ws":
            st["wsSettings"] = {"path": d.get("path", "/"), "headers": {"Host": d.get("sni") or d["host"]}}
        if d.get("tls") == "tls":
            st["security"] = "tls"
            st["tlsSettings"] = {"serverName": d.get("sni") or d["host"], "allowInsecure": False}
        ob["streamSettings"] = st
        return ob
    if scheme == "ss":
        return {"protocol": "shadowsocks", "settings": {"servers": [{"address": d["host"], "port": d["port"],
                "method": d["method"], "password": d["password"]}]}}
    if scheme == "trojan":
        q = d["params"]
        return {"protocol": "trojan", "settings": {"servers": [{"address": d["host"], "port": d["port"],
                "password": d["password"]}]},
                "streamSettings": {"network": "tcp", "security": "tls",
                "tlsSettings": {"serverName": q.get("sni", d["host"]), "allowInsecure": False}}}
    raise ValueError("پروتکل پشتیبانی نمی‌شود")


def build_client_config(uri, socks_port=10808, http_port=10809, opts=None):
    opts = opts or {}
    scheme, _frag, d = parse_uri(uri)
    listen = "0.0.0.0" if opts.get("lan") else "127.0.0.1"
    ob = _outbound(scheme, d)
    if opts.get("mux"):
        ob["mux"] = {"enabled": True, "concurrency": 8}
    st = ob.get("streamSettings") or {}
    sec = st.get("security")
    if opts.get("frag") and sec in ("tls", "reality"):
        st[sec + "Settings"]["fragment"] = {"packets": "tlshello", "length": "100-200", "interval": "10-20"}
    cfg = {"log": {"loglevel": "warning"},
           "inbounds": [{"port": socks_port, "protocol": "socks", "listen": listen,
                         "settings": {"auth": "noauth", "udp": True}},
                        {"port": http_port, "protocol": "http", "listen": listen}],
           "outbounds": [ob]}
    ip = opts.get("ip_type")
    if ip in ("4", "6"):
        cfg["dns"] = {"queryStrategy": "UseIPv4" if ip == "4" else "UseIPv6"}
    return cfg


# ───────────────────────── ۳) هسته ─────────────────────────
APP_DIR = os.path.dirname(os.path.abspath(__file__))
XRAY_PATH = os.path.join(APP_DIR, "xray.exe") if os.name == "nt" else "xray"
ICON_PATH = os.path.join(APP_DIR, "scorpion_icon.png")
ICO_PATH = os.path.join(APP_DIR, "scorpion.ico")
CONFIGS_FILE = os.path.join(APP_DIR, "scorpion_configs.json")
SETTINGS_FILE = os.path.join(APP_DIR, "scorpion_settings.json")


def resolve_config(uri, socks_port=10808, http_port=10809, opts=None):
    uri = uri.strip()
    plain = decode_scorpion(uri) if is_scorpion(uri) else uri
    return build_client_config(plain, socks_port, http_port, opts)


def describe(uri):
    """(نام، خط توضیح پروتکل، آیا scorpion است)"""
    uri = uri.strip()
    sc = is_scorpion(uri)
    try:
        plain = decode_scorpion(uri) if sc else uri
        scheme, frag, d = parse_uri(plain)
        name = up.unquote(frag) if frag else d.get("host", "server")
        net = d.get("params", {}).get("type") or d.get("net") or "tcp"
        sec = d.get("params", {}).get("security") or d.get("tls") or ""
        proto = {"vless": "VLESS", "vmess": "VMESS", "ss": "SHADOWSOCKS", "trojan": "TROJAN"}.get(scheme, scheme.upper())
        sub = f"{proto} / {str(net).upper()}" + (f" / {str(sec).upper()}" if sec and sec != "none" else "")
        return name, sub, sc
    except Exception:
        return ("کانفیگ اسکورپیون" if sc else uri[:20]), "نامعتبر", sc


def load_settings():
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def set_system_proxy(on, server="127.0.0.1:10809"):
    if os.name != "nt":
        return
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                             0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if on else 0)
        if on:
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
        winreg.CloseKey(key)
    except OSError:
        pass


# ───────────────────────── ۴) رابط کاربری ─────────────────────────
import math
import urllib.request as ureq
from PyQt6.QtGui import QFont, QIcon, QPainter, QColor, QPen, QPainterPath, QPalette
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize, QRectF, QPointF
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QListWidget, QListWidgetItem,
                             QTextEdit, QMessageBox, QStackedWidget, QSpinBox, QCheckBox,
                             QDialog, QMenu, QScrollArea, QComboBox)

ACCENT = "#00e07a"
BG = "#0f1115"
PANEL = "#161b23"
CARD = "#171c24"
CARD_HOVER = "#1c2330"
BORDER = "#262c37"
TEXT = "#e6e9ef"
SUB = "#8f98a8"

STYLE = """
QMainWindow{background:%(bg)s;}
QWidget{background:%(bg)s;color:%(tx)s;font-family:'Segoe UI',Tahoma;}
QLabel{background:transparent;}
QLineEdit#search{background:%(card)s;border:1px solid %(bd)s;border-radius:10px;padding:10px 16px;selection-background-color:%(ac)s;}
QLineEdit#search:focus{border:1px solid %(ac)s;}
QListWidget{background:transparent;border:none;outline:none;}
QListWidget::item{background:transparent;border:none;padding:0px;margin:0px;}
QListWidget::item:selected{background:transparent;}
QWidget#card{background:%(card)s;border:1px solid #232a36;border-radius:12px;}
QWidget#card:hover{background:%(ch)s;}
QWidget#card[sel="1"]{border:1px solid %(ac)s;background:#14231d;}
QWidget#iconBadge{background:#202836;border-radius:10px;}
QWidget#panel{background:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #161b23,stop:1 #11151c);border:1px solid #232a36;border-radius:16px;}
QWidget#side{background:#0b0d10;}
QLabel#badge{color:%(ac)s;border:1px solid %(ac)s;border-radius:4px;padding:2px 8px;font-size:10px;font-weight:bold;letter-spacing:1px;}
QLabel#sub{color:%(sb)s;font-size:11px;letter-spacing:1px;}
QLabel#cname{font-size:13px;font-weight:600;}
QLabel#name{font-size:15px;font-weight:600;}
QLabel#ping{color:%(sb)s;font-size:13px;font-weight:600;}
QLabel#pinfo{color:#5f6a7c;font-size:11px;}
QLabel#rtitle{font-size:13px;}
QLabel#sec{color:%(sb)s;font-size:12px;font-weight:600;}
QWidget#row{border-bottom:1px solid #1a2029;}
QComboBox{background:%(card)s;border:1px solid %(bd)s;border-radius:8px;padding:6px 12px;min-width:90px;}
QComboBox::drop-down{border:none;width:20px;}
QComboBox QAbstractItemView{background:%(card)s;border:1px solid %(bd)s;selection-background-color:#1a2430;color:%(tx)s;}
QCheckBox#livecb{color:%(sb)s;font-size:12px;}
QLabel#title{font-size:19px;font-weight:600;}
QLabel#chipOff{color:%(sb)s;background:%(card)s;border:1px solid %(bd)s;border-radius:11px;padding:5px 14px;font-size:12px;}
QLabel#chipOn{color:#06281a;background:%(ac)s;border-radius:11px;padding:5px 14px;font-size:12px;font-weight:bold;}
QPushButton#nav{background:transparent;border:none;border-radius:11px;}
QPushButton#nav:hover{background:%(card)s;}
QPushButton#nav:checked{background:#1a2430;}
QPushButton#flat{background:%(card)s;border:1px solid %(bd)s;border-radius:10px;padding:9px 18px;color:%(tx)s;}
QPushButton#flat:hover{background:%(ch)s;border:1px solid %(ac)s;}
QPushButton#danger{background:transparent;border:1px solid #5a2a2a;border-radius:10px;padding:9px 18px;color:#ff6b6b;}
QPushButton#danger:hover{background:#2a1515;}
QTextEdit#log{background:#0b0d10;border:1px solid #1c222b;border-radius:10px;color:#7ee2a8;font-family:Consolas,monospace;font-size:11px;}
QCheckBox{spacing:8px;background:transparent;}
QCheckBox::indicator{width:16px;height:16px;border-radius:5px;border:1px solid #2a3140;background:%(card)s;}
QCheckBox::indicator:checked{background:%(ac)s;border:1px solid %(ac)s;}
QSpinBox{background:%(card)s;border:1px solid %(bd)s;border-radius:8px;padding:6px;}
QScrollBar:vertical{background:transparent;width:8px;}
QScrollBar::handle:vertical{background:#2c3442;border-radius:4px;}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0px;}
QMenu{background:%(card)s;border:1px solid %(bd)s;border-radius:8px;padding:6px;}
QMenu::item{padding:6px 22px;border-radius:5px;}
QMenu::item:selected{background:#1a2430;color:%(ac)s;}
""" % {"bg": BG, "tx": TEXT, "sb": SUB, "ac": ACCENT, "bd": BORDER, "card": CARD, "ch": CARD_HOVER}


def _draw_icon(p, kind, rect, color, lw=2.0):
    p.save()
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor(color), lw)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    x, y, w, h = rect.x(), rect.y(), rect.width(), rect.height()
    cx, cy = x + w / 2, y + h / 2
    R = min(w, h) / 2
    if kind == "globe":
        p.drawEllipse(QRectF(x, y, w, h))
        p.drawLine(QPointF(x, cy), QPointF(x + w, cy))
        p.drawEllipse(QRectF(cx - w * 0.22, y, w * 0.44, h))
    elif kind == "gear":
        p.drawEllipse(QRectF(cx - R * 0.6, cy - R * 0.6, R * 1.2, R * 1.2))
        p.drawEllipse(QRectF(cx - R * 0.22, cy - R * 0.22, R * 0.44, R * 0.44))
        for i in range(8):
            a = math.radians(i * 45)
            p.drawLine(QPointF(cx + math.cos(a) * R * 0.6, cy + math.sin(a) * R * 0.6),
                       QPointF(cx + math.cos(a) * R * 0.95, cy + math.sin(a) * R * 0.95))
    elif kind == "info":
        p.drawEllipse(QRectF(x, y, w, h))
        p.drawLine(QPointF(cx, cy - R * 0.05), QPointF(cx, cy + R * 0.5))
        p.drawLine(QPointF(cx, cy - R * 0.45), QPointF(cx, cy - R * 0.42))
    elif kind == "shield":
        path = QPainterPath()
        path.moveTo(cx, y + h * 0.02)
        path.lineTo(x + w * 0.94, y + h * 0.2)
        path.lineTo(x + w * 0.94, y + h * 0.52)
        path.lineTo(cx, y + h * 0.98)
        path.lineTo(x + w * 0.06, y + h * 0.52)
        path.lineTo(x + w * 0.06, y + h * 0.2)
        path.closeSubpath()
        p.drawPath(path)
    elif kind == "plus":
        p.drawLine(QPointF(cx - R * 0.6, cy), QPointF(cx + R * 0.6, cy))
        p.drawLine(QPointF(cx, cy - R * 0.6), QPointF(cx, cy + R * 0.6))
    elif kind == "search":
        p.drawEllipse(QRectF(x + w * 0.08, y + h * 0.08, w * 0.6, h * 0.6))
        p.drawLine(QPointF(x + w * 0.6, y + h * 0.6), QPointF(x + w * 0.92, y + h * 0.92))
    p.restore()


class IconWidget(QWidget):
    def __init__(self, kind, color, size, lw=2.0):
        super().__init__()
        self.kind, self.color, self.lw = kind, color, lw
        self.setFixedSize(size, size)
        self.setStyleSheet("background:transparent;")

    def paintEvent(self, e):
        p = QPainter(self)
        _draw_icon(p, self.kind, QRectF(0, 0, self.width(), self.height()), self.color, self.lw)


class NavBtn(QPushButton):
    def __init__(self, kind, tip, checkable=True):
        super().__init__()
        self.setObjectName("nav")
        self.kind = kind
        self.setToolTip(tip)
        self.setFixedHeight(46)
        self.setCheckable(checkable)
        self._hover = False

    def enterEvent(self, e):
        self._hover = True
        self.update()

    def leaveEvent(self, e):
        self._hover = False
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        col = ACCENT if self.isChecked() else (TEXT if self._hover else SUB)
        side = min(self.width(), self.height()) - 24
        r = QRectF((self.width() - side) / 2, (self.height() - side) / 2, side, side)
        _draw_icon(p, self.kind, r, col, 2.0)


class PowerButton(QWidget):
    clicked = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.connected = False
        self._hover = False
        self.setFixedSize(190, 190)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet("background:transparent;")

    def enterEvent(self, e):
        self._hover = True
        self.update()

    def leaveEvent(self, e):
        self._hover = False
        self.update()

    def mouseReleaseEvent(self, e):
        self.clicked.emit()

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2
        if self.connected:
            g = QColor(ACCENT)
            g.setAlpha(40 if self._hover else 26)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(g)
            p.drawEllipse(int(cx - 92), int(cy - 92), 184, 184)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#141a22") if not self.connected else QColor("#0d2b1e"))
        p.drawEllipse(int(cx - 78), int(cy - 78), 156, 156)
        ring = QColor(ACCENT) if self.connected else QColor("#2b3442")
        p.setPen(QPen(ring, 2.5))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(int(cx - 78), int(cy - 78), 156, 156)
        pen = QPen(QColor(ACCENT) if self.connected else QColor(TEXT), 5,
                   Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        r = 30
        p.drawArc(QRectF(cx - r, cy - r + 4, 2 * r, 2 * r), 120 * 16, 300 * 16)
        p.drawLine(int(cx), int(cy - r - 8), int(cx), int(cy - 6))


class ServerCard(QWidget):
    def __init__(self, uri, selected):
        super().__init__()
        self.uri = uri
        self.selected = selected
        self.setObjectName("card")
        h = QHBoxLayout(self)
        h.setContentsMargins(14, 12, 14, 12)
        h.setSpacing(12)
        name, sub, sc = describe(uri)

        holder = QWidget()
        holder.setObjectName("iconBadge")
        holder.setFixedSize(40, 40)
        hl = QVBoxLayout(holder)
        hl.setContentsMargins(0, 0, 0, 0)
        hl.addWidget(IconWidget("shield" if sc else "globe", ACCENT if sc else "#7f8ea3", 20),
                     0, Qt.AlignmentFlag.AlignCenter)
        h.addWidget(holder)

        col = QVBoxLayout()
        col.setSpacing(3)
        nm = QLabel(name)
        nm.setObjectName("cname")
        sb = QLabel(sub)
        sb.setObjectName("sub")
        col.addWidget(nm)
        col.addWidget(sb)
        h.addLayout(col, 1)

        if sc:
            b = QLabel("SCORPION")
            b.setObjectName("badge")
            h.addWidget(b)

    def paintEvent(self, e):
        super().paintEvent(e)
        if self.selected:
            p = QPainter(self)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            p.setPen(QPen(QColor(ACCENT), 1.5))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRoundedRect(QRectF(0.75, 0.75, self.width() - 1.5, self.height() - 1.5), 12, 12)


class AddDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("افزودن کانفیگ / ساب‌کریپشن")
        self.setFixedSize(540, 360)
        v = QVBoxLayout(self)
        t = QLabel("هر خط یک کانفیگ (vless/vmess/ss/trojan/scorpion://)\nلینک http/https به‌عنوان ساب‌کریپشن دریافت و همه‌ی کانفیگ‌های آن اضافه می‌شود.")
        t.setWordWrap(True)
        t.setStyleSheet("color:%s;background:transparent;" % SUB)
        self.txt = QTextEdit()
        self.txt.setStyleSheet("background:%s;border:1px solid %s;border-radius:10px;padding:8px;font-family:Consolas,monospace;" % (CARD, BORDER))
        row = QHBoxLayout()
        ok = QPushButton("افزودن")
        ok.setObjectName("flat")
        cancel = QPushButton("انصراف")
        cancel.setObjectName("danger")
        row.addStretch()
        row.addWidget(ok)
        row.addWidget(cancel)
        v.addWidget(t)
        v.addWidget(self.txt, 1)
        v.addLayout(row)
        ok.clicked.connect(self.accept)
        cancel.clicked.connect(self.reject)

    def text(self):
        return self.txt.toPlainText()


class PingWorker(QThread):
    done = pyqtSignal(int)

    def __init__(self, host, port):
        super().__init__()
        self.host, self.port = host, port

    def run(self):
        t = time.time()
        try:
            if not self.host or not str(self.host).strip():
                raise OSError("no host")
            s = socket.create_connection((str(self.host), int(self.port)), timeout=6)
            s.close()
            self.done.emit(int((time.time() - t) * 1000))
        except Exception:
            self.done.emit(-1)


class Switch(QPushButton):
    def __init__(self, checked=False):
        super().__init__()
        self.setCheckable(True)
        self.setChecked(checked)
        self.setFixedSize(46, 24)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet("background:transparent;border:none;")

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        on = self.isChecked()
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(ACCENT) if on else QColor("#2a3140"))
        p.drawRoundedRect(QRectF(0, 2, 46, 20), 10, 10)
        p.setBrush(QColor("#f5f7fa"))
        p.drawEllipse(QRectF(27 if on else 3, 4, 16, 16))


class Row(QWidget):
    def __init__(self, title, sub=None, danger=False, ctrl=None):
        super().__init__()
        self.setObjectName("row")
        self._h = QHBoxLayout(self)
        self._h.setContentsMargins(18, 10, 18, 10)
        self._h.setSpacing(12)
        col = QVBoxLayout()
        col.setSpacing(2)
        t = QLabel(title)
        t.setObjectName("rtitle")
        if danger:
            pal = t.palette()
            pal.setColor(QPalette.ColorRole.WindowText, QColor("#ff6b6b"))
            t.setPalette(pal)
        col.addWidget(t)
        if sub:
            s = QLabel(sub)
            s.setObjectName("pinfo")
            col.addWidget(s)
        self._h.addLayout(col, 1)
        if ctrl is not None:
            self._h.addWidget(ctrl)

    def add(self, w):
        self._h.addWidget(w)


class PortsDialog(QDialog):
    def __init__(self, socks, http, parent=None):
        super().__init__(parent)
        self.setWindowTitle("پورت‌های پروکسی محلی")
        self.setFixedSize(330, 170)
        v = QVBoxLayout(self)
        v.setSpacing(12)
        r1 = QHBoxLayout()
        r1.addWidget(QLabel("SOCKS:"))
        self.sp_socks = QSpinBox()
        self.sp_socks.setRange(1024, 65535)
        self.sp_socks.setValue(socks)
        r1.addWidget(self.sp_socks)
        r1.addSpacing(16)
        r1.addWidget(QLabel("HTTP:"))
        self.sp_http = QSpinBox()
        self.sp_http.setRange(1024, 65535)
        self.sp_http.setValue(http)
        r1.addWidget(self.sp_http)
        r1.addStretch()
        save = QPushButton("ذخیره")
        save.setObjectName("flat")
        save.clicked.connect(self.accept)
        v.addLayout(r1)
        v.addStretch()
        v.addWidget(save, 0, Qt.AlignmentFlag.AlignLeft)


class SubWorker(QThread):
    done = pyqtSignal(list, int)

    def __init__(self, urls):
        super().__init__()
        self.urls = urls

    def run(self):
        out, errs = [], 0
        for u in self.urls:
            try:
                req = ureq.Request(u, headers={"User-Agent": "ScorpionVPN/1.0"})
                with ureq.urlopen(req, timeout=20) as r:
                    data = r.read()
                try:
                    cand = data.decode("utf-8")
                except UnicodeDecodeError:
                    cand = ""
                cand = cand.strip()
                if "://" not in cand:
                    pad = cand + "=" * (-len(cand) % 4)
                    try:
                        dec = base64.b64decode(pad).decode("utf-8", "ignore")
                        if "://" in dec:
                            cand = dec
                    except Exception:
                        pass
                lines = [l.strip() for l in cand.splitlines() if "://" in l.strip()]
                if lines:
                    out += lines
                else:
                    errs += 1
            except OSError:
                errs += 1
        self.done.emit(out, errs)


class ScorpionVPN(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Scorpion VPN  1.0")
        self.resize(1040, 680)
        self.setMinimumSize(880, 580)
        if os.path.exists(ICON_PATH):
            self.setWindowIcon(QIcon(ICON_PATH))
        self.proc = None
        self.configs = []
        self.settings = load_settings()
        self.socks_port = int(self.settings.get("socks_port", 10808))
        self.http_port = int(self.settings.get("http_port", 10809))

        root = QWidget()
        self.setCentralWidget(root)
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ── سایدبار ──
        side = QWidget()
        side.setObjectName("side")
        side.setFixedWidth(62)
        sv = QVBoxLayout(side)
        sv.setContentsMargins(9, 14, 9, 14)
        sv.setSpacing(8)

        logo_holder = QWidget()
        logo_holder.setFixedHeight(46)
        lh = QHBoxLayout(logo_holder)
        lh.setContentsMargins(0, 0, 0, 0)
        lh.addWidget(IconWidget("shield", ACCENT, 26, 2.2), 0, Qt.AlignmentFlag.AlignCenter)
        sv.addWidget(logo_holder)
        sv.addSpacing(12)

        self.nav_servers = NavBtn("globe", "سرورها")
        self.nav_servers.setChecked(True)
        self.nav_settings = NavBtn("gear", "تنظیمات")
        self.nav_about = NavBtn("info", "درباره", checkable=False)
        for b in (self.nav_servers, self.nav_settings, self.nav_about):
            sv.addWidget(b)
        sv.addStretch()
        outer.addWidget(side)

        # ── محتوای اصلی ──
        main = QWidget()
        mv = QVBoxLayout(main)
        mv.setContentsMargins(22, 18, 22, 18)
        mv.setSpacing(14)

        head = QHBoxLayout()
        self.page_title = QLabel("سرورها")
        self.page_title.setObjectName("title")
        self.chip = QLabel("قطع")
        self.chip.setObjectName("chipOff")
        self.chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
        head.addWidget(self.page_title)
        head.addStretch()
        head.addWidget(self.chip)
        mv.addLayout(head)

        self.pages = QStackedWidget()
        mv.addWidget(self.pages, 1)
        outer.addWidget(main, 1)

        self.pages.addWidget(self._build_servers_page())
        self.pages.addWidget(self._build_settings_page())

        self.nav_servers.clicked.connect(lambda: self._goto(0, "سرورها"))
        self.nav_settings.clicked.connect(lambda: self._goto(1, "تنظیمات"))
        self.nav_about.clicked.connect(self._about)

        self.load_configs()
        self.refresh_list()

    def _goto(self, idx, title):
        self.pages.setCurrentIndex(idx)
        self.page_title.setText(title)
        self.nav_servers.setChecked(idx == 0)
        self.nav_settings.setChecked(idx == 1)

    # ── صفحه سرورها ──
    def _build_servers_page(self):
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(18)

        left = QVBoxLayout()
        left.setSpacing(10)
        top = QHBoxLayout()
        top.setSpacing(10)
        self.search = QLineEdit()
        self.search.setObjectName("search")
        self.search.setPlaceholderText("جست‌وجوی سرور...")
        self.search.textChanged.connect(self.refresh_list)
        add = QPushButton("افزودن")
        add.setObjectName("flat")
        add.clicked.connect(self.open_add)
        top.addWidget(self.search, 1)
        top.addWidget(add)
        left.addLayout(top)

        self.lst = QListWidget()
        self.lst.setSpacing(8)
        self.lst.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.lst.customContextMenuRequested.connect(self._ctx_menu)
        self.lst.itemSelectionChanged.connect(self._on_select)
        left.addWidget(self.lst, 1)
        h.addLayout(left, 13)

        # پنل اتصال
        right = QWidget()
        right.setObjectName("panel")
        rv = QVBoxLayout(right)
        rv.setContentsMargins(20, 24, 20, 16)
        rv.setSpacing(8)

        self.power = PowerButton()
        self.power.clicked.connect(self.toggle)
        rv.addWidget(self.power, 0, Qt.AlignmentFlag.AlignHCenter)
        rv.addSpacing(6)

        self.cur_name = QLabel("سروری انتخاب نشده")
        self.cur_name.setObjectName("name")
        self.cur_name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.cur_name.setFixedHeight(26)
        rv.addWidget(self.cur_name)
        self.cur_sub = QLabel("")
        self.cur_sub.setObjectName("sub")
        self.cur_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.cur_sub.setFixedHeight(20)
        rv.addWidget(self.cur_sub)
        rv.addSpacing(8)

        prow = QHBoxLayout()
        prow.setSpacing(10)
        prow.addStretch()
        self.ping_btn = QPushButton("تست پینگ")
        self.ping_btn.setObjectName("flat")
        self.ping_btn.clicked.connect(self.do_ping)
        self.ping_lbl = QLabel("")
        self.ping_lbl.setObjectName("ping")
        self.ping_lbl.setFixedSize(86, 30)
        self.ping_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        prow.addWidget(self.ping_btn)
        prow.addWidget(self.ping_lbl)
        prow.addStretch()
        rv.addLayout(prow)

        xrow = QHBoxLayout()
        xrow.setSpacing(10)
        self.cb_live = QCheckBox("پروکسی سیستم")
        self.cb_live.setObjectName("livecb")
        self.cb_live.setChecked(bool(self.settings.get("sys_proxy", True)))
        self.cb_live.stateChanged.connect(self._proxy_toggle)
        self.proxy_info = QLabel("")
        self.proxy_info.setObjectName("pinfo")
        xrow.addWidget(self.cb_live)
        xrow.addStretch()
        xrow.addWidget(self.proxy_info)
        rv.addLayout(xrow)
        rv.addStretch(1)

        self.log = QTextEdit()
        self.log.setObjectName("log")
        self.log.setReadOnly(True)
        self.log.setFixedHeight(92)
        rv.addWidget(self.log)
        h.addWidget(right, 10)
        return w

    # ── صفحه تنظیمات ──
    def _build_settings_page(self):
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(4, 4, 4, 4)
        outer.setSpacing(0)

        scr = QScrollArea()
        scr.setWidgetResizable(True)
        content = QWidget()
        cv = QVBoxLayout(content)
        cv.setContentsMargins(2, 2, 2, 2)
        cv.setSpacing(14)

        # ── تونل ──
        cv.addWidget(self._sec("تونل"))
        tun = QWidget()
        tun.setObjectName("panel")
        tv = QVBoxLayout(tun)
        tv.setContentsMargins(0, 6, 0, 6)
        tv.setSpacing(0)

        self.sw_frag = Switch(bool(self.settings.get("frag", False)))
        tv.addWidget(Row("Fragmentation", "می‌تواند به دور زدن فیلترینگ کمک کند", ctrl=self.sw_frag))

        self.sw_mux = Switch(bool(self.settings.get("mux", False)))
        tv.addWidget(Row("Mux", "چند کانفیگ روی یک اتصال", ctrl=self.sw_mux))

        self.cb_ip = QComboBox()
        self.cb_ip.addItems(["IPv4", "IPv6"])
        self.cb_ip.setCurrentIndex(0 if str(self.settings.get("ip_type", "4")) == "4" else 1)
        tv.addWidget(Row("نوع IP ترجیحی", None, ctrl=self.cb_ip))

        self.sw_lan = Switch(bool(self.settings.get("lan", False)))
        tv.addWidget(Row("اجازه اتصال از LAN", "شنود پروکسی روی 0.0.0.0", ctrl=self.sw_lan))

        self.ports_lbl = QLabel("SOCKS %d  /  HTTP %d" % (self.socks_port, self.http_port))
        self.ports_lbl.setObjectName("pinfo")
        ports_btn = QPushButton("تغییر")
        ports_btn.setObjectName("flat")
        ports_btn.clicked.connect(self.open_ports)
        r = Row("پورت‌های پروکسی محلی", None)
        r.add(self.ports_lbl)
        r.add(ports_btn)
        tv.addWidget(r)
        cv.addWidget(tun)

        # ── سایر ──
        cv.addWidget(self._sec("سایر"))
        oth = QWidget()
        oth.setObjectName("panel")
        ov = QVBoxLayout(oth)
        ov.setContentsMargins(0, 6, 0, 6)
        ov.setSpacing(0)
        clear_btn = QPushButton("پاک‌کردن")
        clear_btn.setObjectName("flat")
        clear_btn.clicked.connect(self.log.clear)
        ov.addWidget(Row("لاگ‌ها", "رویدادهای اتصال در صفحه اصلی", ctrl=clear_btn))
        reset_btn = QPushButton("بازنشانی")
        reset_btn.setObjectName("danger")
        reset_btn.clicked.connect(self.reset_all)
        ov.addWidget(Row("بازنشانی", "حذف همه کانفیگ‌ها و تنظیمات", danger=True, ctrl=reset_btn))
        cv.addWidget(oth)

        # ── درباره ──
        cv.addWidget(self._sec("درباره"))
        ab = QWidget()
        ab.setObjectName("panel")
        av = QVBoxLayout(ab)
        av.setContentsMargins(0, 6, 0, 6)
        av.setSpacing(0)
        about_btn = QPushButton("مشاهده")
        about_btn.setObjectName("flat")
        about_btn.clicked.connect(self._about)
        av.addWidget(Row("Scorpion VPN — نسخه 1.0", "Hami Smart Systems", ctrl=about_btn))
        cv.addWidget(ab)

        cv.addStretch(1)
        scr.setWidget(content)
        outer.addWidget(scr)

        # اتصال سیگنال‌ها بعد از آماده‌شدن همه‌ی اجزا
        self.sw_frag.toggled.connect(self._save_opts)
        self.sw_mux.toggled.connect(self._save_opts)
        self.sw_lan.toggled.connect(self._save_opts)
        self.cb_ip.currentIndexChanged.connect(self._save_opts)
        return w

    def _sec(self, t):
        l = QLabel(t)
        l.setObjectName("sec")
        return l

    def _save_opts(self, *_):
        self.settings.update({"frag": self.sw_frag.isChecked(),
                              "mux": self.sw_mux.isChecked(),
                              "ip_type": "4" if self.cb_ip.currentIndex() == 0 else "6",
                              "lan": self.sw_lan.isChecked(),
                              "sys_proxy": self.cb_live.isChecked(),
                              "socks_port": self.socks_port,
                              "http_port": self.http_port})
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.settings, f)
        except OSError:
            pass

    def open_ports(self):
        d = PortsDialog(self.socks_port, self.http_port, self)
        if d.exec() == QDialog.DialogCode.Accepted:
            self.socks_port = d.sp_socks.value()
            self.http_port = d.sp_http.value()
            self.ports_lbl.setText("SOCKS %d  /  HTTP %d" % (self.socks_port, self.http_port))
            self._save_opts()
            self._log("پورت‌های پروکسی تغییر کرد؛ از اتصال بعدی اعمال می‌شود.")

    def reset_all(self):
        if QMessageBox.question(self, "بازنشانی", "همه‌ی کانفیگ‌ها و تنظیمات حذف می‌شوند. ادامه می‌دهید؟",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        self.configs = []
        self.save_configs()
        self.settings = {}
        try:
            os.remove(SETTINGS_FILE)
        except OSError:
            pass
        self.refresh_list()
        self._log("بازنشانی کامل شد.")

    def _proxy_toggle(self, state):
        self.settings["sys_proxy"] = bool(state)
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.settings, f)
        except OSError:
            pass
        if self.proc:
            set_system_proxy(bool(state), "127.0.0.1:%d" % self.http_port)

    # ── مدیریت کانفیگ‌ها ──
    def load_configs(self):
        try:
            with open(CONFIGS_FILE, encoding="utf-8") as f:
                self.configs = json.load(f)
        except (OSError, ValueError):
            self.configs = []

    def save_configs(self):
        with open(CONFIGS_FILE, "w", encoding="utf-8") as f:
            json.dump(self.configs, f, ensure_ascii=False)

    def refresh_list(self):
        q = self.search.text().strip().lower()
        self.lst.clear()
        sel = self._selected_uri()
        for uri in self.configs:
            name, sub, sc = describe(uri)
            if q and q not in name.lower() and q not in sub.lower() and q not in uri.lower():
                continue
            item = QListWidgetItem()
            card = ServerCard(uri, uri == sel)
            item.setSizeHint(QSize(0, 66))
            item.setData(Qt.ItemDataRole.UserRole, uri)
            self.lst.addItem(item)
            self.lst.setItemWidget(item, card)

    def _selected_uri(self):
        it = self.lst.currentItem()
        return it.data(Qt.ItemDataRole.UserRole) if it else None

    def _on_select(self):
        uri = self._selected_uri()
        if uri:
            name, sub, _sc = describe(uri)
            self.cur_name.setText(name)
            self.cur_sub.setText(sub)
        for i in range(self.lst.count()):
            it = self.lst.item(i)
            card = self.lst.itemWidget(it)
            card.selected = it.data(Qt.ItemDataRole.UserRole) == uri
            card.update()

    def open_add(self):
        d = AddDialog(self)
        if d.exec() != QDialog.DialogCode.Accepted:
            return
        urls, added, errs = [], 0, 0
        for line in d.text().splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("http://") or line.startswith("https://"):
                urls.append(line)
                continue
            try:
                resolve_config(line, self.socks_port, self.http_port)
                if line not in self.configs:
                    self.configs.append(line)
                added += 1
            except Exception:
                errs += 1
        self.save_configs()
        self.refresh_list()
        if added or errs:
            self._log(f"{added} کانفیگ اضافه شد" + (f" / {errs} نامعتبر" if errs else ""))
        if urls:
            self._log("دریافت ساب‌کریپشن...")
            self._subw = SubWorker(urls)
            self._subw.done.connect(self._sub_done)
            self._subw.start()

    def _sub_done(self, uris, errs):
        added = 0
        for u in uris:
            try:
                resolve_config(u, self.socks_port, self.http_port)
                if u not in self.configs:
                    self.configs.append(u)
                    added += 1
            except Exception:
                errs += 1
        self.save_configs()
        self.refresh_list()
        self._log(f"ساب: {added} کانفیگ دریافت شد" + (f" / {errs} خطا" if errs else ""))

    def _ctx_menu(self, pos):
        it = self.lst.itemAt(pos)
        if not it:
            return
        uri = it.data(Qt.ItemDataRole.UserRole)
        m = QMenu(self)
        act_copy = m.addAction("کپی لینک")
        act_del = m.addAction("حذف")
        ch = m.exec(self.lst.mapToGlobal(pos))
        if ch == act_copy:
            QApplication.clipboard().setText(uri)
            self._log("لینک کپی شد.")
        elif ch == act_del:
            if uri in self.configs:
                self.configs.remove(uri)
            self.save_configs()
            self.refresh_list()

    # ── اتصال ──
    def toggle(self):
        if self.proc:
            self.disconnect_xray()
            return
        uri = self._selected_uri()
        if not uri:
            QMessageBox.information(self, "Scorpion VPN", "ابتدا یک سرور انتخاب کنید.")
            return
        opts = {"mux": bool(self.settings.get("mux")),
                "frag": bool(self.settings.get("frag")),
                "ip_type": self.settings.get("ip_type", "4"),
                "lan": bool(self.settings.get("lan"))}
        try:
            cfg = resolve_config(uri, self.socks_port, self.http_port, opts)
        except Exception as e:
            QMessageBox.critical(self, "خطا", str(e))
            return
        self.connect_xray(cfg)

    def connect_xray(self, cfg):
        if os.name == "nt" and not os.path.exists(XRAY_PATH):
            QMessageBox.critical(self, "هسته", "فایل xray.exe کنار برنامه قرار ندارد.")
            return
        fd, path = tempfile.mkstemp(suffix=".json", prefix="scorpion_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False)
        flags = 0x08000000 if os.name == "nt" else 0
        try:
            self.proc = subprocess.Popen([XRAY_PATH, "run", "-c", path],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         creationflags=flags)
        except OSError as e:
            QMessageBox.critical(self, "خطا", f"اجرای xray: {e}")
            return
        if self.cb_live.isChecked():
            set_system_proxy(True, "127.0.0.1:%d" % self.http_port)
            self.proxy_info.setText("HTTP 127.0.0.1:%d  •  SOCKS5 127.0.0.1:%d" % (self.http_port, self.socks_port))
        self.power.connected = True
        self.power.update()
        self.chip.setText("متصل")
        self.chip.setObjectName("chipOn")
        self.chip.style().unpolish(self.chip)
        self.chip.style().polish(self.chip)
        self._log("متصل شد.")

    def disconnect_xray(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None
        set_system_proxy(False)
        self.proxy_info.setText("")
        self.power.connected = False
        self.power.update()
        self.chip.setText("قطع")
        self.chip.setObjectName("chipOff")
        self.chip.style().unpolish(self.chip)
        self.chip.style().polish(self.chip)
        self._log("قطع شد.")

    def do_ping(self):
        uri = self._selected_uri()
        if not uri:
            return
        if getattr(self, "_ping", None) is not None and self._ping.isRunning():
            return
        try:
            plain = decode_scorpion(uri) if is_scorpion(uri) else uri
            _s, _f, d = parse_uri(plain)
        except Exception:
            return
        self._set_ping("...", SUB)
        self._ping = PingWorker(d["host"], d["port"])
        self._ping.done.connect(self._ping_done)
        self._ping.start()

    def _set_ping(self, txt, color):
        self.ping_lbl.setText(txt)
        pal = self.ping_lbl.palette()
        pal.setColor(QPalette.ColorRole.WindowText, QColor(color))
        self.ping_lbl.setPalette(pal)

    def _ping_done(self, ms):
        self._set_ping(f"{ms} ms" if ms >= 0 else "ناموفق", ACCENT if ms >= 0 else "#ff6b6b")

    def _about(self):
        QMessageBox.about(self, "Scorpion VPN",
                          "Scorpion VPN 1.0\nHami Smart Systems\n\nپشتیبانی از VLESS / VMESS / Shadowsocks / Trojan\nساب‌کریپشن و کانفیگ‌های اختصاصی scorpion://")

    def _log(self, s):
        self.log.append(s)

    def closeEvent(self, e):
        self.disconnect_xray()
        e.accept()


if __name__ == "__main__":
    import traceback

    def _hook(t, v, tb):
        try:
            with open(os.path.join(APP_DIR, "scorpion_crash.log"), "a", encoding="utf-8") as f:
                f.write(time.ctime() + "\n")
                traceback.print_exception(t, v, tb, file=f)
        except OSError:
            pass

    sys.excepthook = _hook
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("hami.scorpionvpn.1.0")
        except Exception:
            pass
    app = QApplication(sys.argv)
    app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
    app.setFont(QFont("Segoe UI", 10))
    app.setStyleSheet(STYLE)
    icon_file = ICON_PATH if os.path.exists(ICON_PATH) else ICO_PATH
    if os.path.exists(icon_file):
        app.setWindowIcon(QIcon(icon_file))
    win = ScorpionVPN()
    win.show()
    sys.exit(app.exec())
