# -*- coding: utf-8 -*-
"""
Scorpion VPN — کلاینت ویندوز (تک‌فایل)
طراحی حرفه‌ای تاریک + پشتیبانی کانفیگ‌های استاندارد و اختصاصی scorpion://

اجرا:  pip install PyQt6 cryptography  +  xray.exe کنار همین فایل
آیکون نوار وظیفه از scorpion.ico (BMP) و منبع داخل exe می‌آید، نه از کش ویندوز.
"""
import os, sys, json, base64, hashlib, subprocess, tempfile, socket, time
try:
    import scorpion_update as supd
except Exception:
    supd = None
from scorpion_i18n import tr, set_lang, LANG
from scorpion_sub import config_key, merge_subscription

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
        raise ValueError(tr("not_scorpion"))
    raw = base64.urlsafe_b64decode(uri[len(MAGIC):])
    if len(raw) < 13:
        raise ValueError(tr("bad_format"))
    return AESGCM(_key()).decrypt(raw[:12], raw[12:], None).decode("utf-8")


# ───────────────────────── ۲) تبدیل URI به کانفیگ xray ─────────────────────────
import urllib.parse as up


def _b64json(s):
    s = s.strip()
    return json.loads(base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8"))


def parse_uri(uri):
    uri = uri.strip()
    if "://" not in uri:
        raise ValueError(tr("unknown_format"))
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
    raise ValueError(tr("proto_unsup", scheme))


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
    raise ValueError(tr("proto_unsup2"))


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


def _bundle_dir():
    """پوشه‌ای که PyInstaller فایل‌های --add-data را آنجا می‌گذارد (_internal)."""
    d = getattr(sys, "_MEIPASS", None)
    return d if d and os.path.isdir(d) else APP_DIR


def _app_dir():
    """پوشهٔ خود exe (یا اسکریپت در حالت توسعه)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return APP_DIR


def resource_path(name):
    """مسیر فایل همراه برنامه؛ هم داخل _internal و هم کنار exe را می‌گردد."""
    for base in (_bundle_dir(), _app_dir(), APP_DIR, os.path.join(_app_dir(), "_internal")):
        p = os.path.join(base, name)
        if os.path.exists(p):
            return p
    return os.path.join(_bundle_dir(), name)


XRAY_PATH = resource_path("xray.exe") if os.name == "nt" else resource_path("xray")
ICON_PATH = resource_path("scorpion_icon.png")
ICO_PATH = resource_path("scorpion.ico")
CONFIGS_FILE = os.path.join(APP_DIR, "scorpion_configs.json")
SUBS_FILE = os.path.join(os.path.dirname(CONFIGS_FILE), "scorpion_subs.json")
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
        return (tr("cfg_scorpion") if sc else uri[:20]), tr("invalid"), sc


def fmt_time(secs):
    """ثانیه → HH:MM:SS"""
    secs = max(0, int(secs))
    return "%02d:%02d:%02d" % (secs // 3600, (secs % 3600) // 60, secs % 60)


def load_settings():
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def set_system_proxy(on, server="127.0.0.1:10809"):
    host, port = "127.0.0.1", "10809"
    if ":" in str(server):
        host, port = server.rsplit(":", 1)
    if os.name == "nt":
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
        return
    import platform, shutil
    sysname = platform.system()
    try:
        if sysname == "Darwin" and shutil.which("networksetup"):
            out = subprocess.check_output(["networksetup", "-listallnetworkservices"], text=True, errors="replace")
            services = [ln.strip() for ln in out.splitlines()[1:] if ln.strip() and not ln.startswith("*")]
            for svc in services:
                if on:
                    subprocess.call(["networksetup", "-setwebproxy", svc, host, str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.call(["networksetup", "-setsecurewebproxy", svc, host, str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.call(["networksetup", "-setsocksfirewallproxy", svc, "127.0.0.1", "10808"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    subprocess.call(["networksetup", "-setwebproxystate", svc, "off"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.call(["networksetup", "-setsecurewebproxystate", svc, "off"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.call(["networksetup", "-setsocksfirewallproxystate", svc, "off"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        if shutil.which("gsettings"):
            if on:
                subprocess.call(["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.call(["gsettings", "set", "org.gnome.system.proxy.http", "host", host], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.call(["gsettings", "set", "org.gnome.system.proxy.http", "port", str(int(port))], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.call(["gsettings", "set", "org.gnome.system.proxy.https", "host", host], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.call(["gsettings", "set", "org.gnome.system.proxy.https", "port", str(int(port))], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.call(["gsettings", "set", "org.gnome.system.proxy.socks", "host", "127.0.0.1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.call(["gsettings", "set", "org.gnome.system.proxy.socks", "port", "10808"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.call(["gsettings", "set", "org.gnome.system.proxy", "mode", "none"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


# ───────────────────────── ۴) رابط کاربری ─────────────────────────
import math
import urllib.request as ureq
from PyQt6.QtGui import QFont, QIcon, QPainter, QColor, QPen, QPainterPath, QPalette
from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal, QSize, QRectF, QPointF
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QListWidget, QListWidgetItem,
                             QTextEdit, QMessageBox, QStackedWidget, QSpinBox, QCheckBox,
                             QDialog, QMenu, QScrollArea, QComboBox, QInputDialog)

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
QLabel#timer{color:%(ac)s;font-family:Consolas,monospace;font-size:19px;font-weight:bold;letter-spacing:2px;background:transparent;}
QWidget#notify{background:#12241b;border:1px solid %(ac)s;border-radius:10px;}
QLabel#notify{color:%(ac)s;font-size:12px;font-weight:600;background:transparent;}
QLabel#pinfo{color:#5f6a7c;font-size:11px;}
QLabel#cd{color:%(ac)s;font-family:Consolas,monospace;font-size:12px;font-weight:bold;background:transparent;}
QLabel#aboutbody{color:%(sb)s;font-size:12px;}
QLabel#aboutnotify{color:%(ac)s;border:1px solid %(ac)s;background:#12241b;border-radius:10px;padding:10px 14px;font-size:12px;font-weight:600;}
QSpinBox::up-button{subcontrol-origin:border;subcontrol-position:top right;width:18px;border:none;}
QSpinBox::down-button{subcontrol-origin:border;subcontrol-position:bottom right;width:18px;border:none;}
QSpinBox::up-arrow{width:9px;height:7px;}
QSpinBox::down-arrow{width:9px;height:7px;}
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
        self.timer_text = ""
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
        if self.connected:
            # حالت متصل: آیکون کوچک + وضعیت + شمارندهٔ زمان اتصال — وسط دکمه
            r = 22
            iy = cy - 40
            p.drawArc(QRectF(cx - r, iy - r + 3, 2 * r, 2 * r), 120 * 16, 300 * 16)
            p.drawLine(int(cx), int(iy - r - 6), int(cx), int(iy - r - 4))
            p.setPen(QColor(TEXT))
            p.setFont(QFont("Segoe UI", 11, QFont.Weight.DemiBold))
            p.drawText(QRectF(0, cy - 12, w, 20), Qt.AlignmentFlag.AlignCenter, tr("connected"))
            p.setPen(QColor(ACCENT))
            p.setFont(QFont("Consolas", 17, QFont.Weight.Bold))
            p.drawText(QRectF(0, cy + 12, w, 28), Qt.AlignmentFlag.AlignCenter,
                       self.timer_text or "00:00:00")
        else:
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
        self.setWindowTitle(tr("add_title"))
        self.setFixedSize(540, 360)
        v = QVBoxLayout(self)
        t = QLabel(tr("add_hint"))
        t.setWordWrap(True)
        t.setStyleSheet("color:%s;background:transparent;" % SUB)
        self.txt = QTextEdit()
        self.txt.setStyleSheet("background:%s;border:1px solid %s;border-radius:10px;padding:8px;font-family:Consolas,monospace;" % (CARD, BORDER))
        row = QHBoxLayout()
        ok = QPushButton(tr("add"))
        ok.setObjectName("flat")
        cancel = QPushButton(tr("cancel"))
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


class UpdateWorker(QThread):
    """کارهای شبکه‌ای بروزرسانی: بررسی / دانلود — تا رابط گرافیکی قفل نشود"""
    done = pyqtSignal(str, str)     # (نوع، متن نتیجه/JSON)
    prog = pyqtSignal(int, str)     # (درصد، توضیح)

    def __init__(self, kind, payload=None):
        super().__init__()
        self.kind = kind
        self.payload = payload or {}

    def run(self):
        if supd is None:
            self.done.emit(self.kind, "NO_MODULE")
            return
        try:
            if self.kind == "check_app":
                m = supd.fetch_manifest()
                info = supd.app_update(m)
                self.done.emit("check_app", json.dumps(info, ensure_ascii=False) if info else "")

            elif self.kind == "check_core":
                m = supd.fetch_manifest()
                cur = supd.xray_version(XRAY_PATH)
                info = supd.core_update(m, cur)
                self.done.emit("check_core", json.dumps({"current": cur, "info": info}, ensure_ascii=False))

            elif self.kind == "dl_app":
                info = self.payload.get("info", {})
                def _p(pct, done, total):
                    self.prog.emit(pct, tr("dl_app_pct", pct))
                path = supd.download_installer(info, progress=_p)
                self.done.emit("dl_app", path)

            elif self.kind == "dl_core":
                info = self.payload.get("info", {})
                def _p2(pct, done, total):
                    self.prog.emit(pct, tr("dl_core_pct", pct))
                backup = supd.download_and_install_core(info, APP_DIR, progress=_p2)
                self.done.emit("dl_core", str(backup or ""))

            else:
                self.done.emit(self.kind, "UNKNOWN")
        except Exception as e:
            self.done.emit(self.kind, "ERR:" + str(e))


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
        self.setWindowTitle(tr("ports_title"))
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
        save = QPushButton(tr("save"))
        save.setObjectName("flat")
        save.clicked.connect(self.accept)
        v.addLayout(r1)
        v.addStretch()
        v.addWidget(save, 0, Qt.AlignmentFlag.AlignLeft)


class QTimerSetDialog(QDialog):
    def __init__(self, parent=None, current_secs=0):
        super().__init__(parent)
        self.setWindowTitle(tr("timer_title"))
        self.setFixedSize(430, 200)
        v = QVBoxLayout(self)
        v.setSpacing(14)
        t = QLabel(tr("timer_hint"))
        t.setWordWrap(True)
        t.setStyleSheet("color:%s;background:transparent;" % SUB)
        r = QHBoxLayout()
        r.addWidget(QLabel(tr("hours")))
        self.sp_h = QSpinBox()
        self.sp_h.setRange(0, 24)
        self.sp_h.setMinimumWidth(95)
        self.sp_h.setValue(min(24, int(current_secs // 3600)))
        r.addWidget(self.sp_h)
        r.addSpacing(18)
        r.addWidget(QLabel(tr("minutes")))
        self.sp_m = QSpinBox()
        self.sp_m.setRange(0, 59)
        self.sp_m.setMinimumWidth(95)
        self.sp_m.setValue(int((current_secs % 3600) // 60))
        r.addWidget(self.sp_m)
        r.addStretch()
        v.addWidget(t)
        v.addLayout(r)
        r2 = QHBoxLayout()
        ok = QPushButton("Set")
        ok.setObjectName("flat")
        ok.clicked.connect(self.accept)
        cancel = QPushButton(tr("cancel"))
        cancel.setObjectName("danger")
        cancel.clicked.connect(self.reject)
        r2.addStretch()
        r2.addWidget(cancel)
        r2.addWidget(ok)
        v.addLayout(r2)

    def seconds(self):
        return self.sp_h.value() * 3600 + self.sp_m.value() * 60


class SubWorker(QThread):
    done = pyqtSignal(list, int)

    def __init__(self, urls):
        super().__init__()
        self.urls = urls

    def run(self):
        out, errs = [], 0
        self.per_url = {}
        for u in self.urls:
            try:
                req = ureq.Request(u, headers={"User-Agent": "ScorpionVPN/1.4.0"})
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
                self.per_url[u] = lines
                if lines:
                    out += lines
                else:
                    errs += 1
            except OSError:
                self.per_url[u] = []
                errs += 1
        self.done.emit(out, errs)



class AboutDialog(QDialog):
    """About — completely in English + Check for Update + Auto update"""

    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self.setWindowTitle("About")
        self.setFixedSize(480, 470)
        v = QVBoxLayout(self)
        v.setContentsMargins(26, 22, 26, 22)
        v.setSpacing(14)

        head = QHBoxLayout()
        head.addWidget(IconWidget("shield", ACCENT, 36, 2.2))
        head.addSpacing(12)
        col = QVBoxLayout()
        col.setSpacing(2)
        t = QLabel("Scorpion VPN  %s" % (supd.APP_VERSION if supd else "1.4.0"))
        t.setObjectName("title")
        s = QLabel("A HAMI SMART SYSTEMS product")
        s.setObjectName("sub")
        col.addWidget(t)
        col.addWidget(s)
        head.addLayout(col, 1)
        v.addLayout(head)

        core = ""
        try:
            core = supd.xray_version(XRAY_PATH) if supd else ""
        except Exception:
            core = ""
        body = QLabel(
            "Version: %s    |    Xray core: %s\n\n"
            "hamidesigns.shop\n"
            "Telegram support: t.me/Hami_Smart_Systems\n\n"
            "Supports VLESS / VMESS / Shadowsocks / Trojan\n"
            "Subscriptions & custom scorpion:// configs\n\n"
            "All rights to this software belong to the\nHAMISMARTSYSTEMS brand."
            % ((supd.APP_VERSION if supd else "1.4.0"), core or "unknown"))
        body.setObjectName("aboutbody")
        v.addWidget(body)

        self.cb_auto = QCheckBox("Auto update (weekly check & install)")
        self.cb_auto.setChecked(bool(win.settings.get("auto_update")))
        self.cb_auto.toggled.connect(self._on_auto)
        v.addWidget(self.cb_auto)

        row = QHBoxLayout()
        self.check_btn = QPushButton("Check for Update")
        self.check_btn.setObjectName("flat")
        self.check_btn.clicked.connect(lambda: self.win.check_app_update(manual=True))
        row.addWidget(self.check_btn)
        row.addStretch()
        v.addLayout(row)

        self.notify = QLabel("")
        self.notify.setObjectName("aboutnotify")
        self.notify.setWordWrap(True)
        self.notify.hide()
        v.addWidget(self.notify)

        ok = QPushButton("OK")
        ok.setObjectName("flat")
        ok.clicked.connect(self.accept)
        v.addWidget(ok, 0, Qt.AlignmentFlag.AlignHCenter)
        self.refresh_notify()

    def _on_auto(self, on):
        self.win.settings["auto_update"] = bool(on)
        try:
            self.win.sw_autoupd.blockSignals(True)
            self.win.sw_autoupd.setChecked(bool(on))
            self.win.sw_autoupd.blockSignals(False)
            self.win._save_opts()
        except Exception:
            pass

    def refresh_notify(self):
        info = self.win.pending_app_update
        if info and not self.win.settings.get("auto_update"):
            self.notify.setText("New version %s is available — click "
                                 "“Check for Update” to install it." % info.get("latest"))
            self.notify.show()
        else:
            self.notify.hide()


def app_icon():
    """آیکون پنجره — ریشه‌ای فیکس برای تسک‌بار ویندوز.

    مشکل قبلی: QIcon(sys.executable) گاهی null برمی‌گرداند یا PNG به HICON تبدیل نمی‌شود.
    راه‌حل: همه مسیرها را امتحان کن + از QPixmap هم بساز تا هیچ‌وقت خالی نماند.
    """
    from PyQt6.QtGui import QPixmap
    candidates = []
    # 1) exe خودش (آیکون embed شده)
    if os.name == "nt" and getattr(sys, "frozen", False) and os.path.isfile(sys.executable):
        candidates.append(sys.executable)
    # 2) ico کنار exe / داخل _internal / bundle
    for p in [ICO_PATH, ICON_PATH, resource_path("scorpion.ico"), resource_path("scorpion_icon.png"),
              os.path.join(APP_DIR, "scorpion.ico"), os.path.join(APP_DIR, "scorpion_icon.png"),
              os.path.join(_app_dir(), "scorpion.ico"), os.path.join(_app_dir(), "_internal", "scorpion.ico")]:
        if p and os.path.exists(p):
            candidates.append(p)

    for path in candidates:
        try:
            ic = QIcon(path)
            if not ic.isNull():
                # تست کن pixmap هم بدهد
                pm = ic.pixmap(32, 32)
                if not pm.isNull():
                    return ic
        except Exception:
            pass
        # fallback از QPixmap
        try:
            if path.lower().endswith(('.png', '.ico')):
                pm = QPixmap(path)
                if not pm.isNull():
                    return QIcon(pm)
        except Exception:
            pass

    # آخرین تلاش: اگر هیچ فایلی نبود، یه آیکون ساده بساز تا تسک‌بار خالی نماند
    try:
        pm = QPixmap(64, 64)
        pm.fill(QColor("#0B6623"))
        return QIcon(pm)
    except Exception:
        return QIcon()


def _set_windows_taskbar_icon(hwnd, ico_path=None):
    """ویندوز: WM_SETICON با LoadImageW تا تسک‌بار حتماً آیکون بگیرد — ریشه‌ای."""
    if os.name != "nt" or not hwnd:
        return False
    try:
        import ctypes
        from ctypes import wintypes
        # مسیر ico
        if not ico_path or not os.path.exists(ico_path):
            for cand in [ICO_PATH, resource_path("scorpion.ico"), os.path.join(APP_DIR, "scorpion.ico"),
                         os.path.join(_app_dir(), "scorpion.ico"), os.path.join(_app_dir(), "_internal", "scorpion.ico")]:
                if cand and os.path.exists(cand):
                    ico_path = cand
                    break
        if not ico_path or not os.path.exists(ico_path):
            return False

        user32 = ctypes.windll.user32
        # IMAGE_ICON=1, LR_LOADFROMFILE=0x10, LR_DEFAULTSIZE=0x40
        hicon_big = user32.LoadImageW(None, ico_path, 1, 0, 0, 0x10 | 0x40)
        hicon_small = user32.LoadImageW(None, ico_path, 1, 16, 16, 0x10)
        if not hicon_big:
            hicon_big = user32.LoadImageW(None, ico_path, 1, 32, 32, 0x10)
        WM_SETICON = 0x80
        ICON_SMALL = 0
        ICON_BIG = 1
        if hicon_small:
            user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, hicon_small)
        if hicon_big:
            user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, hicon_big)
        return bool(hicon_big or hicon_small)
    except Exception:
        return False


class ScorpionVPN(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Scorpion VPN  %s" % (supd.APP_VERSION if supd else "1.4.0"))
        self.resize(1040, 680)
        self.setMinimumSize(880, 580)
        # ریشه‌ای: همیشه آیکون ست کن، حتی fallback
        self._icon = app_icon()
        try:
            if not self._icon.isNull():
                self.setWindowIcon(self._icon)
            else:
                # آخرین تلاش
                self.setWindowIcon(QIcon(ICO_PATH if os.path.exists(ICO_PATH) else ICON_PATH))
        except Exception:
            pass
        # تسک‌بار ویندوز را بعد از ساخته شدن hwnd ست کن
        if os.name == "nt":
            QTimer.singleShot(200, self._apply_taskbar_icon)
            QTimer.singleShot(800, self._apply_taskbar_icon)

        self.proc = None
        self.connected_uri = None
        self.configs = []
        self.settings = load_settings()
        set_lang(self.settings.get("language") or "en")
        # ── تایمر اتصال / شمارندهٔ قطع خودکار ──
        self.conn_start = 0.0
        self.countdown_end = 0.0
        self.auto_off_secs = int(self.settings.get("auto_off", 0) or 0)
        self.conn_timer = QTimer(self)
        self.conn_timer.setInterval(1000)
        self.conn_timer.timeout.connect(self._tick_conn)
        self.about_dlg = None
        # ── وضعیت بروزرسانی ──
        self.pending_app_update = None
        self._upd_manual = False
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

        self.nav_servers = NavBtn("globe", tr("nav_servers"))
        self.nav_servers.setChecked(True)
        self.nav_settings = NavBtn("gear", tr("nav_settings"))
        self.nav_about = NavBtn("info", tr("nav_about"), checkable=False)
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
        self.page_title = QLabel(tr("nav_servers"))
        self.page_title.setObjectName("title")
        head.addWidget(self.page_title)
        head.addStretch()
        mv.addLayout(head)

        self.pages = QStackedWidget()
        mv.addWidget(self.pages, 1)
        outer.addWidget(main, 1)

        self.pages.addWidget(self._build_servers_page())
        self.pages.addWidget(self._build_settings_page())

        self.nav_servers.clicked.connect(lambda: self._goto(0, tr("nav_servers")))
        self.nav_settings.clicked.connect(lambda: self._goto(1, tr("nav_settings")))
        self.nav_about.clicked.connect(self._about)

        self.load_configs()
        self.refresh_list()

        # بررسی هفتگی بروزرسانی (هر ۷ روز یک‌بار، پس از راه‌اندازی)
        try:
            if time.time() - float(self.settings.get("last_update_check", 0)) > 7 * 86400:
                self.check_app_update(manual=False)
        except Exception:
            pass

    def _apply_taskbar_icon(self):
        """ریشه‌ای: hwnd ویندوز را بگیر و WM_SETICON بفرست تا تسک‌بار خالی نماند."""
        if os.name != "nt":
            return
        try:
            hwnd = int(self.winId())
            if hwnd:
                _set_windows_taskbar_icon(hwnd, ICO_PATH)
        except Exception:
            pass
        try:
            if hasattr(self, '_icon') and not self._icon.isNull():
                self.setWindowIcon(self._icon)
        except Exception:
            pass

    def showEvent(self, event):
        super().showEvent(event)
        if os.name == "nt":
            QTimer.singleShot(100, self._apply_taskbar_icon)
            QTimer.singleShot(500, self._apply_taskbar_icon)

    def _on_language(self, idx):
        code = "fa" if idx == 1 else "en"
        if (self.settings.get("language") or "en") == code:
            return
        self.settings["language"] = code
        set_lang(code)
        self._save_opts()
        self.apply_language()
        QMessageBox.information(self, "Scorpion VPN", tr("lang_restart"))

    def apply_language(self):
        self.nav_servers.setToolTip(tr("nav_servers"))
        self.nav_settings.setToolTip(tr("nav_settings"))
        self.nav_about.setToolTip(tr("nav_about"))
        self.page_title.setText(tr("nav_servers") if self.pages.currentIndex() == 0 else tr("nav_settings"))
        self.search.setPlaceholderText(tr("search"))
        self.add_btn.setText(tr("add"))
        self.refresh_btn.setText(tr("refresh_sub"))
        self.ping_btn.setText(tr("ping"))
        self.cb_live.setText(tr("sys_proxy"))
        if not self.configs:
            self.cur_name.setText(tr("no_server"))
        self.power.update()

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
        self.search.setPlaceholderText(tr("search"))
        self.search.textChanged.connect(self.refresh_list)
        self.add_btn = QPushButton(tr("add"))
        self.add_btn.setObjectName("flat")
        self.add_btn.clicked.connect(self.open_add)
        self.refresh_btn = QPushButton(tr("refresh_sub"))
        self.refresh_btn.setObjectName("flat")
        self.refresh_btn.clicked.connect(self.refresh_subs)
        top.addWidget(self.search, 1)
        top.addWidget(self.refresh_btn)
        top.addWidget(self.add_btn)
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
        rv.addSpacing(2)

        set_btn = QPushButton("Set")
        set_btn.setObjectName("flat")
        set_btn.setFixedWidth(64)
        set_btn.setToolTip(tr("auto_off_tip"))
        set_btn.clicked.connect(self.open_timer_set)
        srow = QHBoxLayout()
        srow.addStretch()
        srow.addWidget(set_btn)
        srow.addStretch()
        rv.addLayout(srow)
        rv.addSpacing(2)

        self.cur_name = QLabel(tr("no_server"))
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
        self.ping_btn = QPushButton(tr("ping"))
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
        self.cb_live = QCheckBox(tr("sys_proxy"))
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

        self.cd_lbl = QLabel("")
        self.cd_lbl.setObjectName("cd")
        self.cd_lbl.hide()
        rv.addWidget(self.cd_lbl)

        self.log = QTextEdit()
        self.log.setObjectName("log")
        self.log.setReadOnly(True)
        self.log.setFixedHeight(80)
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

        # ── Language ──
        cv.addWidget(self._sec(tr("sec_language")))
        langw = QWidget()
        langw.setObjectName("panel")
        lv = QVBoxLayout(langw)
        lv.setContentsMargins(0, 6, 0, 6)
        self.cb_lang = QComboBox()
        self.cb_lang.addItems([tr("lang_en"), tr("lang_fa")])
        self.cb_lang.setCurrentIndex(1 if LANG == "fa" else 0)
        self.cb_lang.currentIndexChanged.connect(self._on_language)
        lv.addWidget(Row(tr("lang_label"), tr("lang_sub"), ctrl=self.cb_lang))
        cv.addWidget(langw)

        # ── تونل ──
        cv.addWidget(self._sec(tr("sec_tunnel")))
        tun = QWidget()
        tun.setObjectName("panel")
        tv = QVBoxLayout(tun)
        tv.setContentsMargins(0, 6, 0, 6)
        tv.setSpacing(0)

        self.sw_frag = Switch(bool(self.settings.get("frag", False)))
        tv.addWidget(Row(tr("frag"), tr("frag_sub"), ctrl=self.sw_frag))

        self.sw_mux = Switch(bool(self.settings.get("mux", False)))
        tv.addWidget(Row(tr("mux"), tr("mux_sub"), ctrl=self.sw_mux))

        self.cb_ip = QComboBox()
        self.cb_ip.addItems(["IPv4", "IPv6"])
        self.cb_ip.setCurrentIndex(0 if str(self.settings.get("ip_type", "4")) == "4" else 1)
        tv.addWidget(Row(tr("ip_type"), None, ctrl=self.cb_ip))

        self.sw_lan = Switch(bool(self.settings.get("lan", False)))
        tv.addWidget(Row(tr("lan"), tr("lan_sub"), ctrl=self.sw_lan))

        self.ports_lbl = QLabel("SOCKS %d  /  HTTP %d" % (self.socks_port, self.http_port))
        self.ports_lbl.setObjectName("pinfo")
        ports_btn = QPushButton(tr("change"))
        ports_btn.setObjectName("flat")
        ports_btn.clicked.connect(self.open_ports)
        r = Row(tr("local_ports"), None)
        r.add(self.ports_lbl)
        r.add(ports_btn)
        tv.addWidget(r)
        cv.addWidget(tun)

        # ── سایر ──
        cv.addWidget(self._sec(tr("sec_other")))
        oth = QWidget()
        oth.setObjectName("panel")
        ov = QVBoxLayout(oth)
        ov.setContentsMargins(0, 6, 0, 6)
        ov.setSpacing(0)
        clear_btn = QPushButton(tr("clear"))
        clear_btn.setObjectName("flat")
        clear_btn.clicked.connect(self.log.clear)
        ov.addWidget(Row(tr("logs"), tr("logs_sub"), ctrl=clear_btn))
        reset_btn = QPushButton(tr("reset"))
        reset_btn.setObjectName("danger")
        reset_btn.clicked.connect(self.reset_all)
        ov.addWidget(Row(tr("reset"), tr("reset_sub"), danger=True, ctrl=reset_btn))
        cv.addWidget(oth)

        # ── بروزرسانی ──
        cv.addWidget(self._sec(tr("sec_update")))
        upd = QWidget()
        upd.setObjectName("panel")
        uv2 = QVBoxLayout(upd)
        uv2.setContentsMargins(0, 6, 0, 6)
        uv2.setSpacing(0)

        self.upd_lbl = QLabel(tr("ver_line", (supd.APP_VERSION if supd else "?")))
        self.upd_lbl.setObjectName("pinfo")
        check_app_btn = QPushButton(tr("check"))
        check_app_btn.setObjectName("flat")
        check_app_btn.clicked.connect(lambda: self.check_app_update(manual=True))
        r_app = Row(tr("upd_app"), tr("upd_app_sub"))
        r_app.add(self.upd_lbl)
        r_app.add(check_app_btn)
        uv2.addWidget(r_app)

        # نوتیفیکیشن آپدیت موجود (وقتی آپدیت خودکار خاموش باشد)
        self.upd_notify = QWidget()
        self.upd_notify.setObjectName("notify")
        nv = QHBoxLayout(self.upd_notify)
        nv.setContentsMargins(14, 10, 14, 10)
        self.upd_notify_lbl = QLabel("")
        self.upd_notify_lbl.setObjectName("notify")
        self.upd_go = QPushButton(tr("update"))
        self.upd_go.setObjectName("flat")
        self.upd_go.clicked.connect(lambda: self.start_app_update())
        nv.addWidget(self.upd_notify_lbl, 1)
        nv.addWidget(self.upd_go)
        self.upd_notify.hide()
        uv2.addWidget(self.upd_notify)

        self.sw_autoupd = Switch(bool(self.settings.get("auto_update", False)))
        uv2.addWidget(Row(tr("auto_upd"), tr("auto_upd_sub"), ctrl=self.sw_autoupd))

        self.core_lbl = QLabel("—")
        self.core_lbl.setObjectName("pinfo")
        check_core_btn = QPushButton(tr("check"))
        check_core_btn.setObjectName("flat")
        check_core_btn.clicked.connect(self.check_core_update)
        r_core = Row(tr("upd_core"), None, ctrl=check_core_btn)
        r_core.add(self.core_lbl)
        uv2.addWidget(r_core)
        cv.addWidget(upd)

        # ── درباره ──
        cv.addWidget(self._sec(tr("sec_about")))
        ab = QWidget()
        ab.setObjectName("panel")
        av = QVBoxLayout(ab)
        av.setContentsMargins(0, 6, 0, 6)
        av.setSpacing(0)
        about_btn = QPushButton(tr("view"))
        about_btn.setObjectName("flat")
        about_btn.clicked.connect(self._about)
        av.addWidget(Row("Scorpion VPN — v%s" % (supd.APP_VERSION if supd else "1.4.0"), "HAMI SMART SYSTEMS", ctrl=about_btn))
        cv.addWidget(ab)

        cv.addStretch(1)
        scr.setWidget(content)
        outer.addWidget(scr)

        # اتصال سیگنال‌ها بعد از آماده‌شدن همه‌ی اجزا
        self.sw_frag.toggled.connect(self._save_opts)
        self.sw_mux.toggled.connect(self._save_opts)
        self.sw_lan.toggled.connect(self._save_opts)
        self.sw_autoupd.toggled.connect(self._save_opts)
        self.cb_ip.currentIndexChanged.connect(self._save_opts)
        self._core_version_async()
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
                              "auto_update": self.sw_autoupd.isChecked(),
                              "socks_port": self.socks_port,
                              "http_port": self.http_port,
                              "language": "fa" if getattr(self, "cb_lang", None) and self.cb_lang.currentIndex() == 1 else self.settings.get("language", "en")})
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.settings, f)
        except OSError:
            pass
        try:
            if self.about_dlg is not None:
                self.about_dlg.cb_auto.blockSignals(True)
                self.about_dlg.cb_auto.setChecked(bool(self.settings.get("auto_update")))
                self.about_dlg.cb_auto.blockSignals(False)
                self.about_dlg.refresh_notify()
        except Exception:
            pass

    def open_ports(self):
        d = PortsDialog(self.socks_port, self.http_port, self)
        if d.exec() == QDialog.DialogCode.Accepted:
            self.socks_port = d.sp_socks.value()
            self.http_port = d.sp_http.value()
            self.ports_lbl.setText("SOCKS %d  /  HTTP %d" % (self.socks_port, self.http_port))
            self._save_opts()
            self._log(tr("ports_changed"))

    def reset_all(self):
        if QMessageBox.question(self, tr("reset_title"), tr("reset_q"),
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
        self._log(tr("reset_done"))

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
            self._log(tr("cfg_added", added) + (tr("cfg_bad", errs) if errs else ""))
        if urls:
            subs = self.load_subs()
            known = {s.get("url") for s in subs}
            for u in urls:
                if u not in known:
                    subs.append({"url": u, "keys": []})
                    known.add(u)
            self.save_subs(subs)
            self._log(tr("sub_saved"))
            self._log(tr("sub_fetch"))
            self._refreshing = False
            self._subw = SubWorker(urls)
            self._subw.done.connect(self._sub_done)
            self._subw.start()

    def load_subs(self):
        try:
            with open(SUBS_FILE, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return [s for s in data if isinstance(s, dict) and s.get("url")]
        except (OSError, ValueError):
            pass
        return []

    def save_subs(self, subs):
        try:
            with open(SUBS_FILE, "w", encoding="utf-8") as f:
                json.dump(subs, f, ensure_ascii=False)
        except OSError:
            pass

    def _key_of(self, uri):
        plain = decode_scorpion(uri) if is_scorpion(uri) else uri
        return config_key(plain, parse_uri)

    def _remember_sub_keys(self):
        per = getattr(getattr(self, "_subw", None), "per_url", None) or {}
        if not per:
            return
        subs = self.load_subs()
        changed = False
        for s in subs:
            lines = per.get(s.get("url"))
            if not lines:
                continue
            keys = []
            for u in lines:
                try:
                    keys.append(self._key_of(u))
                except Exception:
                    pass
            if keys and s.get("keys") != keys:
                s["keys"] = keys
                changed = True
        if changed:
            self.save_subs(subs)

    def _select_uri(self, uri):
        for i in range(self.lst.count()):
            it = self.lst.item(i)
            if it and it.data(Qt.ItemDataRole.UserRole) == uri:
                self.lst.setCurrentItem(it)
                return

    def refresh_subs(self):
        if getattr(self, "_subw", None) is not None and self._subw.isRunning():
            return
        subs = self.load_subs()
        if not subs:
            url, ok = QInputDialog.getText(self, tr("refresh_title"), tr("refresh_need"))
            url = (url or "").strip()
            if not ok or not url.startswith(("http://", "https://")):
                if ok:
                    self._log(tr("refresh_fail"))
                return
            subs = [{"url": url, "keys": []}]
            self.save_subs(subs)
            self._log(tr("sub_saved"))
        self._log(tr("sub_fetch"))
        self._refreshing = True
        self._subw = SubWorker([s["url"] for s in subs])
        self._subw.done.connect(self._refresh_done)
        self._subw.start()

    def _refresh_done(self, _uris, errs):
        self._refreshing = False
        per = getattr(self._subw, "per_url", {}) or {}
        was = self.connected_uri
        was_key = None
        if was:
            try:
                was_key = self._key_of(was)
            except Exception:
                was_key = None
        configs = list(self.configs)
        new_subs = []
        total = {"replaced": 0, "added": 0, "removed": 0}
        any_fetched = False
        for s in self.load_subs():
            url = s.get("url")
            lines = per.get(url)
            if not lines:
                new_subs.append(s)
                continue
            any_fetched = True
            valid = []
            for u in lines:
                try:
                    resolve_config(u, self.socks_port, self.http_port)
                    valid.append(u)
                except Exception:
                    errs += 1
            configs, keys, stats = merge_subscription(
                configs, valid, s.get("keys") or [], self._key_of)
            for k in total:
                total[k] += stats[k]
            new_subs.append({"url": url, "keys": keys})
        if not any_fetched:
            self._log(tr("refresh_fail"))
            return
        self.configs = configs
        self.save_configs()
        self.save_subs(new_subs)
        self.refresh_list()
        new_uri = None
        if was_key:
            for u in self.configs:
                try:
                    if self._key_of(u) == was_key:
                        new_uri = u
                        break
                except Exception:
                    pass
        if new_uri:
            self._select_uri(new_uri)
        if was and new_uri and new_uri != was and self.proc:
            self.disconnect_xray()
            self._select_uri(new_uri)
            self.toggle()
        if total["replaced"] or total["added"] or total["removed"]:
            self._log(tr("refresh_done", total["replaced"], total["added"], total["removed"]))
        elif errs:
            self._log(tr("refresh_fail"))
        else:
            self._log(tr("refresh_same"))

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
        self._remember_sub_keys()
        self.refresh_list()
        self._log(tr("sub_ok", added) + (tr("sub_err", errs) if errs else ""))

    def _ctx_menu(self, pos):
        it = self.lst.itemAt(pos)
        if not it:
            return
        uri = it.data(Qt.ItemDataRole.UserRole)
        m = QMenu(self)
        act_copy = m.addAction(tr("copy_link"))
        act_del = m.addAction(tr("delete"))
        ch = m.exec(self.lst.mapToGlobal(pos))
        if ch == act_copy:
            QApplication.clipboard().setText(uri)
            self._log(tr("link_copied"))
        elif ch == act_del:
            if uri in self.configs:
                self.configs.remove(uri)
            self.save_configs()
            self.refresh_list()

    # ── تایمر اتصال ──
    def open_timer_set(self):
        d = QTimerSetDialog(self, self.auto_off_secs)
        if d.exec() != QDialog.DialogCode.Accepted:
            return
        secs = d.seconds()
        self.auto_off_secs = secs
        self.settings["auto_off"] = secs
        self._save_opts()
        if secs <= 0:
            self.countdown_end = 0.0
            self.cd_lbl.hide()
            self._log(tr("timer_cleared"))
        elif self.proc:
            # الان متصلیم — شمارش از همین لحظه
            self.countdown_end = time.time() + secs
            self.cd_lbl.setText(tr("auto_off", fmt_time(secs)))
            self.cd_lbl.show()
            self._log(tr("timer_set_now", fmt_time(secs)))
        else:
            # هنوز وصل نیستیم — برای شروع اتصال بعدی ذخیره می‌شود
            self.countdown_end = 0.0
            self.cd_lbl.hide()
            self._log(tr("timer_saved", fmt_time(secs)))

    def _clear_auto_off(self):
        """بعد از پایان شمارنده، تایمر ریست می‌شود تا اتصال بعدی بدون محدودیت زمان باشد."""
        self.countdown_end = 0.0
        if not self.auto_off_secs:
            return
        self.auto_off_secs = 0
        self.settings["auto_off"] = 0
        self._save_opts()
        self._log(tr("timer_reset"))

    def _tick_conn(self):
        if not self.proc:
            return
        now = time.time()
        self.power.timer_text = fmt_time(now - self.conn_start)
        self.power.update()
        if self.countdown_end:
            left = self.countdown_end - now
            if left <= 0:
                self.cd_lbl.hide()
                self._log(tr("timer_fired"))
                self._clear_auto_off()
                self.disconnect_xray()
            else:
                self.cd_lbl.setText(tr("auto_off", fmt_time(left)))
                self.cd_lbl.show()

    # ── اتصال ──
    def toggle(self):
        if self.proc:
            self.disconnect_xray()
            return
        uri = self._selected_uri()
        if not uri:
            QMessageBox.information(self, "Scorpion VPN", tr("pick_server"))
            return
        opts = {"mux": bool(self.settings.get("mux")),
                "frag": bool(self.settings.get("frag")),
                "ip_type": self.settings.get("ip_type", "4"),
                "lan": bool(self.settings.get("lan"))}
        try:
            cfg = resolve_config(uri, self.socks_port, self.http_port, opts)
        except Exception as e:
            QMessageBox.critical(self, tr("error"), str(e))
            return
        self.connect_xray(cfg)

    def connect_xray(self, cfg):
        if os.name == "nt" and not os.path.exists(XRAY_PATH):
            QMessageBox.critical(self, tr("core"), tr("no_xray"))
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
            QMessageBox.critical(self, tr("error"), tr("xray_run", e))
            return
        self.connected_uri = self._selected_uri()
        if self.cb_live.isChecked():
            set_system_proxy(True, "127.0.0.1:%d" % self.http_port)
            self.proxy_info.setText("HTTP 127.0.0.1:%d  •  SOCKS5 127.0.0.1:%d" % (self.http_port, self.socks_port))
        self.power.connected = True
        self.conn_start = time.time()
        self.countdown_end = (self.conn_start + self.auto_off_secs) if self.auto_off_secs > 0 else 0.0
        self.power.timer_text = "00:00:00"
        self.conn_timer.start()
        self.power.update()
        if self.countdown_end:
            self.cd_lbl.setText(tr("auto_off", fmt_time(self.auto_off_secs)))
            self.cd_lbl.show()
            self._log(tr("connected_off", fmt_time(self.auto_off_secs)))
        else:
            self._log(tr("connected_log"))

    def disconnect_xray(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None
        self.connected_uri = None
        set_system_proxy(False)
        self.proxy_info.setText("")
        self.conn_timer.stop()
        self.conn_start = 0.0
        self.countdown_end = 0.0
        self.cd_lbl.hide()
        self.power.connected = False
        self.power.timer_text = ""
        self.power.update()
        self._log(tr("disconnected"))

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
        self._set_ping(f"{ms} ms" if ms >= 0 else tr("ping_fail"), ACCENT if ms >= 0 else "#ff6b6b")

    # ─────────────── بروزرسانی ───────────────
    def _core_version_async(self):
        """نمایش نسخهٔ هستهٔ فعلی در برچسب"""
        try:
            v = supd.xray_version(XRAY_PATH) if supd else ""
            self.core_lbl.setText(v if v else tr("unknown"))
        except Exception:
            self.core_lbl.setText(tr("unknown"))

    def _upd_progress(self, pct, text):
        try:
            self._log(text)
        except Exception:
            pass

    def _mark_checked(self):
        try:
            self.settings["last_update_check"] = time.time()
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.settings, f)
        except OSError:
            pass

    def check_app_update(self, manual=True):
        if supd is None:
            if manual:
                QMessageBox.warning(self, tr("upd"), tr("upd_missing"))
            return
        self._upd_manual = manual
        if manual:
            self._log(tr("checking_app"))
        self.w_upd = UpdateWorker("check_app")
        self.w_upd.done.connect(self._on_check_app)
        self.w_upd.start()

    def start_app_update(self, info=None):
        if supd is None:
            QMessageBox.warning(self, tr("upd"), tr("upd_missing"))
            return
        info = info or self.pending_app_update
        if not info:
            self.check_app_update(manual=True)
            return
        self.upd_notify.hide()
        self._log(tr("dl_app", info.get("latest")))
        self.w_dl = UpdateWorker("dl_app", {"info": info})
        self.w_dl.prog.connect(self._upd_progress)
        self.w_dl.done.connect(self._on_dl_app)
        self.w_dl.start()

    def _on_check_app(self, kind, payload):
        self._mark_checked()
        if payload == "NO_MODULE":
            if self._upd_manual:
                QMessageBox.warning(self, tr("upd"), tr("upd_missing"))
            return
        if payload.startswith("ERR:"):
            if self._upd_manual:
                QMessageBox.warning(self, tr("upd"), tr("upd_fail", payload[4:]))
            return
        if not payload:
            self.pending_app_update = None
            self.upd_notify.hide()
            if self._upd_manual:
                QMessageBox.information(self, tr("upd"), tr("latest", supd.APP_VERSION))
            self._log(tr("app_current"))
            try:
                if self.about_dlg is not None:
                    self.about_dlg.refresh_notify()
            except Exception:
                pass
            return
        info = json.loads(payload)
        self.pending_app_update = info
        self.upd_notify_lbl.setText(tr("new_ready", info.get("latest")))
        self.upd_notify.show()
        self._log(tr("new_avail", info.get("latest")))
        try:
            if self.about_dlg is not None:
                self.about_dlg.refresh_notify()
        except Exception:
            pass
        if not self._upd_manual and self.settings.get("auto_update"):
            self._log(tr("auto_dl"))
            self.start_app_update(info)
        elif self._upd_manual:
            notes = (info.get("notes") or "").strip()
            msg = tr("new_q", info.get("latest"), notes)
            if QMessageBox.question(self, tr("upd_app"), msg,
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
                return
            self.start_app_update(info)

    def _on_dl_app(self, kind, path):
        if path.startswith("ERR:"):
            QMessageBox.warning(self, tr("upd"), tr("dl_fail", path[4:]))
            return
        try:
            supd.run_installer(path)
            QMessageBox.information(self, tr("upd"), tr("installer_opened"))
            self._log(tr("installer_ran", path))
        except Exception as e:
            QMessageBox.information(self, tr("upd"), tr("installer_err", path, e))

    def check_core_update(self):
        if supd is None:
            QMessageBox.warning(self, tr("upd"), tr("upd_missing"))
            return
        self._log(tr("checking_core"))
        self.w_core = UpdateWorker("check_core")
        self.w_core.done.connect(self._on_check_core)
        self.w_core.start()

    def _on_check_core(self, kind, payload):
        if payload.startswith("ERR:"):
            QMessageBox.warning(self, tr("upd"), tr("upd_fail", payload[4:]))
            return
        try:
            d = json.loads(payload)
        except Exception:
            QMessageBox.warning(self, tr("upd"), tr("upd_fail", "Invalid response"))
            return
        cur = d.get("current") or ""
        self.core_lbl.setText(cur if cur else tr("unknown"))
        info = d.get("info")
        if not info:
            QMessageBox.information(self, tr("core"), tr("core_current", (tr("core_ver", cur) if cur else "")))
            self._log(tr("app_current"))
            return
        msg = tr("core_q", info.get("version"), cur or tr("unknown"))
        if QMessageBox.question(self, tr("upd_core"), msg,
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        self.w_core2 = UpdateWorker("dl_core", {"info": info})
        self.w_core2.prog.connect(self._upd_progress)
        self.w_core2.done.connect(self._on_dl_core)
        self.w_core2.start()

    def _on_dl_core(self, kind, backup):
        if backup.startswith("ERR:"):
            QMessageBox.warning(self, tr("upd_core"), tr("core_fail", backup[4:]))
            return
        self._core_version_async()
        QMessageBox.information(self, tr("upd_core"), tr("core_ok", backup))
        self._log(tr("core_ok_log", backup))

    def _about(self):
        if self.about_dlg is None:
            self.about_dlg = AboutDialog(self)
            def _closed(_=None):
                self.about_dlg = None
            self.about_dlg.finished.connect(_closed)
        self.about_dlg.refresh_notify()
        self.about_dlg.show()
        self.about_dlg.raise_()
        self.about_dlg.activateWindow()

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
    # ریشه‌ای: AppUserModelID باید قبل از QApplication ست شود و ثابت بماند
    if os.name == "nt":
        try:
            import ctypes
            # شناسه یکتا و ثابت برای تسک‌بار — تغییر نده تا ویندوز کش را گم نکند
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("HamiSmartSystems.ScorpionVPN")
        except Exception:
            pass
    app = QApplication(sys.argv)
    app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
    app.setFont(QFont("Segoe UI", 10))
    app.setStyleSheet(STYLE)
    icon = app_icon()
    if not icon.isNull():
        app.setWindowIcon(icon)
    # اگر آیکون null بود، از PNG بساز تا تسک‌بار خالی نماند
    else:
        try:
            from PyQt6.QtGui import QPixmap
            if os.path.exists(ICON_PATH):
                app.setWindowIcon(QIcon(ICON_PATH))
        except Exception:
            pass
    win = ScorpionVPN()
    win.show()
    # بعد از show، حتماً WM_SETICON بفرست
    if os.name == "nt":
        try:
            QTimer.singleShot(150, win._apply_taskbar_icon)
            QTimer.singleShot(600, win._apply_taskbar_icon)
        except Exception:
            pass
    sys.exit(app.exec())
