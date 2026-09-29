# -*- coding: utf-8 -*-
"""
منطق بروزرسانی Scorpion VPN (ویندوز) — بدون وابستگی به Qt تا بشود مستقل تستش کرد.

دو قابلیت مستقل:
  ۱) بروزرسانی خود برنامه (دانلود فایل نصبی از سایت پشتیبانی و اجرای آن)
  ۲) بروزرسانی هستهٔ Xray (جایگزینی xray.exe + geoip.dat + geosite.dat — با پشتیبان‌گیری)
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request

SITE = "https://hamidesigns.shop"
MANIFEST_URL = SITE + "/apps/update.json"
APP_VERSION = "1.4.1"
USER_AGENT = "ScorpionVPN-Windows"


# ─────────────────────────── مانیفست ───────────────────────────

def fetch_manifest(url=MANIFEST_URL, timeout=20):
    """دریافت مانیفست بروزرسانی از سایت. در صورت خطا استثنا می‌دهد."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", "replace")
    return json.loads(raw.lstrip("\ufeff"))


def cmp_version(a, b):
    """۱ اگر a بزرگ‌تر از b، ۰ مساوی، ‏-۱ کوچک‌تر"""
    def parts(v):
        return [int(x) if x.isdigit() else 0 for x in re.split(r"[.\-+]", str(v or "0")) if x != ""]
    pa, pb = parts(a), parts(b)
    for i in range(max(len(pa), len(pb))):
        x = pa[i] if i < len(pa) else 0
        y = pb[i] if i < len(pb) else 0
        if x != y:
            return 1 if x > y else -1
    return 0


def app_update(manifest, current=APP_VERSION):
    """اطلاعات نسخهٔ جدید برنامه (یا None اگر به‌روز باشیم)"""
    info = (manifest or {}).get("apps", {}).get("windows")
    if not info:
        return None
    latest = str(info.get("latest", ""))
    if not latest or cmp_version(latest, current) <= 0:
        return None
    return info


def core_update(manifest, current_core):
    """اطلاعات هستهٔ جدید ویندوز (یا None)"""
    info = (manifest or {}).get("coreWindows")
    if not info:
        return None
    latest = str(info.get("version", ""))
    if not latest:
        return None
    if current_core and cmp_version(latest, current_core) <= 0:
        return None
    return info


# ─────────────────────────── نسخهٔ هستهٔ محلی ───────────────────────────

def xray_version(xray_path):
    """نسخهٔ xray.exe نصب‌شده — مثلاً '26.3.27'"""
    try:
        out = subprocess.run([xray_path, "version"], capture_output=True, text=True, timeout=20)
        txt = (out.stdout or "") + (out.stderr or "")
        m = re.search(r"[Xx]ray\s+([0-9][0-9A-Za-z.\-]*)", txt)
        if m:
            return m.group(1)
        m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", txt)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


# ─────────────────────────── دانلود ───────────────────────────

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url, dest, progress=None, expected_sha256=""):
    """
    دانلود فایل از url به dest.
    progress: تابعی مثل fn(percent, done, total) که اختیاری است.
    در صورت تعیین expected_sha256، صحت فایل بررسی می‌شود.
    """
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    tmp = dest + ".part"
    try:
        with urllib.request.urlopen(req, timeout=60) as resp, open(tmp, "wb") as out:
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            last = -1
            while True:
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                done += len(chunk)
                if progress and total:
                    pct = int(done * 100 / total)
                    if pct != last:
                        last = pct
                        progress(pct, done, total)
        if expected_sha256:
            actual = sha256_file(tmp)
            if actual.lower() != expected_sha256.lower():
                os.remove(tmp)
                raise ValueError("فایل دانلودشده سالم نیست (هش مطابقت ندارد)")
        if os.path.exists(dest):
            os.remove(dest)
        os.rename(tmp, dest)
        return True
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


# ─────────────────────────── نصب هسته ───────────────────────────

CORE_FILES = ("xray.exe", "geoip.dat", "geosite.dat")


def install_core(zip_path, app_dir, progress=None):
    """
    جایگزینی هستهٔ Xray از فایل زیپ دانلودشده.
    فایل‌های فعلی در پوشهٔ core_backup با تاریخ نگه داشته می‌شوند.
    """
    import zipfile
    import time

    staging = tempfile.mkdtemp(prefix="scorpion_core_")
    try:
        with zipfile.ZipFile(zip_path) as z:
            names = z.namelist()
            picked = {}
            for want in CORE_FILES:
                hit = next((n for n in names if os.path.basename(n).lower() == want), None)
                if hit:
                    picked[want] = hit
            if "xray.exe" not in picked:
                raise ValueError("فایل هسته (xray.exe) داخل بسته پیدا نشد")
            for want, member in picked.items():
                with z.open(member) as src, open(os.path.join(staging, want), "wb") as dst:
                    shutil.copyfileobj(src, dst)
                if progress:
                    progress(want)

        backup = os.path.join(app_dir, "core_backup", time.strftime("%Y%m%d-%H%M%S"))
        os.makedirs(backup, exist_ok=True)
        for name in CORE_FILES:
            cur = os.path.join(app_dir, name)
            if os.path.exists(cur):
                try:
                    shutil.copy2(cur, os.path.join(backup, name))
                except OSError:
                    pass

        for name in CORE_FILES:
            new = os.path.join(staging, name)
            if os.path.exists(new):
                shutil.copy2(new, os.path.join(app_dir, name))
        return backup
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def download_and_install_core(info, app_dir, progress=None):
    """دانلود و نصب هستهٔ جدید ویندوز"""
    url = info.get("url", "")
    tmp_zip = os.path.join(tempfile.gettempdir(), "scorpion-core-win.zip")
    download(url, tmp_zip, progress=progress, expected_sha256=info.get("sha256", ""))
    try:
        return install_core(tmp_zip, app_dir)
    finally:
        try:
            os.remove(tmp_zip)
        except OSError:
            pass


# ─────────────────────────── نصب برنامه ───────────────────────────

def download_installer(info, progress=None):
    """دانلود فایل نصبی نسخهٔ جدید و بازگرداندن مسیر آن (اجرای نصب با فراخوان)"""
    url = info.get("url", "")
    name = os.path.basename(url.split("?")[0]) or "ScorpionVPN-Setup.exe"
    dest = os.path.join(tempfile.gettempdir(), name)
    download(url, dest, progress=progress, expected_sha256=info.get("sha256", ""))
    return dest


def run_installer(path):
    """اجرای فایل نصبی (ویندوز)"""
    if os.name == "nt":
        os.startfile(path)  # noqa: S606
    else:
        subprocess.Popen([path])


if __name__ == "__main__":
    # تست سریع خط فرمان: python scorpion_update.py
    m = fetch_manifest()
    print("مانیفست دریافت شد ✅")
    print("نسخهٔ ویندوز در سایت:", m.get("apps", {}).get("windows", {}).get("latest"))
    print("نسخهٔ هستهٔ اندروید در سایت:", m.get("core", {}).get("version"))
    up = app_update(m)
    print("بروزرسانی برنامه:", "نسخهٔ " + up["latest"] if up else "به‌روز است")
