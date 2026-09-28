# -*- coding: utf-8 -*-
"""
Scorpion Config — قالب اختصاصی کانفیگ VPN
کانفیگ‌های واقعی (vless/vmess/reality/…) داخل یک پاکت رمزنگاری‌شده‌ی AES-GCM
با کلید مشترکِ فقط-مخصوص-اپ‌های-ما پیچیده می‌شوند و با پیشوند scorpion:// منتشر می‌شوند.

نتیجه:
  * اپ‌های متفرقه پیشوند scorpion:// را نمی‌شناسند → نمی‌توانند اجرا کنند.
  * فقط Scorpion VPN و بخش VPN هانتر (که کلید را دارند) باز و اجرا می‌کنند.

وابستگی: pip install cryptography
استفاده (تولید کانفیگ توسط خودتان):
    python scorpion_config.py "vless://...."        → خروجی scorpion://...
"""
import os, sys, base64, hashlib

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False

MAGIC = "scorpion://v1."

# 🔑 کلید مشترک — داخل همه‌ی اپ‌های ما (Scorpion VPN + هانتر) یکسان است.
# اگر روزی لو رفت، فقط با تغییر این و بازتولید اپ‌ها کانفیگ‌های قدیمی باطل می‌شوند.
SECRET = b"HSS-SCORPION-VPN-2026-SECRET"


def _key() -> bytes:
    return hashlib.sha256(SECRET).digest()


def is_scorpion(uri: str) -> bool:
    return isinstance(uri, str) and uri.strip().startswith(MAGIC)


def encode(plain: str) -> str:
    """کانفیگ معمولی → کانفیگ اختصاصی scorpion://"""
    if not HAS_CRYPTO:
        raise RuntimeError("pip install cryptography")
    plain = plain.strip()
    if not plain:
        raise ValueError("کانفیگ خالی است")
    nonce = os.urandom(12)
    ct = AESGCM(_key()).encrypt(nonce, plain.encode("utf-8"), None)
    return MAGIC + base64.urlsafe_b64encode(nonce + ct).decode()


def decode(uri: str) -> str:
    """کانفیگ scorpion:// → کانفیگ معمولی. اگر کلید/امضا غلط باشد، exception."""
    uri = uri.strip()
    if not is_scorpion(uri):
        raise ValueError("این یک کانفیگ Scorpion نیست")
    raw = base64.urlsafe_b64decode(uri[len(MAGIC):])
    if len(raw) < 13:
        raise ValueError("قالب نامعتبر")
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(_key()).decrypt(nonce, ct, None).decode("utf-8")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("کاربرد:  python scorpion_config.py \"<کانفیگ معمولی>\"")
        sys.exit(1)
    print(encode(sys.argv[1]))
