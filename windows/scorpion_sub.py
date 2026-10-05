# -*- coding: utf-8 -*-
"""
منطق سابسکریپشن Scorpion VPN (ویندوز) — بدون وابستگی به Qt تا مستقل تست شود.

  - config_key: هویت پایدار یک کانفیگ (صرف‌نظر از نام/فرگمنت و پارامترها) تا
    رفرش سابسکریپشن همان کانفیگ را جایگزین کند نه اینکه یکی جدید بسازد.
  - merge_subscription: ادغام خروجی تازهٔ ساب با فهرست فعلی کانفیگ‌ها:
    جایگزینیِ درجا بر اساس کلید، افزودن کلیدهای جدید، حذف کلیدهای ناپدیدشده؛
    کانفیگ‌های دستی کاربر دست‌نخورده می‌مانند.
"""
import hashlib


def config_key(plain, parse_uri):
    """کلید پایدار کانفیگ: «پروتکل://شناسه@میزبان:پورت».

    fragment (نام نمایشی) و پارامترهای کوئری (sni، path، …) عمداً در کلید
    نمی‌آیند تا تغییر نام یا تنظیمات سمت سرور، کانفیگ را «جدید» نکند.
    چون parse_uri از خود اپ به ما داده می‌شود، با هر قالبی که اپ بفهمد کار
    می‌کند و در هر خطا یک اثر انگشت از کل رشته برمی‌گردانیم.
    """
    try:
        scheme, _frag, d = parse_uri(plain)
    except Exception:
        return "raw:" + hashlib.sha256(plain.encode("utf-8", "ignore")).hexdigest()[:16]
    scheme = scheme.lower()
    if scheme == "vless":
        ident = d.get("uuid") or ""
    elif scheme == "trojan":
        ident = d.get("password") or ""
    elif scheme == "ss":
        ident = "%s:%s" % (d.get("method", ""), d.get("password", ""))
    elif scheme == "vmess":
        ident = d.get("uuid") or ""
    else:
        ident = ""
    return "%s://%s@%s:%s" % (scheme, ident, d.get("host", ""), d.get("port", 0))


def merge_subscription(configs, valid, keys, key_of):
    """ادغام خروجی تازهٔ یک سابسکریپشن با فهرست کانفیگ‌های فعلی.

    configs  : فهرست فعلی همهٔ کانفیگ‌ها (ساب‌ها + دستی)
    valid    : خطوط معتبر تازهٔ این ساب (به ترتیب فید)
    keys     : کلیدهای ثبت‌شدهٔ این ساب از رفرش قبل
    key_of   : تابع ساخت کلید از روی uri

    خروجی: (configs تازه، keys تازه، {"replaced","added","removed"})
    """
    old = [k for k in (keys or []) if k]

    # کلید تازهٔ هر خط فید (به ترتیب فید)
    new_keys = []
    for u in valid:
        try:
            new_keys.append(key_of(u))
        except Exception:
            new_keys.append(None)
    feed = {k: u for u, k in zip(valid, new_keys) if k}      # اولین تکرارِ هر کلید می‌ماند
    new_set = set(feed)

    stats = {"replaced": 0, "added": 0, "removed": 0}

    # ۱) کانفیگ‌های متعلق به این ساب که دیگر در فید نیستند → حذف
    out = []
    for c in configs:
        try:
            kc = key_of(c)
        except Exception:
            kc = None
        if kc in old and kc not in new_set:
            stats["removed"] += 1
            continue
        out.append(c)

    # ۲) جایگزینی درجا: هر کانفیگ موجود که کلیدش در فید است با نسخهٔ تازه عوض می‌شود
    for i, c in enumerate(out):
        try:
            kc = key_of(c)
        except Exception:
            kc = None
        if kc in feed:
            out[i] = feed[kc]
            stats["replaced"] += 1

    # ۳) کلیدهای تازهٔ فید (که در فهرست نیستند) به ترتیب فید اضافه می‌شوند
    have = set()
    for c in out:
        try:
            have.add(key_of(c))
        except Exception:
            pass
    for u, k in zip(valid, new_keys):
        if not k or k in have:
            continue
        out.append(u)
        have.add(k)
        stats["added"] += 1

    return out, list(feed), stats
