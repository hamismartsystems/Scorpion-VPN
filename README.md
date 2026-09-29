<div dir="rtl">

# 🦂 Scorpion VPN

کلاینت VPN اختصاصی **HAMI SMART SYSTEMS / حامی دیزاینز** — برای ویندوز، اندروید، مک و لینوکس. بر پایه هسته‌های **Xray** و **sing-box**، با پشتیبانی کامل از پروتکل‌های روز:

**VLESS / VMess / Trojan / Shadowsocks / Hysteria2 / TUIC / AnyTLS + Reality / XHTTP / gRPC / HTTPUpgrade**

## ⬇️ دانلود

- صفحهٔ دانلود فارسی سایت: **[hamidesigns.shop/apps](https://hamidesigns.shop/apps/)**
- ریلیزها: **[GitHub Releases](https://github.com/hamismartsystems/Scorpion-VPN/releases/latest)**

| پلتفرم | فایل | نسخه |
|---|---|---|
| 🪟 ویندوز | `ScorpionVPN-Setup-1.4.0.exe` (نصب‌کننده) | 1.4.0 ✅ |
| 🤖 اندروید | [`ScorpionVPN-1.4.3-arm64-v8a.apk`](https://github.com/hamismartsystems/Scorpion-VPN/releases/download/v1.4.3/ScorpionVPN-1.4.3-arm64-v8a.apk) | 1.4.3 ✅ |
| 🍎 مک | `ScorpionVPN-macOS-1.3.3.zip` (بتا — Python 3.10+) | 1.3.3 ✅ |
| 🐧 لینوکس | `ScorpionVPN-Linux-1.3.3.tar.gz` (Python 3.10+) | 1.3.3 ✅ |
| 📱 iOS | — | 🛠 به‌زودی |

> به‌روزرسانی خودکار اپ اندروید به همین ریپو متصل می‌شود — ریلیز جدید = پیشنهاد آپدیت داخل اپ.

## ✨ ویژگی‌ها

- 🌐 **پشتیبانی کامل از پروتکل‌های استاندارد** — VLESS، VMess، Trojan، Shadowsocks، Hysteria2، TUIC، AnyTLS
- ⚡ **دو هسته:** Xray (Reality، XHTTP، gRPC) + sing-box (QUIC، Hysteria2، TUIC)
- 🔒 **اینباند خصوصی (ادمین-فقط) با Hami Panel** — به‌جای دستکاری لینک ساب، اینباند اختصاصی با `is_private` ساخته می‌شود؛ از توزیع خودکار حذف و فقط برای کلاینت‌های همان اینباند سرو می‌شود. امن، سمت سرور.
- 🎨 رابط حرفه‌ای با تم اختصاصی و آیکون برند
- 🖥 ویندوز: نصب‌کننده با آیکون تسک‌بار، تایتل‌بار و شورتکات‌ها
- 🤖 اندروید: فورک تخصصی v2rayNG (GPL-3.0) + بهینه‌سازی‌های Scorpion
- 🔄 ساب چندقالبه: v2ray base64، Clash/Mihomo YAML، sing-box JSON، Shadowrocket

### درباره فرمت قدیمی `scorpion://`

نسخه‌های قبلی یک لایه رمزنگاری کلاینت-ساید (`scorpion://v1.` + AES-GCM) داشتند. این فرمت هنوز برای سازگاری با نسخه‌های قدیمی باز می‌شود، اما **برای امنیت جدید توصیه نمی‌شود** — چون کلید داخل اپ است و قابل استخراج است. برای کانفیگ اختصاصی واقعی از قابلیت **Private Inbound** در **HP-UI / Hami Panel** استفاده کنید (`hami inbound add --private`).

ساخت کانفیگ قدیمی (فقط برای سازگاری): `python windows/scorpion_config.py "vless://..."`

## 🛠 سورس و پنل

- **اندروید:** همین ریپازیتوری — فورک v2rayNG + لایه Scorpion
- **ویندوز/مک/لینوکس:** پوشه [`windows/`](windows) — پایتون + PyInstaller + Inno Setup
- **پنل مدیریت:** **[Hami Panel (HP-UI)](https://github.com/hamismartsystems/Hami_panel)** — پنل Go با GPL-3.0، مدیریت اینباند، کاربر، ساب، نود، sing-box، اینباند خصوصی، Reality check، قالب‌ها

## 📄 پروانه

بخش‌های مبتنی بر v2rayNG تحت **GPL-3.0**. لایه Scorpion متعلق به HAMI SMART SYSTEMS است.

---

🏠 [hamidesigns.shop](https://hamidesigns.shop) — HAMI SMART SYSTEMS

</div>
