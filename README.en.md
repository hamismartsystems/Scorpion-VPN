# 🦂 Scorpion VPN

The official VPN client of **HAMI SMART SYSTEMS / Hami Designs** — for Windows, Android, macOS and Linux. Built on the **Xray** and **sing-box** cores, with full support for modern protocols:

**VLESS / VMess / Trojan / Shadowsocks / Hysteria2 / TUIC / AnyTLS + Reality / XHTTP / gRPC / HTTPUpgrade**

[فارسی](README.md)

## ⬇️ Download

- Persian download page: **[hamidesigns.shop/apps](https://hamidesigns.shop/apps/)**
- Releases: **[GitHub Releases](https://github.com/hamismartsystems/Scorpion-VPN/releases/latest)**

| Platform | File | Version |
|---|---|---|
| 🪟 Windows | `ScorpionVPN-Setup-1.4.0.exe` (installer) | 1.4.0 ✅ |
| 🤖 Android | [`ScorpionVPN-1.4.3-arm64-v8a.apk`](https://github.com/hamismartsystems/Scorpion-VPN/releases/download/v1.4.3/ScorpionVPN-1.4.3-arm64-v8a.apk) | 1.4.3 ✅ |
| 🍎 macOS | `ScorpionVPN-macOS-1.3.3.zip` (beta — Python 3.10+) | 1.3.3 ✅ |
| 🐧 Linux | `ScorpionVPN-Linux-1.3.3.tar.gz` (Python 3.10+) | 1.3.3 ✅ |
| 📱 iOS | — | 🛠 soon |

> The Android app's auto-update checks this repository — a new release here means an in-app update prompt.

## ✨ Features

- 🌐 **Full support for standard protocols** — VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS
- ⚡ **Two cores:** Xray (Reality, XHTTP, gRPC) + sing-box (QUIC, Hysteria2, TUIC)
- 🔒 **Private inbounds (admin-only) with Hami Panel** — instead of hand-editing sub links, a dedicated inbound is created with `is_private`, excluded from mass distribution and served only to that inbound's own clients. Secure, server-side.
- 🎨 Professional UI with a custom theme and branded icon
- 🖥 Windows: installer with taskbar icon, title bar and shortcuts
- 🤖 Android: dedicated fork of v2rayNG (GPL-3.0) + Scorpion's optimizations
- 🔄 Multi-format subscription: v2ray base64, Clash/Mihomo YAML, sing-box JSON, Shadowrocket

### About the legacy `scorpion://` format

Older releases used a client-side encryption layer (`scorpion://v1.` + AES-GCM). That format is still opened for backwards compatibility, but it is **not recommended for new security setups** — the key ships inside the app and can be extracted. For genuinely private configs use the **Private Inbound** feature in **HP-UI / Hami Panel** (`hami inbound add --private`).

Build a legacy config (compatibility only): `python windows/scorpion_config.py "vless://..."`

## 🛠 Source & panel

- **Android:** this repository — v2rayNG fork + the Scorpion layer
- **Windows/macOS/Linux:** folder [`windows/`](windows) — Python + PyInstaller + Inno Setup
- **Management panel:** **[Hami Panel (HP-UI)](https://github.com/hamismartsystems/Hami_panel)** — GPL-3.0 Go panel: inbound, user, subscription, node and sing-box management, private inbounds, Reality check, templates

## 📄 License

The parts based on v2rayNG are under **GPL-3.0**. The Scorpion layer belongs to HAMI SMART SYSTEMS.

---

🏠 [hamidesigns.shop](https://hamidesigns.shop) — HAMI SMART SYSTEMS
