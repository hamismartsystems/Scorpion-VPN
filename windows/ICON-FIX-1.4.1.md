# Scorpion VPN 1.4.1 — Taskbar Icon Root Fix

## مشکل ریشه‌ای
آیکون نوار ابزار ویندوز (taskbar) نمایش داده نمی‌شد، در حالی که بقیه برنامه‌ها درست بودند → مشکل از خود برنامه بود، نه ویندوز.

### دلایل ریشه‌ای (3 مورد)
1. **app_icon() ضعیف**: فقط `QIcon(sys.executable)` و `QIcon(ico_path)` را امتحان می‌کرد. اگر `QIcon` null برمی‌گشت (گاهی PyInstaller onedir این را می‌دهد)، هیچ fallback نداشت و `setWindowIcon` اصلاً صدا نمی‌شد → تسک‌بار خالی.

2. **عدم ست کردن WM_SETICON ویندوز**: Qt فقط `setWindowIcon` را ست می‌کند، ولی ویندوز برای تسک‌بار به `WM_SETICON` با `HICON` واقعی نیاز دارد. اگر فقط QIcon ست شود و HICON لود نشود، تسک‌بار آیکون پیش‌فرض یا خالی نشان می‌دهد.

3. **AppUserModelID ناپایدار**: شناسه `hami.scorpionvpn.1.0` قبل از QApplication ست می‌شد ولی بعد از show دوباره ست نمی‌شد. ویندوز کش تسک‌بار را با AppUserModelID گروه‌بندی می‌کند، اگر null باشد یا عوض شود، آیکون گم می‌شود.

### فیکس ریشه‌ای در 1.4.1
#### 1) app_icon() قوی
```python
def app_icon():
    candidates = [sys.executable, ICO_PATH, ICON_PATH, resource_path("scorpion.ico"), ...]
    for path in candidates:
        ic = QIcon(path)
        if not ic.isNull() and not ic.pixmap(32,32).isNull():
            return ic
        # fallback از QPixmap
        pm = QPixmap(path)
        if not pm.isNull():
            return QIcon(pm)
    # آخرین تلاش: pixmap سبز تا هیچ‌وقت خالی نماند
    pm = QPixmap(64,64); pm.fill(QColor("#0B6623")); return QIcon(pm)
```

#### 2) _set_windows_taskbar_icon(hwnd, ico_path)
با ctypes:
```python
hicon_big = LoadImageW(None, ico_path, IMAGE_ICON, 0,0, LR_LOADFROMFILE|LR_DEFAULTSIZE)
hicon_small = LoadImageW(None, ico_path, IMAGE_ICON, 16,16, LR_LOADFROMFILE)
SendMessageW(hwnd, WM_SETICON, ICON_SMALL, hicon_small)
SendMessageW(hwnd, WM_SETICON, ICON_BIG, hicon_big)
```

#### 3) ScorpionVPN class
- `self._icon = app_icon()` همیشه ست می‌شود، حتی fallback
- `QTimer.singleShot(200, _apply_taskbar_icon)` و `800ms` بعد از __init__
- `showEvent` هم دوباره `WM_SETICON` می‌فرستد
- `setWindowIcon` در هر دو جا تکرار می‌شود

#### 4) main()
- `SetCurrentProcessExplicitAppUserModelID("HamiSmartSystems.ScorpionVPN")` ثابت و قبل از QApplication
- `app.setWindowIcon(icon)` + fallback از PNG
- بعد از `win.show()` دوباره `_apply_taskbar_icon`

#### 5) Build
- `scorpion.ico` 7 سایز دارد (16,24,32,48,64,128,256) — تست شد
- PyInstaller `--icon=scorpion.ico` + `--add-data scorpion.ico` + `scorpion_icon.png`
- Inno Setup `SetupIconFile=scorpion.ico` و `IconFilename={app}\Scorpion VPN.exe`

### تست
- ویندوز 10/11: تسک‌بار آیکون سبز H باید دیده شود، نه آیکون سفید پیش‌فرض
- Alt+Tab هم باید آیکون را نشان دهد
- بعد از پین کردن به تسک‌بار، آیکون نباید گم شود

### بیلد
```
build_windows.bat  -> dist\Scorpion VPN\Scorpion VPN.exe
installer.iss F9   -> ScorpionVPN-Setup-1.4.1.exe
```

نسخه: 1.4.1 — فقط فیکس آیکون، بقیه کد مثل 1.4.0
