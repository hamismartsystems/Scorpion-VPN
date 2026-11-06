"""Per-application routing rules for the Windows TUN mode (sing-box).

Pure logic, no Qt and no OS calls, so it can be tested on any machine.

Behaviour:
  * the VPN core (xray.exe) ALWAYS goes DIRECT. Its own connection to the VPN
    server must not be captured by the TUN, otherwise it loops back into itself.
  * apps in the exclusion list go DIRECT (not through the VPN),
  * everything else goes through the VPN outbound (the local Xray SOCKS port).
"""

import json
import ntpath
import re

MAX_APPS = 200
# A Windows executable name: letters, digits, space, dot, dash, underscore,
# plus parentheses. No path separators, so a user cannot point the rule at
# a folder or inject anything into the config.
_EXE_RE = re.compile(r"^[A-Za-z0-9 ._()\-]{1,120}\.exe$")

TUN_NAME = "ScorpionTUN"
TUN_ADDRESS = "172.19.0.1/30"

# Processes that must never be captured by the TUN (always direct).
CORE_PROCESSES = ["xray.exe"]


class RuleError(ValueError):
    pass


def normalize_apps(apps):
    """Return a sorted, de-duplicated list of lower-case executable names.

    Raises RuleError for anything that is not a plain .exe file name.
    """
    if apps is None:
        return []
    if not isinstance(apps, (list, tuple)):
        raise RuleError("the app list must be a list")
    out = set()
    for raw in apps:
        if not isinstance(raw, str):
            raise RuleError("every app name must be a string")
        name = raw.strip()
        if not _EXE_RE.match(name):
            raise RuleError(f"not a plain .exe file name: {raw!r}")
        out.add(name.lower())
    if len(out) > MAX_APPS:
        raise RuleError(f"too many apps (max {MAX_APPS})")
    return sorted(out)


def build_singbox_config(apps, socks_port, *, tun_name=TUN_NAME):
    """Build a sing-box config dict for TUN mode with per-app bypass."""
    if not isinstance(socks_port, int) or not (1 <= socks_port <= 65535):
        raise RuleError("socks_port must be an integer in 1..65535")
    excluded = normalize_apps(apps)

    rules = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"process_name": list(CORE_PROCESSES), "outbound": "direct"},
    ]
    if excluded:
        rules.append({"process_name": excluded, "outbound": "direct"})

    return {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": tun_name,
                "address": [TUN_ADDRESS],
                "auto_route": True,
                "strict_route": True,
                "stack": "system",
            }
        ],
        "outbounds": [
            {
                "type": "socks",
                "tag": "vpn",
                "server": "127.0.0.1",
                "server_port": socks_port,
            },
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": rules,
            "final": "vpn",
            "auto_detect_interface": True,
        },
    }


def config_to_json(apps, socks_port):
    return json.dumps(build_singbox_config(apps, socks_port), ensure_ascii=False, indent=2)


def add_apps(current, new_names):
    """Return the normalized list with new_names added (no duplicates)."""
    return normalize_apps(list(current or []) + list(new_names or []))


def remove_app(current, name):
    """Return the normalized list without `name` (case-insensitive)."""
    target = (name or "").strip().lower()
    return [a for a in normalize_apps(current or []) if a != target]


# ---- app rules: each entry {"name": "x.exe", "path": "C:\\...\\x.exe" or "", "enabled": bool} ----

def rules_from_settings(settings):
    """Return the app rules. Migrates the old 'excluded_apps' name list."""
    rules = settings.get("app_rules")
    if isinstance(rules, list):
        return [
            {"name": r["name"], "path": str(r.get("path", "") or ""), "enabled": bool(r.get("enabled", True))}
            for r in rules if isinstance(r, dict) and isinstance(r.get("name"), str)
        ]
    old = settings.get("excluded_apps") or []
    return [{"name": n, "path": "", "enabled": True} for n in normalize_apps(old)]


def enabled_names(rules):
    """Names that bypass the VPN (enabled rules only)."""
    return normalize_apps([r["name"] for r in rules if r.get("enabled", True)])


def add_rule(rules, file_path, path=""):
    """Add an app (name taken from the file name). Existing app is re-enabled."""
    name = normalize_apps([ntpath.basename(file_path)])[0]
    out = [dict(r) for r in rules]
    for r in out:
        if r["name"] == name:
            r["enabled"] = True
            if path:
                r["path"] = path
            return out
    if len(out) >= MAX_APPS:
        raise RuleError(f"too many apps (max {MAX_APPS})")
    out.append({"name": name, "path": path or "", "enabled": True})
    return sorted(out, key=lambda r: r["name"])


def set_enabled(rules, name, enabled):
    target = (name or "").strip().lower()
    return [dict(r, enabled=bool(enabled)) if r["name"] == target else dict(r) for r in rules]


def delete_rule(rules, name):
    target = (name or "").strip().lower()
    return [dict(r) for r in rules if r["name"] != target]
