import json
import unittest

from scorpion_tun_rules import (
    RuleError,
    build_singbox_config,
    normalize_apps,
    TUN_NAME,
)


class NormalizeAppsTests(unittest.TestCase):
    def test_lowercases_sorts_and_dedupes(self):
        self.assertEqual(
            normalize_apps(["Chrome.exe", "chrome.exe", "Steam.exe"]),
            ["chrome.exe", "steam.exe"],
        )

    def test_empty_and_none_mean_no_exclusions(self):
        self.assertEqual(normalize_apps([]), [])
        self.assertEqual(normalize_apps(None), [])

    def test_rejects_paths(self):
        for bad in ["C:\\Games\\a.exe", "..\\a.exe", "dir/a.exe", "/usr/bin/a.exe"]:
            with self.assertRaises(RuleError, msg=bad):
                normalize_apps([bad])

    def test_rejects_non_exe_and_injection(self):
        for bad in ["a.dll", "a", "a.exe; rm -rf /", '"a".exe', "a\n.exe", ""]:
            with self.assertRaises(RuleError, msg=repr(bad)):
                normalize_apps([bad])

    def test_rejects_non_string_and_non_list(self):
        with self.assertRaises(RuleError):
            normalize_apps([123])
        with self.assertRaises(RuleError):
            normalize_apps("chrome.exe")

    def test_too_many_apps(self):
        with self.assertRaises(RuleError):
            normalize_apps([f"app{i}.exe" for i in range(201)])


class BuildConfigTests(unittest.TestCase):
    def test_default_all_through_vpn_without_process_rule(self):
        cfg = build_singbox_config([], 10808)
        rules = cfg["route"]["rules"]
        self.assertFalse(any("process_name" in r for r in rules))
        self.assertEqual(cfg["route"]["final"], "vpn")

    def test_excluded_apps_go_direct(self):
        cfg = build_singbox_config(["Telegram.exe"], 10808)
        direct = [r for r in cfg["route"]["rules"] if r.get("outbound") == "direct"]
        self.assertEqual(direct, [{"process_name": ["telegram.exe"], "outbound": "direct"}])
        self.assertEqual(cfg["route"]["final"], "vpn")

    def test_vpn_outbound_points_to_local_socks(self):
        cfg = build_singbox_config([], 10808)
        vpn = next(o for o in cfg["outbounds"] if o["tag"] == "vpn")
        self.assertEqual(vpn, {"type": "socks", "tag": "vpn", "server": "127.0.0.1", "server_port": 10808})

    def test_tun_inbound(self):
        cfg = build_singbox_config([], 10808)
        tun = cfg["inbounds"][0]
        self.assertEqual(tun["type"], "tun")
        self.assertEqual(tun["interface_name"], TUN_NAME)
        self.assertTrue(tun["auto_route"])

    def test_bad_port_rejected(self):
        for bad in [0, 65536, "10808", None]:
            with self.assertRaises(RuleError, msg=repr(bad)):
                build_singbox_config([], bad)

    def test_output_is_valid_json(self):
        cfg = build_singbox_config(["a.exe"], 10808)
        self.assertEqual(json.loads(json.dumps(cfg)), cfg)


if __name__ == "__main__":
    unittest.main()
