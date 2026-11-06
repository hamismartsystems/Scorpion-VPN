import json
import unittest

from scorpion_tun_rules import (
    CORE_PROCESSES,
    RuleError,
    build_singbox_config,
    add_apps,
    add_rule,
    delete_rule,
    enabled_names,
    normalize_apps,
    remove_app,
    rules_from_settings,
    set_enabled,
    TUN_NAME,
)


def _direct_rules(cfg):
    return [r for r in cfg["route"]["rules"] if r.get("outbound") == "direct"]


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
    def test_core_process_always_direct(self):
        cfg = build_singbox_config([], 10808)
        direct = _direct_rules(cfg)
        self.assertEqual(direct, [{"process_name": list(CORE_PROCESSES), "outbound": "direct"}])
        self.assertIn("xray.exe", CORE_PROCESSES)

    def test_default_only_core_process_rule(self):
        cfg = build_singbox_config([], 10808)
        process_rules = [r for r in cfg["route"]["rules"] if "process_name" in r]
        self.assertEqual(process_rules, [{"process_name": ["xray.exe"], "outbound": "direct"}])
        self.assertEqual(cfg["route"]["final"], "vpn")

    def test_excluded_apps_go_direct(self):
        cfg = build_singbox_config(["Telegram.exe"], 10808)
        direct = _direct_rules(cfg)
        self.assertIn({"process_name": ["telegram.exe"], "outbound": "direct"}, direct)
        self.assertIn({"process_name": ["xray.exe"], "outbound": "direct"}, direct)
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


class AddRemoveTests(unittest.TestCase):
    def test_add_keeps_existing_and_dedupes(self):
        self.assertEqual(add_apps(["steam.exe"], ["Telegram.exe", "steam.exe"]),
                         ["steam.exe", "telegram.exe"])

    def test_add_to_empty(self):
        self.assertEqual(add_apps(None, ["a.exe"]), ["a.exe"])

    def test_add_rejects_bad_name(self):
        with self.assertRaises(RuleError):
            add_apps(["a.exe"], ["C:\\x\\b.exe"])

    def test_remove_only_selected_app(self):
        self.assertEqual(remove_app(["a.exe", "b.exe", "c.exe"], "B.EXE"), ["a.exe", "c.exe"])

    def test_remove_missing_app_keeps_list(self):
        self.assertEqual(remove_app(["a.exe"], "zzz.exe"), ["a.exe"])

    def test_remove_from_empty(self):
        self.assertEqual(remove_app([], "a.exe"), [])


class AppRuleTests(unittest.TestCase):
    def test_migrates_old_name_list(self):
        rules = rules_from_settings({"excluded_apps": ["telegram.exe", "Steam.exe"]})
        self.assertEqual([r["name"] for r in rules], ["steam.exe", "telegram.exe"])
        self.assertTrue(all(r["enabled"] for r in rules))

    def test_new_format_wins_over_old(self):
        rules = rules_from_settings({"app_rules": [{"name": "a.exe", "path": "C:\\x\\a.exe", "enabled": False}],
                                     "excluded_apps": ["b.exe"]})
        self.assertEqual(rules, [{"name": "a.exe", "path": "C:\\x\\a.exe", "enabled": False}])

    def test_disabled_rule_not_in_enabled_names(self):
        rules = [{"name": "a.exe", "path": "", "enabled": True}, {"name": "b.exe", "path": "", "enabled": False}]
        self.assertEqual(enabled_names(rules), ["a.exe"])

    def test_add_rule_sets_name_and_path_and_dedupes(self):
        rules = add_rule([], "C:\\Apps\\Discord.exe", path="C:\\Apps\\Discord.exe")
        rules = add_rule(rules, "C:\\Other\\discord.exe", path="C:\\Other\\discord.exe")
        self.assertEqual(rules, [{"name": "discord.exe", "path": "C:\\Other\\discord.exe", "enabled": True}])

    def test_add_rule_rejects_non_exe(self):
        with self.assertRaises(RuleError):
            add_rule([], "C:\\Apps\\readme.txt")

    def test_set_enabled_only_changes_one(self):
        rules = [{"name": "a.exe", "path": "", "enabled": True}, {"name": "b.exe", "path": "", "enabled": True}]
        out = set_enabled(rules, "b.exe", False)
        self.assertEqual(out[0]["enabled"], True)
        self.assertEqual(out[1]["enabled"], False)

    def test_delete_rule_removes_only_that_app(self):
        rules = [{"name": "a.exe", "path": "", "enabled": True}, {"name": "b.exe", "path": "", "enabled": True}]
        self.assertEqual([r["name"] for r in delete_rule(rules, "A.EXE")], ["b.exe"])


if __name__ == "__main__":
    unittest.main()
