import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("ZTP_DEV", "1")
import app


class StabilizationTests(unittest.TestCase):
    """Focused acceptance tests for the active/pending and protected runtime model."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.old = {name: getattr(app, name) for name in (
            "DATA_DIR", "NGINX_DIR", "UPLOAD_DIR", "DEVICES_JSON", "STATIC_MAPPINGS_JSON",
            "PROFILES_JSON", "SETTINGS_JSON", "CREDS_JSON", "PROVISIONING_STATE_JSON", "CONFIG_POOL_JSON", "ASSIGNMENTS_JSON",
            "RESULTS_JSON", "HISTORY_JSONL", "DEVICE_RUNTIME_JSON", "DOWNLOAD_RECORDS_JSON",
            "PARSER_CURSORS_JSON", "ALLOCATION_LOCK", "HISTORY_LOCK", "LEASES_FILE", "SYSLOG_FILE",
            "NGINX_ACCESS", "DEV_MODE")}
        app.DATA_DIR = root / "state"; app.DATA_DIR.mkdir()
        app.NGINX_DIR = root / "configs"; app.NGINX_DIR.mkdir()
        app.UPLOAD_DIR = root / "uploads"; app.UPLOAD_DIR.mkdir()
        for name in ("DEVICES_JSON", "STATIC_MAPPINGS_JSON", "PROFILES_JSON", "SETTINGS_JSON", "CREDS_JSON",
                     "PROVISIONING_STATE_JSON", "CONFIG_POOL_JSON", "ASSIGNMENTS_JSON", "RESULTS_JSON", "HISTORY_JSONL",
                     "DEVICE_RUNTIME_JSON", "DOWNLOAD_RECORDS_JSON", "PARSER_CURSORS_JSON"):
            setattr(app, name, app.DATA_DIR / Path(getattr(app, name)).name)
        app.ALLOCATION_LOCK = app.DATA_DIR / "allocation.lock"
        app.HISTORY_LOCK = app.DATA_DIR / "history.lock"
        app.LEASES_FILE = root / "dhcpd.leases"
        app.SYSLOG_FILE = root / "syslog"
        app.NGINX_ACCESS = root / "ztp-access.log"
        app.DEV_MODE = True

    def tearDown(self):
        for name, value in self.old.items():
            setattr(app, name, value)
        self.tmp.cleanup()

    def settings(self, mode="ZTP_PROVISIONING"):
        value = dict(app.DEFAULT_SETTINGS)
        value.update({"active_mode": mode, "operating_mode": mode, "global_mode": mode,
                      "server_ip": "192.168.250.1", "subnet": "192.168.250.0",
                      "netmask": "255.255.255.0", "range_low": "192.168.250.10",
                      "range_high": "192.168.250.200", "gateway": ""})
        app.write_settings(value)
        return value

    def config(self, name="edge.conf"):
        self.settings()
        app.NGINX_DIR.joinpath(name).write_text("system { root-authentication { encrypted-password x; } }")
        app.sync_config_pool()
        return app.read_config_pool()[0]

    def test_mode_selection_is_pending_until_apply(self):
        self.settings()
        ok, message = app._apply_operating_mode("DHCP_FILE_SERVER", apply=False)
        self.assertTrue(ok)
        self.assertIn("Pending mode", message)
        saved = app.read_settings()
        self.assertEqual(saved["active_mode"], "ZTP_PROVISIONING")
        self.assertEqual(saved["pending_mode"], "DHCP_FILE_SERVER")

    def test_gateway_is_optional_and_not_implicit_server_router(self):
        settings = self.settings()
        rendered = app.generate_dhcpd(settings, [], [])
        self.assertNotIn("option routers", rendered)
        settings["gateway"] = "192.168.250.254"
        self.assertIn("option routers 192.168.250.254;", app.generate_dhcpd(settings, [], []))

    def test_repair_quarantines_orphan_and_is_idempotent(self):
        self.settings()
        app.write_config_pool([{"filename": "gone.conf", "status": "RESERVED", "assigned_device": "mac:x"}])
        app.write_assignments({"mac:x": {"filename": "gone.conf", "state": "ASSIGNED", "status": "RESERVED"}})
        first = app.repair_state_consistency()
        second = app.repair_state_consistency()
        self.assertTrue(first)
        self.assertEqual(second, [])
        self.assertEqual(app.read_assignments()["mac:x"]["state"], "REVIEW_REQUIRED")
        self.assertEqual(app.read_config_pool()[0]["status"], "QUARANTINED")

    def test_unified_view_keeps_dhcp_only_client(self):
        self.settings()
        app.DEVICE_RUNTIME_JSON.write_text(json.dumps({"mac:aa": {"mac": "aa:bb:cc:dd:ee:aa",
            "client_id": "cid-a", "dhcp_ip": "192.168.250.20", "last_event": "DHCPACK"}}))
        app.LEASES_FILE.write_text("lease 192.168.250.20 { hardware ethernet aa:bb:cc:dd:ee:aa; binding state active; }")
        rows = app.unified_client_rows()
        self.assertTrue(any(row["dhcp_ip"] == "192.168.250.20" for row in rows))

    def test_release_only_unused_auto_and_force_quarantines(self):
        self.config()
        app.write_assignments({"mac:a": {"filename": "edge.conf", "assignment_type": "AUTO",
            "state": "ASSIGNED", "status": "RESERVED", "fetch_times": []}})
        client = app.app.test_client()
        response = client.post("/provisioning/release/mac:a", data={"confirm_release": "yes"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(app.read_config_pool()[0]["status"], "AVAILABLE")
        app.write_config_pool([{"filename": "edge.conf", "status": "DELIVERED", "assigned_device": "mac:a"}])
        app.write_assignments({"mac:a": {"filename": "edge.conf", "assignment_type": "AUTO",
            "state": "DELIVERED", "status": "DELIVERED"}})
        response = client.post("/provisioning/release/mac:a", data={"confirm_release": "yes"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(app.read_config_pool()[0]["status"], "DELIVERED")
        response = client.post("/provisioning/force-release/mac:a", data={"confirm_force": "yes", "reason": "operator review"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(app.read_config_pool()[0]["status"], "QUARANTINED")

    def test_legacy_bindings_page_is_gone_and_verify_route_is_available(self):
        self.settings()
        client = app.app.test_client()
        self.assertEqual(client.get("/bindings").status_code, 404)
        self.assertEqual(client.post("/provisioning/verify/mac:x").status_code, 302)

    def test_overview_has_exactly_four_primary_menu_items(self):
        self.settings()
        html = app.app.test_client().get("/?view=overview").get_data(as_text=True)
        for label in ("Overview", "Config Inventory", "Logs", "Settings"):
            self.assertIn(label, html)
        self.assertIn("Operating Mode", html)
        self.assertIn("Deployment Status", html)
        self.assertNotIn("Health", html)
        self.assertNotIn("SSH credentials", html)

    def test_config_pool_quarantined_cannot_be_overwritten(self):
        self.config()
        pool = app.read_config_pool(); pool[0]["status"] = "QUARANTINED"; app.write_config_pool(pool)
        result = app.upload_config_bytes("edge.conf", b"system { root-authentication { encrypted-password new; } }")
        self.assertEqual(result["result"], "PROTECTED")

    def test_retry_resets_window_counters_but_keeps_assignment_file(self):
        self.config()
        app.write_assignments({"mac:r": {"filename": "edge.conf", "assignment_type": "AUTO",
            "state": "FETCH_FAILED", "status": "RESERVED", "fetch_times": ["now"],
            "fetch_count_window": 4, "request_count_window": 7}})
        response = app.app.test_client().post("/provisioning/retry/mac:r")
        self.assertEqual(response.status_code, 302)
        row = app.read_assignments()["mac:r"]
        self.assertEqual(row["filename"], "edge.conf")
        self.assertEqual(row["state"], "ASSIGNED")
        self.assertEqual(row["fetch_times"], [])
        self.assertEqual(row["request_count_window"], 0)

    def test_duplicate_fixed_and_management_ips_are_blocked(self):
        settings = self.settings()
        base = {"match_method": "mac", "mac_address": "aa:bb:cc:dd:ee:01", "hostname": "a",
                "assignment_type": "AUTO", "ip_address": "192.168.250.20", "mgmt_ip": "10.0.0.1"}
        other = dict(base, hostname="b", mac_address="aa:bb:cc:dd:ee:02")
        errors = app.validate_device_row(other, [base], settings=settings)
        self.assertTrue(any("DHCP IP" in item for item in errors))
        self.assertTrue(any("Management IP" in item for item in errors))

    def test_partial_http_200_never_promotes_delivery(self):
        self.settings()
        data = b"system { root-authentication { encrypted-password x; } }"
        app.NGINX_DIR.joinpath("partial.conf").write_bytes(data)
        app.NGINX_ACCESS.write_text(f'192.168.250.20 [02/Aug/2026:12:00:00 +0000] "GET /configs/partial.conf HTTP/1.1" 200 2 0.01 "req-partial" "" "" "" "" "test"\n')
        app.reconcile_downloads()
        self.assertNotEqual(app.read_download_records()["req-partial"]["download_state"], "DELIVERED")

    def test_settings_gateway_can_be_cleared(self):
        self.settings()
        current = app.read_settings(); current["gateway"] = "192.168.250.254"; app.write_settings(current)
        response = app.app.test_client().post("/settings", data={"gateway": "", "server_ip": "192.168.250.1",
            "subnet": "192.168.250.0", "prefix_length": "24", "range_low": "192.168.250.10",
            "range_high": "192.168.250.200", "internet_interface": "", "ztp_interface": "",
            "confirm_dhcp": "yes", "save_mode": "draft"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(app.read_settings()["gateway"], "")

    def test_legacy_nginx_dash_bytes_are_safe(self):
        parsed = app._parse_nginx_line('192.168.250.20 [02/Aug/2026:12:00:00 +0000] "GET /configs/edge.conf HTTP/1.1" 304 0 0.01 "req-304" "edge.conf" "" "AUTO" "-" "test"')
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["expected_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
