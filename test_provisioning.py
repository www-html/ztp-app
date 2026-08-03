import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

os.environ.setdefault("ZTP_DEV", "1")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app


class ProvisioningSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.old = {name: getattr(app, name) for name in (
            "NGINX_DIR", "UPLOAD_DIR", "DEVICES_JSON", "STATIC_MAPPINGS_JSON", "PROFILES_JSON", "SETTINGS_JSON",
            "CREDS_JSON", "CONFIG_POOL_JSON", "ASSIGNMENTS_JSON", "RESULTS_JSON",
            "HISTORY_JSONL", "ALLOCATION_LOCK", "HISTORY_LOCK", "LEASES_FILE", "SYSLOG_FILE",
        )}
        app.NGINX_DIR = root / "configs"; app.NGINX_DIR.mkdir()
        app.UPLOAD_DIR = root / "uploads"; app.UPLOAD_DIR.mkdir()
        app.DEVICES_JSON = root / "devices.json"; app.STATIC_MAPPINGS_JSON = root / "static_mappings.json"; app.PROFILES_JSON = root / "profiles.json"
        app.SETTINGS_JSON = root / "settings.json"; app.CREDS_JSON = root / "creds.json"
        app.CONFIG_POOL_JSON = root / "config_pool.json"; app.ASSIGNMENTS_JSON = root / "assignments.json"
        app.RESULTS_JSON = root / "results.json"; app.HISTORY_JSONL = root / "history.jsonl"
        app.ALLOCATION_LOCK = root / "allocation.lock"; app.HISTORY_LOCK = root / "history.lock"
        app.LEASES_FILE = root / "dhcpd.leases"; app.SYSLOG_FILE = root / "syslog"
        app.DEV_MODE = True

    def tearDown(self):
        for name, value in self.old.items():
            setattr(app, name, value)
        self.tmp.cleanup()

    def add_configs(self, names):
        rows = []
        for order, name in enumerate(names, 1):
            path = app.NGINX_DIR / name
            path.write_text("system { root-authentication { encrypted-password x; } }", encoding="utf-8")
            rows.append({"filename": name, "hostname": "", "supported_models": [],
                         "compatibility_group": "", "pool_name": "default", "checksum": app.config_sha256(path),
                         "allocation_order": order, "status": "AVAILABLE", "assigned_device": "",
                         "created_at": "now", "updated_at": "now"})
        app.write_config_pool(rows)

    def test_thirty_concurrent_reservations_do_not_duplicate(self):
        self.add_configs([f"auto-{i}.conf" for i in range(30)])
        results = []
        def reserve(i):
            lease = {"mac": f"aa:bb:cc:dd:ee:{i:02x}", "client_id": "", "state": "active"}
            assignment, error = app.reserve_auto_assignment(
                f"mac:{lease['mac']}", None, {"pool_name": "default"}, lease, f"mac:{lease['mac']}")
            results.append((assignment, error))
        threads = [threading.Thread(target=reserve, args=(i,)) for i in range(30)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(len(results), 30)
        self.assertTrue(all(item and not error for item, error in results))
        self.assertEqual(len({item["filename"] for item, _ in results}), 30)

    def test_retry_keeps_same_file_and_static_override_releases_auto(self):
        self.add_configs(["auto.conf", "static.conf"])
        lease = {"mac": "aa:bb:cc:dd:ee:01", "client_id": "", "state": "active"}
        first, _ = app.reserve_auto_assignment("mac:aa:bb:cc:dd:ee:01", None,
                                               {"pool_name": "default"}, lease, "mac:aa:bb:cc:dd:ee:01")
        second, _ = app.reserve_auto_assignment("mac:aa:bb:cc:dd:ee:01", None,
                                                {"pool_name": "default"}, lease, "mac:aa:bb:cc:dd:ee:01")
        self.assertEqual(first["filename"], second["filename"])
        static = {"hostname": "edge-1", "device_type": "", "compatibility_group": "",
                  "specific_config_file": "static.conf"}
        app._ensure_static_runtime("mac:aa:bb:cc:dd:ee:01", static, "static.conf", "192.168.250.10", lease)
        pool = {row["filename"]: row for row in app.read_config_pool()}
        self.assertEqual(pool["auto.conf"]["status"], "AVAILABLE")
        self.assertEqual(app.read_assignments()["mac:aa:bb:cc:dd:ee:01"]["filename"], "static.conf")

    def test_exact_model_and_group_rules(self):
        self.assertTrue(app.config_is_compatible({"supported_models": ["EX4100-24T"]}, "EX4100-24T", ""))
        self.assertFalse(app.config_is_compatible({"supported_models": ["EX4100-24T"]}, "EX4100-48T", ""))
        self.assertTrue(app.config_is_compatible({"compatibility_group": "EX4100"}, "EX4100-48T", "EX4100"))

    def test_dynamic_resolver_dhcp_only_and_auto(self):
        self.add_configs(["auto.conf"])
        app.LEASES_FILE.write_text("lease 192.168.250.10 { hardware ethernet aa:bb:cc:dd:ee:01; binding state active; }", encoding="utf-8")
        app.DEVICES_JSON.write_text("[]", encoding="utf-8")
        app.PROFILES_JSON.write_text('[{"label":"auto","vendor_class":"EX4100","match_mode":"contains","config_file":"","assignment_type":"AUTO","option60_confirmed":"yes"}]', encoding="utf-8")
        app.SYSLOG_FILE.write_text("dhcpd vendor-class-identifier \"EX4100\" 192.168.250.10", encoding="utf-8")
        body, filename, status = app.dynamic_config_result("192.168.250.10")
        self.assertEqual((filename, status), ("auto.conf", 200))
        self.assertIn(b"root-authentication", body)
        body2, filename2, status2 = app.dynamic_config_result("192.168.250.10")
        self.assertEqual((filename2, status2, body2), (filename, status, body))

    def test_static_model_mismatch_does_not_fallback_to_auto(self):
        self.add_configs(["static.conf", "auto.conf"])
        pool = app.read_config_pool()
        pool[0]["supported_models"] = ["EX4100-24T"]
        pool[1]["supported_models"] = []
        app.write_config_pool(pool)
        app.LEASES_FILE.write_text("lease 192.168.250.10 { hardware ethernet aa:bb:cc:dd:ee:02; binding state active; }", encoding="utf-8")
        app.DEVICES_JSON.write_text('[{"match_method":"mac","mac_address":"aa:bb:cc:dd:ee:02","hostname":"edge-2","device_type":"EX4100-48T","ip_address":"192.168.250.10","specific_config_file":"static.conf","assignment_type":"STATIC"}]', encoding="utf-8")
        app.PROFILES_JSON.write_text('[{"label":"fallback","vendor_class":"EX4100","match_mode":"contains","assignment_type":"AUTO","option60_confirmed":"yes"}]', encoding="utf-8")
        body, reason, status = app.dynamic_config_result("192.168.250.10")
        self.assertIsNone(body); self.assertEqual((reason, status), ("MODEL_MISMATCH", 409))
        self.assertNotIn("auto.conf", {item.get("filename") for item in app.read_assignments().values()})

    def test_static_requires_file_and_empty_auto_pool_is_review_required(self):
        row = {"match_method": "mac", "mac_address": "aa:bb:cc:dd:ee:03",
               "hostname": "edge-3", "assignment_type": "STATIC"}
        errors = app.validate_device_row(row, [], settings=app.DEFAULT_SETTINGS)
        self.assertTrue(any("requires a specific config file" in error for error in errors))
        app.LEASES_FILE.write_text(
            "lease 192.168.250.11 { hardware ethernet aa:bb:cc:dd:ee:03; binding state active; }",
            encoding="utf-8")
        app.PROFILES_JSON.write_text(
            '[{"label":"empty","vendor_class":"EX4400","match_mode":"contains",'
            '"assignment_type":"AUTO","option60_confirmed":"yes"}]', encoding="utf-8")
        app.SYSLOG_FILE.write_text(
            'dhcpd vendor-class-identifier "EX4400" 192.168.250.11', encoding="utf-8")
        body, reason, status = app.dynamic_config_result("192.168.250.11")
        self.assertIsNone(body)
        self.assertEqual((reason, status), ("AUTO_POOL_EMPTY", 409))
        self.assertEqual(app.read_assignments()["mac:aa:bb:cc:dd:ee:03"]["state"], "REVIEW_REQUIRED")

    def test_json_schema_error_and_file_server_only(self):
        app.DEVICES_JSON.write_text("[1]", encoding="utf-8")
        with self.assertRaises(app.JsonDataError): app.read_devices()
        app.DEVICES_JSON.write_text("[]", encoding="utf-8")
        app.SETTINGS_JSON.write_text('{"global_mode":"FILE_SERVER_ONLY"}', encoding="utf-8")
        ok, message = app.deploy_dhcpd("ignored", settings=app.read_settings(), devices=[], profiles=[])
        self.assertTrue(ok); self.assertIn("FILE_SERVER_ONLY", message)

    def test_runtime_thresholds_manual_verification_history_and_exports(self):
        self.add_configs(["auto.conf"])
        app.write_assignments({"mac:aa": {"device_key": "mac:aa", "assignment_type": "AUTO",
                                           "filename": "auto.conf", "status": "RESERVED", "state": "ASSIGNED",
                                           "assigned_at": "2000-01-01T00:00:00+00:00", "fetch_times": [],
                                           "fetch_count": 0, "request_count": 1, "hostname": "edge"}})
        refreshed = app.refresh_runtime_states()
        self.assertEqual(refreshed["mac:aa"]["state"], "ASSIGNED_NO_FETCH")
        app.append_history("TEST_EVENT", "mac:aa", message="audit")
        self.assertEqual(app.export_history_rows()[0]["event_type"], "TEST_EVENT")
        client = app.app.test_client()
        response = client.post("/provisioning/verify/mac:aa", data={"result": "COMPLETED",
            "serial": "S1", "model": "EX4100-24T", "hostname": "edge", "remarks": "commit ok"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(app.read_results()["mac:aa"]["result"], "COMPLETED")
        self.assertEqual(app.read_assignments()["mac:aa"]["state"], "COMPLETED")

    def test_json_backup_is_created_before_replacement(self):
        app.write_settings({"global_mode": "FULL_ZTP", "server_ip": "192.168.250.1"})
        app.write_settings({"global_mode": "FILE_SERVER_ONLY", "server_ip": "192.168.250.1"})
        self.assertTrue(app.SETTINGS_JSON.with_name("settings.json.bak").exists())
        app.SETTINGS_JSON.write_text("{broken", encoding="utf-8")
        with self.assertRaises(app.JsonDataError): app.read_settings()


if __name__ == "__main__":
    unittest.main()
