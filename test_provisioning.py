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
            "CREDS_JSON", "PROVISIONING_STATE_JSON", "CONFIG_POOL_JSON", "ASSIGNMENTS_JSON", "RESULTS_JSON",
            "HISTORY_JSONL", "ALLOCATION_LOCK", "HISTORY_LOCK", "LEASES_FILE", "SYSLOG_FILE",
        )}
        app.NGINX_DIR = root / "configs"; app.NGINX_DIR.mkdir()
        app.UPLOAD_DIR = root / "uploads"; app.UPLOAD_DIR.mkdir()
        app.DEVICES_JSON = root / "devices.json"; app.STATIC_MAPPINGS_JSON = root / "static_mappings.json"; app.PROFILES_JSON = root / "profiles.json"
        app.SETTINGS_JSON = root / "settings.json"; app.CREDS_JSON = root / "creds.json"
        app.PROVISIONING_STATE_JSON = root / "provisioning_state.json"
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
                         "auto_pool_enabled": True, "allow_any_model": True,
                         "created_at": "now", "updated_at": "now"})
        app.write_config_pool(rows)
        state = app.read_provisioning_state()
        state["project"].update({"status": "ACTIVE", "expected_devices": 0})
        app.commit_provisioning_state(state)

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
        app.LEASES_FILE.write_text('lease 192.168.250.10 { hardware ethernet aa:bb:cc:dd:ee:01; '
                                   'binding state active; set vendor-string = '
                                   '"Juniper-ex4100-h-12mp-GE4825AW015"; }', encoding="utf-8")
        app.DEVICES_JSON.write_text("[]", encoding="utf-8")
        app.PROFILES_JSON.write_text('[{"label":"auto","vendor_class":"Juniper-ex4100-h-12mp-",'
                                     '"vendor_prefix":"Juniper-ex4100-h-12mp-","device_model":"EX4100-H-12MP",'
                                     '"match_mode":"contains","config_file":"","assignment_type":"AUTO",'
                                     '"pool_name":"default","config_pattern":"*",'
                                     '"option60_confirmed":"yes"}]', encoding="utf-8")
        body, filename, status = app.dynamic_config_result("192.168.250.10")
        self.assertEqual((filename, status), ("auto.conf", 200))
        self.assertIn(b"root-authentication", body)
        body2, filename2, status2 = app.dynamic_config_result("192.168.250.10")
        self.assertEqual((filename2, status2, body2), (filename, status, body))

    def test_project_resolver_prefers_serial_override(self):
        self.add_configs(["static.conf", "auto.conf"])
        pool = app.read_config_pool()
        pool[0]["supported_models"] = ["EX4100-H-12MP"]
        pool[0]["device_model"] = "EX4100-H-12MP"
        pool[0]["allow_any_model"] = False
        pool[1]["supported_models"] = ["EX4100-H-12MP"]
        pool[1]["device_model"] = "EX4100-H-12MP"
        app.write_config_pool(pool)
        app.LEASES_FILE.write_text('lease 192.168.250.10 { hardware ethernet aa:bb:cc:dd:ee:02; '
                                   'binding state active; set vendor-string = '
                                   '"Juniper-ex4100-h-12mp-GE4825AW015"; }', encoding="utf-8")
        app.DEVICES_JSON.write_text('[{"match_method":"serial","serial_number":"GE4825AW015",'
                                    '"mac_address":"","hostname":"GE4825AW015","device_type":"EX4100-H-12MP",'
                                    '"expected_model":"EX4100-H-12MP","ip_address":"","specific_config_file":"static.conf",'
                                    '"assignment_type":"STATIC","option60_confirmed":"yes"}]', encoding="utf-8")
        app.PROFILES_JSON.write_text('[{"label":"fallback","vendor_class":"Juniper-ex4100-h-12mp-",'
                                     '"vendor_prefix":"Juniper-ex4100-h-12mp-","device_model":"EX4100-H-12MP",'
                                     '"match_mode":"contains","assignment_type":"AUTO","pool_name":"default",'
                                     '"config_pattern":"*","option60_confirmed":"yes"}]', encoding="utf-8")
        body, filename, status = app.dynamic_config_result("192.168.250.10")
        self.assertEqual((filename, status), ("static.conf", 200))
        self.assertIn(b"root-authentication", body)
        self.assertEqual("static.conf", app.read_assignments()["serial:ge4825aw015"]["filename"])

    def test_override_validation_and_empty_profile_pool_fail_closed(self):
        row = {"match_method": "serial", "serial_number": "GE4825AW017", "mac_address": "",
               "hostname": "GE4825AW017", "device_type": "EX4400", "expected_model": "EX4400",
               "assignment_type": "STATIC", "option60_confirmed": "yes"}
        errors = app.validate_device_row(row, [], settings=app.DEFAULT_SETTINGS)
        self.assertTrue(any("requires a specific config file" in error for error in errors))
        app.LEASES_FILE.write_text(
            'lease 192.168.250.11 { hardware ethernet aa:bb:cc:dd:ee:03; binding state active; '
            'set vendor-string = "Juniper-ex4400-GE4825AW017"; }',
            encoding="utf-8")
        app.PROFILES_JSON.write_text(
            '[{"label":"empty","vendor_class":"Juniper-ex4400-","vendor_prefix":"Juniper-ex4400-",'
            '"device_model":"EX4400","match_mode":"contains","assignment_type":"AUTO",'
            '"pool_name":"empty","option60_confirmed":"yes"}]', encoding="utf-8")
        state = app.read_provisioning_state()
        state["project"].update({"status": "ACTIVE", "expected_devices": 0})
        app.commit_provisioning_state(state)
        body, reason, status = app.dynamic_config_result("192.168.250.11")
        self.assertIsNone(body)
        self.assertEqual((reason, status), ("PROFILE_POOL_EMPTY", 409))
        self.assertNotIn("serial:ge4825aw017", app.read_assignments())

    def test_json_schema_error_and_file_server_only(self):
        app.DEVICES_JSON.write_text("[1]", encoding="utf-8")
        with self.assertRaises(app.JsonDataError): app.read_devices()
        app.DEVICES_JSON.write_text("[]", encoding="utf-8")
        app.SETTINGS_JSON.write_text('{"global_mode":"FILE_SERVER_ONLY"}', encoding="utf-8")
        ok, message = app.deploy_dhcpd("ignored", settings=app.read_settings(), devices=[], profiles=[])
        self.assertTrue(ok); self.assertIn("FILE_SERVER_ONLY", message)

    def test_runtime_thresholds_and_verify_requires_delivery(self):
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
        response = client.post("/provisioning/verify/mac:aa", data={"result": "COMPLETED"})
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("COMPLETED", app.read_assignments()["mac:aa"].get("state", ""))

    def test_json_backup_is_created_before_replacement(self):
        app.write_settings({"global_mode": "FULL_ZTP", "server_ip": "192.168.250.1"})
        app.write_settings({"global_mode": "FILE_SERVER_ONLY", "server_ip": "192.168.250.1"})
        self.assertTrue(app.SETTINGS_JSON.with_name("settings.json.bak").exists())
        app.SETTINGS_JSON.write_text("{broken", encoding="utf-8")
        with self.assertRaises(app.JsonDataError): app.read_settings()


if __name__ == "__main__":
    unittest.main()
