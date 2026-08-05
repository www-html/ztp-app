import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

os.environ.setdefault("ZTP_DEV", "1")
import app


VALID_CONFIG = "system { root-authentication { encrypted-password x; } }\n"
PREFIX = "Juniper-ex4100-h-12mp-"
MODEL = "EX4100-H-12MP"
POOL = "OXISANTA_EX4100_H_12MP"


class ProjectAllocationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.old = {name: getattr(app, name) for name in (
            "DATA_DIR", "NGINX_DIR", "UPLOAD_DIR", "DEVICES_JSON", "STATIC_MAPPINGS_JSON",
            "PROFILES_JSON", "SETTINGS_JSON", "CREDS_JSON", "PROVISIONING_STATE_JSON",
            "CONFIG_POOL_JSON", "ASSIGNMENTS_JSON", "RESULTS_JSON", "HISTORY_JSONL",
            "DEVICE_RUNTIME_JSON", "DOWNLOAD_RECORDS_JSON", "PARSER_CURSORS_JSON",
            "ALLOCATION_LOCK", "HISTORY_LOCK", "LEASES_FILE", "SYSLOG_FILE", "NGINX_ACCESS",
            "DEV_MODE")}
        app.DATA_DIR = root / "state"; app.DATA_DIR.mkdir()
        app.NGINX_DIR = root / "configs"; app.NGINX_DIR.mkdir()
        app.UPLOAD_DIR = app.NGINX_DIR
        for name in ("DEVICES_JSON", "STATIC_MAPPINGS_JSON", "PROFILES_JSON", "SETTINGS_JSON",
                     "CREDS_JSON", "PROVISIONING_STATE_JSON", "CONFIG_POOL_JSON", "ASSIGNMENTS_JSON",
                     "RESULTS_JSON", "HISTORY_JSONL", "DEVICE_RUNTIME_JSON", "DOWNLOAD_RECORDS_JSON",
                     "PARSER_CURSORS_JSON"):
            setattr(app, name, app.DATA_DIR / Path(getattr(app, name)).name)
        app.ALLOCATION_LOCK = app.DATA_DIR / ".allocation.lock"
        app.HISTORY_LOCK = app.DATA_DIR / ".history.lock"
        app.LEASES_FILE = root / "dhcpd.leases"
        app.SYSLOG_FILE = root / "syslog"
        app.NGINX_ACCESS = root / "access.log"
        app.DEV_MODE = True
        app.app.config.update(TESTING=True)
        settings = dict(app.DEFAULT_SETTINGS)
        settings.update({"active_mode": "ZTP_PROVISIONING", "operating_mode": "ZTP_PROVISIONING",
                         "global_mode": "ZTP_PROVISIONING", "project_expected_devices": "0"})
        app.write_settings(settings)
        app.write_devices([])
        app.write_profiles([{"label": MODEL, "vendor_class": PREFIX, "vendor_prefix": PREFIX,
                             "device_model": MODEL, "match_mode": "contains", "config_file": "",
                             "assignment_type": "AUTO", "pool_name": POOL,
                             "config_pattern": "*",
                             "compatibility_group": MODEL, "option60_confirmed": "yes"}])
        state = app._default_provisioning_state()
        state["project"].update({"status": "ACTIVE", "expected_devices": 0, "next_sequence": 1})
        app.commit_provisioning_state(state)

    def tearDown(self):
        for name, value in self.old.items():
            setattr(app, name, value)
        self.tmp.cleanup()

    def add_configs(self, count, pool=POOL, model=MODEL):
        state = app.read_provisioning_state()
        for index in range(1, count + 1):
            filename = f"switch-{index:03d}.conf"
            path = app.NGINX_DIR / filename
            path.write_text(VALID_CONFIG, encoding="utf-8")
            state["configs"][filename] = {
                "status": "AVAILABLE", "checksum": app.config_sha256(path),
                "allocation_order": index, "assigned_device": "", "assigned_serial": "",
                "device_model": model, "supported_models": [model], "pool_name": pool,
                "auto_pool_enabled": True, "file_size": path.stat().st_size,
            }
        app.commit_provisioning_state(state)

    @staticmethod
    def lease(index, mac=None):
        serial = f"GE4825AW{index:04d}"
        return serial, {"mac": mac or f"02:00:00:00:{index // 256:02x}:{index % 256:02x}",
                        "hostname": serial, "client_id": "", "state": "active",
                        "option60": PREFIX + serial}

    def reserve(self, index, ip=None, mac=None):
        _, lease = self.lease(index, mac)
        return app.reserve_project_assignment(ip or f"192.168.250.{10 + index}", lease)

    def test_many_serials_receive_unique_files(self):
        self.add_configs(40)
        with ThreadPoolExecutor(max_workers=8) as workers:
            results = list(workers.map(lambda index: self.reserve(index)[0], range(40)))
        self.assertTrue(all(results))
        self.assertEqual(40, len({item["filename"] for item in results}))
        self.assertTrue(all(item["device_key"].startswith("serial:") for item in results))

    def test_same_serial_new_mac_and_ip_keeps_assignment(self):
        self.add_configs(2)
        first, _ = self.reserve(1)
        second, _ = self.reserve(1, ip="192.168.250.200", mac="aa:bb:cc:dd:ee:ff")
        self.assertEqual(first["filename"], second["filename"])
        self.assertEqual("aa:bb:cc:dd:ee:ff", second["observed_mac"])
        self.assertTrue(any(row["event_type"] == "IP_CHANGED" for row in app.read_history()))

    def test_same_mac_different_serial_creates_distinct_identity(self):
        self.add_configs(2)
        first, _ = self.reserve(1, mac="aa:bb:cc:dd:ee:01")
        second, _ = self.reserve(2, ip="192.168.250.22", mac="aa:bb:cc:dd:ee:01")
        self.assertNotEqual(first["device_key"], second["device_key"])
        self.assertNotEqual(first["filename"], second["filename"])

    def test_paused_blocks_new_but_serves_existing_serial(self):
        self.add_configs(2)
        first, _ = self.reserve(1)
        state = app.read_provisioning_state(); state["project"]["status"] = "PAUSED"
        app.commit_provisioning_state(state)
        existing, error = self.reserve(1)
        self.assertEqual("", error); self.assertEqual(first["filename"], existing["filename"])
        new, error = self.reserve(2, ip="192.168.250.22")
        self.assertIsNone(new); self.assertEqual("PROJECT_PAUSED", error)

    def test_ip_conflict_blocks_other_serial(self):
        self.add_configs(2)
        self.reserve(1, ip="192.168.250.20")
        other, error = self.reserve(2, ip="192.168.250.20")
        self.assertIsNone(other); self.assertEqual("IP_CONFLICT", error)

    def test_empty_named_pool_never_falls_back(self):
        self.add_configs(1, pool="OTHER")
        assignment, error = self.reserve(1)
        self.assertIsNone(assignment); self.assertEqual("PROFILE_POOL_EMPTY", error)
        self.assertEqual("AVAILABLE", app.read_config_pool()[0]["status"])

    def test_empty_syslog_does_not_affect_lease_option60(self):
        self.add_configs(1)
        app.SYSLOG_FILE.write_text("", encoding="utf-8")
        assignment, error = self.reserve(1)
        self.assertFalse(error); self.assertIsNotNone(assignment)

    def test_manual_explicit_download_requires_and_uses_serial_lease(self):
        self.add_configs(1)
        serial, lease = self.lease(1)
        app.LEASES_FILE.write_text(
            f'lease 192.168.250.20 {{ hardware ethernet {lease["mac"]}; binding state active; '
            f'set vendor-string = "{lease["option60"]}"; }}\n', encoding="utf-8")
        client = app.app.test_client()
        listing = client.get("/ztp/config/")
        self.assertEqual(200, listing.status_code)
        download = client.get("/ztp/config/switch-001.conf",
                              environ_base={"REMOTE_ADDR": "192.168.250.20"})
        self.assertEqual(200, download.status_code)
        self.assertIn(VALID_CONFIG.encode(), download.data)
        self.assertEqual(serial, app.read_config_pool()[0]["assigned_serial"])
        download.close()

    def test_configs_directory_mode_boundaries(self):
        self.add_configs(1)
        client = app.app.test_client()
        self.assertEqual(403, client.get("/configs/").status_code)
        settings = app.read_settings(); settings.update({"active_mode": "DHCP_FILE_SERVER",
                                                         "operating_mode": "DHCP_FILE_SERVER",
                                                         "global_mode": "DHCP_FILE_SERVER"})
        app.write_settings(settings)
        self.assertEqual(200, client.get("/configs/").status_code)

    def test_serial_migration_is_idempotent_and_keeps_backup(self):
        state = app.read_provisioning_state()
        state["schema_version"] = 1
        state["devices"] = {"mac:aa:bb:cc:dd:ee:01": {
            "device_key": "mac:aa:bb:cc:dd:ee:01", "serial": "GE4825AW0001",
            "mac": "aa:bb:cc:dd:ee:01", "filename": "", "state": "DHCP_SEEN"}}
        app._atomic_write_json(app.PROVISIONING_STATE_JSON, state)
        self.assertTrue(app.migrate_serial_first_state())
        self.assertFalse(app.migrate_serial_first_state())
        migrated = app.read_provisioning_state()
        self.assertIn("serial:ge4825aw0001", migrated["devices"])
        self.assertTrue((app.DATA_DIR / "migration-backup-serial-v2" /
                         "provisioning_state.json").exists())


if __name__ == "__main__":
    unittest.main()
