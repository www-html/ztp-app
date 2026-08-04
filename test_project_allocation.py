import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

os.environ.setdefault("ZTP_DEV", "1")
import app


VALID_CONFIG = "system { root-authentication { encrypted-password x; } }\n"


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
        app.DATA_DIR = root / "state"
        app.NGINX_DIR = root / "configs"
        app.UPLOAD_DIR = root / "uploads"
        app.DATA_DIR.mkdir()
        app.NGINX_DIR.mkdir()
        app.UPLOAD_DIR.mkdir()
        for name in (
                "DEVICES_JSON", "STATIC_MAPPINGS_JSON", "PROFILES_JSON", "SETTINGS_JSON",
                "CREDS_JSON", "PROVISIONING_STATE_JSON", "CONFIG_POOL_JSON", "ASSIGNMENTS_JSON",
                "RESULTS_JSON", "HISTORY_JSONL", "DEVICE_RUNTIME_JSON", "DOWNLOAD_RECORDS_JSON",
                "PARSER_CURSORS_JSON"):
            setattr(app, name, app.DATA_DIR / Path(getattr(app, name)).name)
        app.ALLOCATION_LOCK = app.DATA_DIR / "allocation.lock"
        app.HISTORY_LOCK = app.DATA_DIR / "history.lock"
        app.LEASES_FILE = root / "dhcpd.leases"
        app.SYSLOG_FILE = root / "syslog"
        app.NGINX_ACCESS = root / "ztp-access.log"
        app.DEV_MODE = True
        app.app.config.update(TESTING=True)
        self.set_mode("ZTP_PROVISIONING")

    def tearDown(self):
        for name, value in self.old.items():
            setattr(app, name, value)
        self.tmp.cleanup()

    def set_mode(self, mode):
        settings = dict(app.DEFAULT_SETTINGS)
        settings.update({
            "active_mode": mode, "operating_mode": mode, "global_mode": mode,
            "deployment_name": "ex-rollout", "project_expected_devices": "0",
            "server_ip": "192.168.250.1", "subnet": "192.168.250.0",
            "netmask": "255.255.255.0", "range_low": "192.168.250.10",
            "range_high": "192.168.250.254", "gateway": "",
        })
        app.write_settings(settings)

    def add_configs(self, count, *, project="ACTIVE"):
        state = app._default_provisioning_state()
        state["project"].update({"name": "ex-rollout", "status": project,
                                 "expected_devices": 0, "next_sequence": 1})
        for index in range(1, count + 1):
            filename = f"switch-{index:03d}.conf"
            path = app.NGINX_DIR / filename
            path.write_text(VALID_CONFIG, encoding="utf-8")
            state["configs"][filename] = {
                "status": "AVAILABLE", "checksum": app.config_sha256(path),
                "allocation_order": index, "assigned_device": "", "file_size": path.stat().st_size,
            }
        app.commit_provisioning_state(state)

    @staticmethod
    def lease(index, *, option60="Juniper-example"):
        return {"mac": f"02:00:00:00:{index // 256:02x}:{index % 256:02x}",
                "client_id": f"client-{index}", "hostname": f"ex-{index}",
                "option60": option60, "state": "active"}

    def reserve(self, index, ip=None, option60="Juniper-example"):
        return app.reserve_project_assignment(
            ip or f"192.168.250.{10 + index}", self.lease(index, option60=option60))

    def test_150_macs_receive_150_unique_files(self):
        self.add_configs(150)
        assignments = [self.reserve(i, f"192.168.250.{10 + i}")[0] for i in range(150)]
        self.assertEqual(len({item["config"] for item in assignments}), 150)

    def test_no_config_has_two_owners(self):
        self.add_configs(3)
        for index in range(3):
            self.reserve(index)
        state = app.read_provisioning_state()
        owners = [meta["assigned_device"] for meta in state["configs"].values()]
        self.assertEqual(len(owners), len(set(owners)))
        self.assertTrue(all(meta["status"] == "ASSIGNED" for meta in state["configs"].values()))

    def test_same_mac_retries_same_file(self):
        self.add_configs(2)
        first, _ = self.reserve(1)
        second, _ = self.reserve(1)
        self.assertEqual(first["config"], second["config"])

    def test_state_reload_keeps_assignment(self):
        self.add_configs(1)
        first, _ = self.reserve(1)
        reloaded = app.read_provisioning_state()["devices"]["mac:02:00:00:00:00:01"]
        self.assertEqual(first["config"], reloaded["config"])

    def test_concurrent_requests_never_duplicate_a_file(self):
        self.add_configs(40)
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda index: self.reserve(index)[0], range(40)))
        filenames = [item["config"] for item in results]
        self.assertEqual(40, len(set(filenames)))

    def pause_project(self):
        state = app.read_provisioning_state()
        state["project"]["status"] = "PAUSED"
        app.commit_provisioning_state(state)

    def test_paused_blocks_new_client(self):
        self.add_configs(1)
        self.pause_project()
        new, error = self.reserve(1)
        self.assertIsNone(new)
        self.assertEqual("PROJECT_PAUSED", error)

    def test_paused_serves_existing_assignment(self):
        self.add_configs(1)
        first, _ = self.reserve(1)
        self.pause_project()
        existing, error = self.reserve(1)
        self.assertEqual(first["config"], existing["config"])
        self.assertEqual("", error)

    def test_empty_pool_never_reuses_claimed_file(self):
        self.add_configs(1)
        first, _ = self.reserve(1)
        second, error = self.reserve(2)
        self.assertIsNotNone(first)
        self.assertIsNone(second)
        self.assertEqual("CONFIG_POOL_EMPTY", error)

    def test_reset_uncompleted_releases_config(self):
        self.add_configs(1)
        first, _ = self.reserve(1)
        key = first["device_key"]
        ok, _ = app.reset_project_client(key)
        self.assertTrue(ok)
        self.assertEqual("AVAILABLE", app.read_provisioning_state()["configs"][first["config"]]["status"])

    def test_delivered_never_returns_to_available_implicitly(self):
        self.add_configs(1)
        assigned, _ = self.reserve(1)
        key = assigned["device_key"]
        state = app.read_provisioning_state()
        state["devices"][key]["state"] = "DELIVERED"
        state["devices"][key]["status"] = "DELIVERED"
        state["configs"][assigned["config"]]["status"] = "DELIVERED"
        app.commit_provisioning_state(state)
        blocked, _ = app.reset_project_client(key)
        self.assertFalse(blocked)
        self.assertEqual("DELIVERED", app.read_provisioning_state()["configs"][assigned["config"]]["status"])

    def test_delivered_reset_requires_review_then_explicit_release(self):
        self.add_configs(1)
        device, _ = self.reserve(1)
        key, filename = device["device_key"], device["config"]
        state = app.read_provisioning_state()
        state["devices"][key]["state"] = "DELIVERED"
        state["configs"][filename]["status"] = "DELIVERED"
        app.commit_provisioning_state(state)
        ok, _ = app.reset_project_client(key, allow_delivered=True)
        self.assertTrue(ok)
        self.assertEqual("REVIEW_REQUIRED", app.read_provisioning_state()["configs"][filename]["status"])
        ok, _ = app.release_review_config(filename)
        self.assertTrue(ok)
        self.assertEqual("AVAILABLE", app.read_provisioning_state()["configs"][filename]["status"])

    def test_archive_hidden_from_recent_but_in_full_export(self):
        self.add_configs(1)
        device, _ = self.reserve(1)
        app.archive_project_client(device["device_key"])
        with app.app.test_request_context("/?view=overview"):
            self.assertEqual([], app.unified_client_rows())
        rows = app.provisioning_rows()
        self.assertEqual(1, len(rows))
        self.assertTrue(rows[0]["archived"])

    def test_recent_limit_does_not_limit_full_export_or_history(self):
        self.add_configs(110)
        for index in range(110):
            self.reserve(index)
        with app.app.test_request_context("/?view=overview"):
            recent = app.unified_client_rows()
        self.assertEqual(100, len(recent))
        self.assertEqual(110, len(app.provisioning_rows()))
        self.assertGreaterEqual(len(app.read_history(100000)), 220)

    def test_ip_change_keeps_config_and_records_event(self):
        self.add_configs(1)
        first, _ = self.reserve(1, "192.168.250.20")
        second, _ = self.reserve(1, "192.168.250.21")
        self.assertEqual(first["config"], second["config"])
        self.assertEqual("192.168.250.20", second["first_dhcp_ip"])
        self.assertEqual("192.168.250.21", second["current_dhcp_ip"])
        self.assertIn("IP_CHANGED", [row["event_type"] for row in app.read_history(1000)])

    def test_ip_conflict_blocks_other_mac(self):
        self.add_configs(2)
        self.reserve(1, "192.168.250.20")
        second, error = self.reserve(2, "192.168.250.20")
        self.assertIsNone(second)
        self.assertEqual("IP_CONFLICT", error)

    def test_empty_syslog_does_not_affect_allocation(self):
        self.add_configs(1)
        app.SYSLOG_FILE.write_text("", encoding="utf-8")
        assigned, error = self.reserve(1)
        self.assertFalse(error)
        self.assertEqual("switch-001.conf", assigned["config"])

    def test_identical_option60_still_allocates_by_mac(self):
        self.add_configs(3)
        assigned = [self.reserve(index, option60="Juniper-ex4100")[0]["config"] for index in range(3)]
        self.assertEqual(3, len(set(assigned)))

    def test_vendor_profile_allocates_only_from_named_pool(self):
        state = app._default_provisioning_state()
        state["project"].update({"name": "ex-rollout", "status": "ACTIVE",
                                  "expected_devices": 0, "next_sequence": 1})
        entries = [
            ("OXISANTA_EX4100_PC01.conf", "OXISANTA_EX4100"),
            ("OXISANTA_EX4100_PC02.conf", "OXISANTA_EX4100"),
            ("OXISANTA_EX4400_PC01.conf", "OXISANTA_EX4400"),
        ]
        for order, (filename, pool_name) in enumerate(entries, start=1):
            path = app.NGINX_DIR / filename
            path.write_text(VALID_CONFIG, encoding="utf-8")
            state["configs"][filename] = {
                "status": "AVAILABLE", "checksum": app.config_sha256(path),
                "allocation_order": order, "assigned_device": "", "pool_name": pool_name,
                "file_size": path.stat().st_size,
            }
        app.commit_provisioning_state(state)
        profile = {"label": "EX4100 OXISANTA", "vendor_class": "Juniper-ex4100-h-12mp-xxx",
                   "match_mode": "contains", "assignment_type": "AUTO",
                   "pool_name": "OXISANTA_EX4100", "option60_confirmed": "yes"}
        app.PROFILES_JSON.write_text(
            '[{"label":"EX4100 OXISANTA","vendor_class":"Juniper-ex4100-h-12mp-xxx",'
            '"match_mode":"contains","assignment_type":"AUTO",'
            '"pool_name":"OXISANTA_EX4100","option60_confirmed":"yes"}]',
            encoding="utf-8")
        app.SYSLOG_FILE.write_text(
            'dhcpd vendor-class-identifier "Juniper-ex4100-h-12mp-xxx" 192.168.250.20',
            encoding="utf-8")
        first_lease = self.lease(1, option60="")
        second_lease = self.lease(2, option60="")
        first, first_error = app.reserve_project_assignment(
            "192.168.250.20", first_lease)
        second, second_error = app.reserve_project_assignment(
            "192.168.250.21", second_lease, profile=profile)
        self.assertFalse(first_error)
        self.assertFalse(second_error)
        self.assertEqual("OXISANTA_EX4100_PC01.conf", first["config"])
        self.assertEqual("OXISANTA_EX4100_PC02.conf", second["config"])
        self.assertEqual("OXISANTA_EX4100", first["pool_name"])
        self.assertNotIn("OXISANTA_EX4400", {first["config"], second["config"]})

    def test_vendor_profile_pool_empty_does_not_fallback_to_other_model(self):
        self.add_configs(1)
        profile = {"label": "EX4100 OXISANTA", "vendor_class": "Juniper-ex4100-h-12mp-xxx",
                   "match_mode": "contains", "assignment_type": "AUTO",
                   "pool_name": "OXISANTA_EX4100", "option60_confirmed": "yes"}
        state = app.read_provisioning_state()
        only_file = next(iter(state["configs"].values()))
        only_file["pool_name"] = "OXISANTA_EX4400"
        app.commit_provisioning_state(state)
        assigned, error = app.reserve_project_assignment(
            "192.168.250.20", self.lease(1, option60=profile["vendor_class"]), profile=profile)
        self.assertIsNone(assigned)
        self.assertEqual("PROFILE_POOL_EMPTY", error)

    def test_configs_directory_is_blocked_in_ztp_mode(self):
        self.add_configs(1)
        client = app.app.test_client()
        self.assertEqual(403, client.get("/configs/").status_code)

    def test_configs_directory_works_in_dhcp_file_server_mode(self):
        self.add_configs(1)
        client = app.app.test_client()
        self.set_mode("DHCP_FILE_SERVER")
        response = client.get("/configs/")
        self.assertEqual(200, response.status_code)
        self.assertIn(b"switch-001.conf", response.data)

    def test_migration_is_idempotent_and_keeps_backup(self):
        filename = "legacy.conf"
        path = app.NGINX_DIR / filename
        path.write_text(VALID_CONFIG, encoding="utf-8")
        app._atomic_write_json(app.CONFIG_POOL_JSON, [{
            "filename": filename, "status": "AVAILABLE", "checksum": app.config_sha256(path),
            "allocation_order": 1, "assigned_device": ""}])
        app._atomic_write_json(app.ASSIGNMENTS_JSON, {})
        self.assertTrue(app.migrate_provisioning_state())
        first = app.PROVISIONING_STATE_JSON.read_bytes()
        self.assertFalse(app.migrate_provisioning_state())
        self.assertEqual(first, app.PROVISIONING_STATE_JSON.read_bytes())
        self.assertTrue((app.DATA_DIR / "migration-backup-provisioning-v1" / "config_pool.json").is_file())


if __name__ == "__main__":
    unittest.main()
