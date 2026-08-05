import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

os.environ.setdefault("ZTP_DEV", "1")
import app


class ThreeModeAcceptanceTests(unittest.TestCase):
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

    def _settings(self, mode="ZTP_PROVISIONING"):
        value = dict(app.DEFAULT_SETTINGS)
        value.update({"operating_mode": mode, "global_mode": mode,
                      "server_ip": "192.168.250.1", "subnet": "192.168.250.0",
                      "netmask": "255.255.255.0", "range_low": "192.168.250.10",
                      "range_high": "192.168.250.254"})
        app.write_settings(value)
        return value

    def test_templates_are_mode_specific(self):
        settings = self._settings("ZTP_PROVISIONING")
        profile = [{"vendor_class": "EX4100", "match_mode": "contains", "assignment_type": "AUTO"}]
        ztp = app.generate_dhcpd(settings, [], profile)
        self.assertIn('"ztp/config"', ztp)
        dhcp_file = app.generate_dhcpd(dict(settings, operating_mode="DHCP_FILE_SERVER", global_mode="DHCP_FILE_SERVER"), [], [])
        self.assertNotIn("config-file-name", dhcp_file)
        self.assertIn("subnet 192.168.250.0", dhcp_file)
        self.assertIn("FILE_SERVER_ONLY", app.generate_dhcpd(dict(settings, operating_mode="FILE_SERVER_ONLY"), [], []))

    def test_auto_pool_is_explicit_opt_in(self):
        self._settings()
        config = b"system { root-authentication { encrypted-password x; } }"
        result = app.upload_config_bytes("edge.conf", config)
        self.assertEqual(result["result"], "ADDED")
        lease = {"mac": "aa:bb:cc:dd:ee:01", "client_id": "", "state": "active"}
        assignment, error = app.reserve_auto_assignment("mac:aa:bb:cc:dd:ee:01", None,
                                                        {"pool_name": ""}, lease, "mac:aa:bb:cc:dd:ee:01")
        self.assertIsNotNone(assignment)
        self.assertEqual(assignment["state"], "REVIEW_REQUIRED")
        self.assertEqual(error, "AUTO_POOL_EMPTY")
        pool = app.read_config_pool(); pool[0]["auto_pool_enabled"] = True; pool[0]["allow_any_model"] = True
        app.write_config_pool(pool)
        assignment, error = app.reserve_auto_assignment("mac:aa:bb:cc:dd:ee:01", None,
                                                        {"pool_name": ""}, lease, "mac:aa:bb:cc:dd:ee:01")
        self.assertFalse(error)
        self.assertEqual(assignment["filename"], "edge.conf")

    def test_legacy_dhcp_only_is_not_resolved(self):
        self._settings()
        app.LEASES_FILE.write_text("lease 192.168.250.10 { hardware ethernet aa:bb:cc:dd:ee:02; binding state active; }")
        app.DEVICES_JSON.write_text(json.dumps([{"match_method": "mac", "mac_address": "aa:bb:cc:dd:ee:02",
                                                  "hostname": "legacy", "assignment_type": "DHCP_ONLY"}]))
        state = app.read_provisioning_state()
        state["project"].update({"status": "ACTIVE", "expected_devices": 0})
        app.commit_provisioning_state(state)
        body, detail, status = app.dynamic_config_result("192.168.250.10")
        self.assertIsNone(body)
        self.assertEqual((detail, status), ("OPTION60_NOT_CAPTURED", 409))
        self.assertEqual(app.read_assignments(), {})

    def test_nginx_reconciliation_promotes_only_complete_download(self):
        self._settings("FILE_SERVER_ONLY")
        self.assertEqual(app.operating_mode(), "FILE_SERVER_ONLY")
        data = b"set system host-name edge;"
        app.NGINX_DIR.joinpath("edge.conf").write_bytes(data)
        line = f'192.168.250.10 [02/Aug/2026:12:00:00 +0000] "GET /configs/edge.conf HTTP/1.1" 200 {len(data)} 0.01 "req-1" "" "" "" "" "test"\n'
        app.NGINX_ACCESS.write_text(line)
        first = app.reconcile_downloads()
        second = app.reconcile_downloads()
        self.assertEqual(len(first), len(second))
        self.assertEqual(second[-1]["download_state"], "DOWNLOADED")
        self.assertEqual(len(app.read_download_records()), 1)

    def test_ztp_reconciliation_records_delivered_history_without_duplicate_device_key(self):
        self._settings("ZTP_PROVISIONING")
        data = b"system { root-authentication { encrypted-password x; } }"
        app.NGINX_DIR.joinpath("edge.conf").write_bytes(data)
        state = app.read_provisioning_state()
        state["project"]["status"] = "ACTIVE"
        state["devices"]["serial:serial001"] = {
            "serial": "SERIAL001", "filename": "edge.conf", "current_dhcp_ip": "192.168.250.20",
            "state": "FETCHING", "status": "ASSIGNED", "assignment_type": "AUTO"}
        state["configs"]["edge.conf"] = {
            "status": "ASSIGNED", "assigned_device": "serial:serial001",
            "assigned_serial": "SERIAL001", "checksum": "test"}
        app.commit_provisioning_state(state)
        app.NGINX_ACCESS.write_text(
            f'192.168.250.20 [02/Aug/2026:12:00:00 +0000] "GET /ztp/config HTTP/1.1" '
            f'200 {len(data)} 0.01 "req-ztp" "edge.conf" "test" "AUTO" "{len(data)}" "test"\n')

        app.reconcile_downloads()

        delivered = app.read_provisioning_state()["devices"]["serial:serial001"]
        self.assertEqual(delivered["state"], "DELIVERED")
        history = app.read_history()
        self.assertEqual(history[-1]["event_type"], "DELIVERED")
        self.assertEqual(history[-1]["device_key"], "serial:serial001")

    def test_live_deployment_status_api(self):
        self._settings("ZTP_PROVISIONING")
        response = app.app.test_client().get("/api/deployment-status")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn("rows", payload)
        self.assertIn("metrics", payload)

    def test_protected_update_and_unchanged_upload(self):
        self._settings()
        data = b"system { root-authentication { encrypted-password x; } }"
        self.assertEqual(app.upload_config_bytes("edge.conf", data)["result"], "ADDED")
        self.assertEqual(app.upload_config_bytes("edge.conf", data)["result"], "UNCHANGED")
        app.write_assignments({"mac:a": {"filename": "edge.conf", "assignment_type": "AUTO",
                                           "state": "DELIVERED", "status": "DELIVERED"}})
        result = app.upload_config_bytes("edge.conf", data + b"\n")
        self.assertEqual(result["result"], "PROTECTED")

    def test_mode_transition_requires_confirmation(self):
        self._settings("ZTP_PROVISIONING")
        ok, _ = app._apply_operating_mode("FILE_SERVER_ONLY", confirm=False)
        self.assertFalse(ok)
        self.assertEqual(app.read_settings()["operating_mode"], "ZTP_PROVISIONING")
        ok, _ = app._apply_operating_mode("FILE_SERVER_ONLY", confirm=True)
        self.assertTrue(ok)
        self.assertEqual(app.read_settings()["operating_mode"], "FILE_SERVER_ONLY")

    def test_export_excludes_secrets_and_import_checksum_is_verified(self):
        self._settings()
        app.CREDS_JSON.write_text(json.dumps({"default": {"username": "u", "password": "secret"}}))
        archive = app.build_export_archive()
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            self.assertNotIn("state/creds.json", zf.namelist())
            self.assertNotIn("admin_auth.json", " ".join(zf.namelist()))
        with zipfile.ZipFile(io.BytesIO(archive)) as source:
            bad_out = io.BytesIO()
            with zipfile.ZipFile(bad_out, "w") as target:
                for name in source.namelist():
                    data = source.read(name)
                    if name == "manifest.json":
                        manifest = json.loads(data)
                        if manifest["files"]:
                            manifest["files"][0]["sha256"] = "0" * 64
                        data = (json.dumps(manifest) + "\n").encode()
                    target.writestr(name, data)
        ok, _message, _manifest, _payloads = app.validate_import_archive(bad_out.getvalue())
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
