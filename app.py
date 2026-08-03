#!/usr/bin/env python3
"""
ZTP Web App (Flask) — vendor-neutral Juniper ZTP over HTTP (Nginx) + ISC-DHCP.  [v26.08.07]
Author: binh.trinh

Matching (method-driven, not model-hardcoded):
  - Specific "By Serial" -> if/elsif  option vendor-class-identifier ~= "<serial>$"
  - Specific "By MAC"     -> host { hardware ethernet ...; }
  - Generic Profile       -> elsif option vendor-class-identifier ~= "<vendor-class>"
File-server advertised via Option 66 (tftp-server-name).

v26.08.07: editable DHCP pool (settings.json), SSH credential store (creds.json, default +
per-device), config auto-checks (override-aware), bindings + ping/SSH health to a
post-ZTP management IP (any subnet), production WSGI (waitress).

Run:
  ZTP_DEV=1 python app.py            # dev (Flask reloader)
  python app.py                      # production via waitress (if installed)
"""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import tempfile
import subprocess
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import partial
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - production target is Linux/WSL
    fcntl = None

from flask import (Flask, Response, flash, jsonify, redirect, render_template,
                   request, send_from_directory, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------- paths -----
APP_DIR      = Path(__file__).resolve().parent
NGINX_DIR    = Path(os.environ.get("ZTP_WEBROOT", "/var/www/html/configs"))
UPLOAD_DIR   = Path(os.environ.get("ZTP_UPLOADS", str(APP_DIR / "uploads")))
DEVICES_JSON = Path(os.environ.get("ZTP_DEVICES", str(APP_DIR / "devices.json")))
STATIC_MAPPINGS_JSON = Path(os.environ.get("ZTP_STATIC_MAPPINGS", str(APP_DIR / "static_mappings.json")))
PROFILES_JSON= Path(os.environ.get("ZTP_PROFILES", str(APP_DIR / "generic_profiles.json")))
SETTINGS_JSON= Path(os.environ.get("ZTP_SETTINGS", str(APP_DIR / "settings.json")))
CREDS_JSON   = Path(os.environ.get("ZTP_CREDS", str(APP_DIR / "creds.json")))
CONFIG_POOL_JSON = Path(os.environ.get("ZTP_CONFIG_POOL", str(APP_DIR / "config_pool.json")))
ASSIGNMENTS_JSON = Path(os.environ.get("ZTP_ASSIGNMENTS", str(APP_DIR / "assignments.json")))
RESULTS_JSON = Path(os.environ.get("ZTP_RESULTS", str(APP_DIR / "results.json")))
HISTORY_JSONL = Path(os.environ.get("ZTP_HISTORY", str(APP_DIR / "history.jsonl")))
ALLOCATION_LOCK = Path(os.environ.get("ZTP_ALLOCATION_LOCK", str(APP_DIR / ".allocation.lock")))
HISTORY_LOCK = Path(os.environ.get("ZTP_HISTORY_LOCK", str(APP_DIR / ".history.lock")))
ADMIN_AUTH_JSON = Path(os.environ.get("ZTP_ADMIN_FILE", str(APP_DIR / "admin_auth.json")))
SECRET_FILE  = Path(os.environ.get("ZTP_SECRET_FILE", str(APP_DIR / ".secret_key")))
DHCPD_CONF   = Path(os.environ.get("ZTP_DHCPD", "/etc/dhcp/dhcpd.conf"))
LEASES_FILE  = Path(os.environ.get("ZTP_LEASES", "/var/lib/dhcp/dhcpd.leases"))
SYSLOG_FILE  = Path(os.environ.get("ZTP_SYSLOG", "/var/log/syslog"))
NGINX_ACCESS = Path(os.environ.get("ZTP_NGINX_ACCESS", "/var/log/nginx/access.log"))
DHCP_INTERFACE_FILE = Path(os.environ.get("ZTP_DHCP_INTERFACE_FILE", "/etc/default/isc-dhcp-server"))
DEV_MODE     = os.environ.get("ZTP_DEV", "0") == "1"
SSH_PORT     = int(os.environ.get("ZTP_SSH_PORT", "22"))

# Default DHCP pool — RFC1918 192.168.250.0/24. Editable in the UI.
DEFAULT_SETTINGS = {
    "global_mode": os.environ.get("ZTP_MODE", "FULL_ZTP"),
    "server_ip": os.environ.get("ZTP_VM_IP", "192.168.250.1"),
    "subnet":    os.environ.get("ZTP_SUBNET", "192.168.250.0"),
    "netmask":   os.environ.get("ZTP_NETMASK", "255.255.255.0"),
    "range_low": os.environ.get("ZTP_RANGE_LOW", "192.168.250.10"),
    "range_high":os.environ.get("ZTP_RANGE_HIGH", "192.168.250.254"),
    "internet_interface": os.environ.get("ZTP_INTERNET_INTERFACE", ""),
    "ztp_interface":      os.environ.get("ZTP_INTERFACE", ""),
    "assigned_no_fetch_minutes": os.environ.get("ZTP_ASSIGNED_NO_FETCH_MINUTES", "5"),
    "repeated_fetch_limit": os.environ.get("ZTP_REPEATED_FETCH_LIMIT", "5"),
    "repeated_fetch_window_minutes": os.environ.get("ZTP_REPEATED_FETCH_WINDOW_MINUTES", "10"),
    "dhcp_retry_limit": os.environ.get("ZTP_DHCP_RETRY_LIMIT", "10"),
    "dhcp_retry_window_minutes": os.environ.get("ZTP_DHCP_RETRY_WINDOW_MINUTES", "5"),
}

ALLOWED_EXT   = {".txt", ".conf"}
MATCH_METHODS = ["serial", "mac"]
GLOBAL_MODES = ["FULL_ZTP", "FILE_SERVER_ONLY"]
ASSIGNMENT_TYPES = ["STATIC", "AUTO", "DHCP_ONLY"]
CONFIG_STATUSES = ["AVAILABLE", "RESERVED", "FETCHED", "PENDING_CHECK", "COMPLETED", "FAILED", "MISSING"]
PROVISION_STATES = ["DHCP_SEEN", "DHCP_ONLY", "ASSIGNED", "ASSIGNED_NO_FETCH", "FETCHING",
                    "FETCHED", "FETCH_FAILED", "REPEATED_FETCH", "DHCP_RETRY_LOOP",
                    "PENDING_CHECK", "COMPLETED", "FAILED", "REVIEW_REQUIRED"]
URL_MAX       = 256
SERIAL_RE       = re.compile(r"^[A-Za-z0-9]+$")
VENDOR_CLASS_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
MAC_RE          = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
PROFILE_REGEX_TEXT_RE = re.compile(r'^[^\r\n"]{1,160}$')
DEVICE_FIELDS = ["match_method", "serial_number", "mac_address", "device_type",
                 "hostname", "ip_address", "mgmt_ip", "client_id", "compatibility_group",
                 "specific_config_file", "assignment_type", "pool_name", "option60_confirmed"]
PROFILE_MATCH_MODES = ["contains", "regex"]
PROFILE_FIELDS = ["label", "vendor_class", "match_mode", "config_file", "assignment_type",
                  "pool_name", "compatibility_group", "option60_confirmed"]
SETTINGS_FIELDS = ["server_ip", "subnet", "netmask", "range_low", "range_high",
                   "internet_interface", "ztp_interface", "global_mode",
                   "assigned_no_fetch_minutes", "repeated_fetch_limit",
                   "repeated_fetch_window_minutes", "dhcp_retry_limit",
                   "dhcp_retry_window_minutes"]
AUTHOR = "binh.trinh"
VERSION = "26.08.07"   # provisioning modes, Auto Pool and manual verification release


class JsonDataError(RuntimeError):
    """A runtime JSON file is unreadable; never silently treat it as empty."""


def _atomic_write_json(path: Path, data, mode: int = 0o600) -> None:
    """Backup and atomically replace a JSON runtime file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = path.with_name(path.name + ".bak")
    tmp_name = None
    try:
        if path.exists():
            shutil.copy2(path, backup)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except (OSError, TypeError, ValueError) as exc:
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        raise JsonDataError(f"Cannot safely write {path}: {exc}") from exc

def _load_secret_key() -> str:
    """ZTP_SECRET env wins; otherwise persist a random key to SECRET_FILE (chmod 600)
    so flash-message cookies aren't signed with the old hardcoded default."""
    env = os.environ.get("ZTP_SECRET")
    if env:
        return env
    if SECRET_FILE.exists():
        return SECRET_FILE.read_text().strip()
    key = secrets.token_hex(32)
    try:
        fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key)
        os.chmod(SECRET_FILE, 0o600)
    except OSError:
        pass
    return key


app = Flask(__name__)
app.secret_key = _load_secret_key()

for d in (NGINX_DIR, UPLOAD_DIR):
    try:
        d.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        pass


# --------------------------------------------------------- admin auth -------
def _save_admin(username: str, password: str) -> None:
    data = {"username": username, "password_hash": generate_password_hash(password)}
    try:
        fd = os.open(ADMIN_AUTH_JSON, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.chmod(ADMIN_AUTH_JSON, 0o600)
    except OSError:
        pass


def _bootstrap_admin() -> None:
    """Create admin_auth.json (chmod 600) on first run. Default login is
    admin/admin (or ZTP_ADMIN_USER/ZTP_ADMIN_PASSWORD) — change it from the
    UI (Dashboard -> Admin Login) before exposing this beyond an isolated lab."""
    if ADMIN_AUTH_JSON.exists():
        return
    user = os.environ.get("ZTP_ADMIN_USER", "admin")
    pw = os.environ.get("ZTP_ADMIN_PASSWORD", "admin")
    _save_admin(user, pw)
    print("=== ZTP Manager: admin login initialized ===")
    print(f"  username: {user}")
    print(f"  password: {pw}")
    print("  Default credentials — change them at Dashboard -> Admin Login.")
    print("==============================================")


def _check_admin(user: str, pw: str) -> bool:
    if not (user and pw) or not ADMIN_AUTH_JSON.exists():
        return False
    data = _read_json(ADMIN_AUTH_JSON, {})
    return user == data.get("username") and check_password_hash(data.get("password_hash", ""), pw)


if not DEV_MODE:
    _bootstrap_admin()


@app.before_request
def _require_auth():
    """GUI is protected by HTTP Basic Auth in production. /configs/* stays open —
    Junos devices fetch their config there during ZTP and can't present credentials.
    Auth is skipped entirely under ZTP_DEV=1 (local dev / _smoketest.py)."""
    if DEV_MODE or request.path.startswith("/configs/") or request.path == "/ztp/config":
        return None
    auth = request.authorization
    if not auth or not _check_admin(auth.username, auth.password):
        return Response("Authentication required.", 401,
                        {"WWW-Authenticate": 'Basic realm="ZTP Manager"'})


@app.errorhandler(JsonDataError)
def _json_data_error(exc):
    """Show runtime JSON corruption as an actionable UI error, never as empty data."""
    return Response(f"JSON error; no deployment performed: {exc}\n", 500,
                    mimetype="text/plain")


# --------------------------------------------------------- json helpers -----
def _read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JsonDataError(f"Cannot read valid JSON from {path}: {exc}") from exc


def _validate_string_records(path: Path, rows, kind: str) -> None:
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise JsonDataError(f"Expected {path} to contain a JSON array of {kind} objects.")
    for row in rows:
        if any(not isinstance(value, str) for value in row.values()):
            raise JsonDataError(f"Expected all values in {path} to be strings.")


def read_devices():
    source = STATIC_MAPPINGS_JSON if STATIC_MAPPINGS_JSON.exists() else DEVICES_JSON
    rows = _read_json(source, [])
    _validate_string_records(source, rows, "device")
    for row in rows:
        row.setdefault("option60_confirmed", "")
        row.setdefault("client_id", "")
        row.setdefault("compatibility_group", "")
        # Legacy rows without a dedicated file are DHCP_ONLY (they may still
        # be tracked in the inventory, but must not accidentally shadow a
        # Generic Profile as an incomplete STATIC rule).
        if not row.get("assignment_type"):
            row["assignment_type"] = "STATIC" if row.get("specific_config_file") else "DHCP_ONLY"
        row.setdefault("pool_name", "")
        row.setdefault("compatibility_group", "")
    return rows
def write_devices(rows):
    _atomic_write_json(STATIC_MAPPINGS_JSON, rows)
    _atomic_write_json(DEVICES_JSON, rows)
def read_profiles():
    rows = _read_json(PROFILES_JSON, [])
    _validate_string_records(PROFILES_JSON, rows, "profile")
    for row in rows:
        row.setdefault("match_mode", "contains")
        row.setdefault("option60_confirmed", "")
        row.setdefault("assignment_type", "STATIC" if row.get("config_file") else "DHCP_ONLY")
        row.setdefault("pool_name", "")
    return rows
def write_profiles(rows): _atomic_write_json(PROFILES_JSON, rows)


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def _confirmed(value) -> bool:
    return str(value or "").strip().lower() in {"1", "yes", "true", "on"}


def _serial_overlap(left: str, right: str) -> bool:
    """Both serial rules are suffix regexes, so a shorter suffix can catch the longer one."""
    return bool(left and right and left != right and (left.endswith(right) or right.endswith(left)))


def _vendor_overlap(left: str, right: str) -> bool:
    """Vendor-class rules use an unanchored DHCP regex search; substring rules can shadow each other."""
    left, right = left.lower(), right.lower()
    return bool(left and right and left != right and (left in right or right in left))


def profile_match_expression(profile: dict) -> str:
    """Build the DHCP regex while keeping legacy profiles literal by default."""
    value = profile.get("vendor_class", "")
    if profile.get("match_mode", "contains") == "regex":
        return value
    return re.escape(value)


def mapping_issues(devices=None, profiles=None) -> list[str]:
    """Return deterministic warnings for ambiguous or malformed multi-device rules."""
    devices = read_devices() if devices is None else devices
    profiles = read_profiles() if profiles is None else profiles
    issues = []
    serials = {}
    macs = {}
    for row in devices:
        host = row.get("hostname") or "(unnamed device)"
        kind = assignment_type(row, "STATIC")
        if kind not in ASSIGNMENT_TYPES:
            issues.append(f"{host}: unknown assignment type '{row.get('assignment_type')}'.")
        if kind == "AUTO" and row.get("specific_config_file"):
            issues.append(f"{host}: AUTO assignment still has a static config file.")
        serial = row.get("serial_number", "")
        mac = row.get("mac_address", "").lower()
        if serial:
            if not SERIAL_RE.fullmatch(serial):
                issues.append(f"{host}: Serial must be alphanumeric.")
            if serial in serials:
                issues.append(f"Duplicate Serial '{serial}' on {serials[serial]} and {host}.")
            serials[serial] = host
            if row.get("match_method") == "serial" and not _confirmed(row.get("option60_confirmed")):
                issues.append(f"{host}: Serial rule is not confirmed against a real DHCP Option 60 capture.")
        if mac:
            if not MAC_RE.fullmatch(mac):
                issues.append(f"{host}: MAC must use aa:bb:cc:dd:ee:ff format.")
            if mac in macs:
                issues.append(f"Duplicate MAC '{mac}' on {macs[mac]} and {host}.")
            macs[mac] = host
        for field in ("ip_address", "mgmt_ip"):
            value = row.get(field, "")
            if value and not _valid_ipv4(value):
                issues.append(f"{host}: {field} is not a valid IPv4 address.")
    serial_items = list(serials)
    for idx, left in enumerate(serial_items):
        for right in serial_items[idx + 1:]:
            if _serial_overlap(left, right):
                issues.append(f"Serial suffixes '{left}' and '{right}' overlap; first DHCP rule wins.")
    vendors = {}
    for profile in profiles:
        vendor = profile.get("vendor_class", "")
        mode = profile.get("match_mode", "contains")
        label = profile.get("label") or vendor or "(unnamed profile)"
        kind = assignment_type(profile, "STATIC")
        if kind not in ASSIGNMENT_TYPES:
            issues.append(f"{label}: unknown assignment type '{profile.get('assignment_type')}'.")
        if not _confirmed(profile.get("option60_confirmed")):
            issues.append(f"{label}: Generic Profile is not confirmed against a real DHCP Option 60 capture.")
        if mode not in PROFILE_MATCH_MODES:
            issues.append(f"{label}: unknown match mode '{mode}'.")
        elif mode == "contains" and not VENDOR_CLASS_RE.fullmatch(vendor):
            issues.append(f"{label}: Vendor class contains unsupported characters.")
        elif mode == "regex":
            try:
                re.compile(vendor)
                issues.append(f"{label}: Regex mode requires a real DHCP Option 60 test before production.")
            except re.error as exc:
                issues.append(f"{label}: invalid regex ({exc}).")
        if vendor in vendors:
            issues.append(f"Duplicate Vendor class '{vendor}' on {vendors[vendor]} and {label}.")
        vendors[vendor] = label
    vendor_items = list(vendors)
    for idx, left in enumerate(vendor_items):
        for right in vendor_items[idx + 1:]:
            if _vendor_overlap(left, right):
                issues.append(f"Vendor classes '{left}' and '{right}' overlap; first DHCP rule wins.")
    return issues


def _fixed_ip_errors(value: str, settings: dict, label: str = "DHCP IP") -> list[str]:
    if not value:
        return []
    errors = []
    try:
        fixed = ipaddress.IPv4Address(value)
        network = ipaddress.IPv4Network(f"{settings['subnet']}/{settings['netmask']}", strict=False)
        low = ipaddress.IPv4Address(settings["range_low"])
        high = ipaddress.IPv4Address(settings["range_high"])
        server = ipaddress.IPv4Address(settings["server_ip"])
    except (KeyError, ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
        return [f"{label} cannot be checked against the ZTP subnet: {exc}."]
    if fixed not in network:
        errors.append(f"{label} {fixed} must be inside ZTP subnet {network}.")
    if fixed == server:
        errors.append(f"{label} {fixed} must not equal Server IP.")
    if low <= fixed <= high:
        errors.append(f"{label} {fixed} must not be inside the dynamic DHCP range {low}-{high}.")
    if fixed not in network.hosts():
        errors.append(f"{label} {fixed} cannot be the network or broadcast address.")
    return errors


def validate_device_row(row: dict, existing=None, settings=None) -> list[str]:
    """Validate form/import data before it can change the generated DHCP rules."""
    existing = read_devices() if existing is None else existing
    settings = read_settings() if settings is None else settings
    errors = []
    method = row.get("match_method", "")
    host = row.get("hostname", "")
    kind = assignment_type(row, "STATIC")
    if method not in MATCH_METHODS:
        errors.append("Match method must be serial or mac.")
    if kind not in ASSIGNMENT_TYPES:
        errors.append("Assignment type must be STATIC, AUTO or DHCP_ONLY.")
    if not host:
        errors.append("Hostname is required.")
    serial = row.get("serial_number", "")
    mac = row.get("mac_address", "").lower()
    if serial and not SERIAL_RE.fullmatch(serial):
        errors.append("Serial must contain letters and digits only.")
    if method == "serial" and not _confirmed(row.get("option60_confirmed")):
        errors.append("Serial matching requires confirmation that the serial is at the end of DHCP Option 60.")
    if mac and not MAC_RE.fullmatch(mac):
        errors.append("MAC must use aa:bb:cc:dd:ee:ff format.")
    if method == "mac" and row.get("specific_config_file") and not row.get("ip_address"):
        errors.append("DHCP IP is required for a By-MAC device with its own config file.")
    if method == "mac" and kind == "AUTO" and not row.get("ip_address"):
        errors.append("DHCP IP is required for a By-MAC AUTO device.")
    if kind == "AUTO" and row.get("specific_config_file"):
        errors.append("AUTO assignment cannot also specify a static config file.")
    if kind == "DHCP_ONLY" and row.get("specific_config_file"):
        errors.append("DHCP_ONLY assignment cannot specify a config file.")
    if kind == "STATIC" and not row.get("specific_config_file"):
        errors.append("STATIC assignment requires a specific config file; use DHCP_ONLY for IP-only inventory.")
    for field in ("ip_address", "mgmt_ip"):
        value = row.get(field, "")
        if value and not _valid_ipv4(value):
            errors.append(f"{field} must be a valid IPv4 address.")
    errors.extend(_fixed_ip_errors(row.get("ip_address", ""), settings))
    if row.get("specific_config_file"):
        errors.extend(config_file_errors(row["specific_config_file"], settings=settings))
    for other in existing:
        if host and other.get("hostname") == host:
            errors.append(f"Hostname '{host}' is already mapped to another device.")
        if serial:
            other_serial = other.get("serial_number", "")
            if serial == other_serial:
                errors.append(f"Serial '{serial}' is already mapped to {other.get('hostname')}.")
            elif other_serial and _serial_overlap(serial, other_serial):
                errors.append(f"Serial '{serial}' overlaps '{other_serial}' on {other.get('hostname')}.")
        if mac:
            if mac == other.get("mac_address", "").lower():
                errors.append(f"MAC '{mac}' is already mapped to {other.get('hostname')}.")
        if row.get("ip_address") and row.get("ip_address") == other.get("ip_address"):
            errors.append(f"DHCP IP '{row['ip_address']}' is already mapped to {other.get('hostname')}.")
        if row.get("mgmt_ip") and row.get("mgmt_ip") == other.get("mgmt_ip"):
            errors.append(f"Management IP '{row['mgmt_ip']}' is already mapped to {other.get('hostname')}.")
        if row.get("client_id") and row.get("client_id").lower() == other.get("client_id", "").lower():
            errors.append(f"Client ID '{row['client_id']}' is already mapped to {other.get('hostname')}.")
    return errors


def validate_profile_row(profile: dict, existing=None, settings=None) -> list[str]:
    existing = read_profiles() if existing is None else existing
    settings = read_settings() if settings is None else settings
    errors = []
    vendor = profile.get("vendor_class", "")
    mode = profile.get("match_mode", "contains")
    kind = assignment_type(profile, "STATIC")
    if not vendor:
        errors.append("Vendor class is required.")
    elif kind not in ASSIGNMENT_TYPES:
        errors.append("Assignment type must be STATIC, AUTO or DHCP_ONLY.")
    elif mode not in PROFILE_MATCH_MODES:
        errors.append("Match mode must be Contains or Regex.")
    elif mode == "contains" and not VENDOR_CLASS_RE.fullmatch(vendor):
        errors.append("Vendor class may contain only letters, digits, '.', '_' and '-'.")
    elif mode == "regex":
        if not PROFILE_REGEX_TEXT_RE.fullmatch(vendor):
            errors.append("Regex must be 1–160 characters without quotes or newlines.")
        else:
            try:
                re.compile(vendor)
            except re.error as exc:
                errors.append(f"Regex is invalid: {exc}.")
    if not _confirmed(profile.get("option60_confirmed")):
        errors.append("Generic Profile requires confirmation from a real DHCP Option 60 capture.")
    if kind == "STATIC" and not profile.get("config_file"):
        errors.append("STATIC profile requires a config file.")
    if kind in {"AUTO", "DHCP_ONLY"} and profile.get("config_file"):
        errors.append(f"{kind} profile cannot specify a static config file.")
    if profile.get("config_file") and kind == "STATIC":
        errors.extend(config_file_errors(profile["config_file"], settings=settings))
    for other in existing:
        other_vendor = other.get("vendor_class", "")
        other_mode = other.get("match_mode", "contains")
        if other_vendor == vendor and other_mode == mode:
            continue
        if mode == "contains" and other_mode == "contains" and _vendor_overlap(vendor, other_vendor):
            errors.append(f"Vendor class '{vendor}' overlaps '{other_vendor}'; first DHCP rule wins.")
    return errors


def read_settings() -> dict:
    s = dict(DEFAULT_SETTINGS)
    raw = _read_json(SETTINGS_JSON, {})
    if not isinstance(raw, dict):
        raise JsonDataError(f"Expected {SETTINGS_JSON} to contain a JSON object.")
    if any(not isinstance(value, str) for value in raw.values()):
        raise JsonDataError(f"Expected all values in {SETTINGS_JSON} to be strings.")
    s.update({k: v for k, v in raw.items() if k in SETTINGS_FIELDS and v})
    if s.get("global_mode") not in GLOBAL_MODES:
        s["global_mode"] = "FULL_ZTP"
    return s


def write_settings(s: dict):
    _atomic_write_json(SETTINGS_JSON, {k: s.get(k, "") for k in SETTINGS_FIELDS})


def is_full_ztp(settings: dict | None = None) -> bool:
    return (settings or read_settings()).get("global_mode", "FULL_ZTP") == "FULL_ZTP"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_int(settings: dict, key: str, fallback: int) -> int:
    try:
        return max(0, int(settings.get(key, fallback)))
    except (TypeError, ValueError):
        return fallback


@contextmanager
def _exclusive_lock(path: Path):
    """Hold an exclusive Linux file lock for allocation/history mutations."""
    if fcntl is None:
        raise RuntimeError("Exclusive file locking requires fcntl on Linux/WSL.")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield handle
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _read_object_store(path: Path, default: dict) -> dict:
    value = _read_json(path, default)
    if not isinstance(value, dict):
        raise JsonDataError(f"Expected {path} to contain a JSON object.")
    return value


def _read_list_store(path: Path, default: list) -> list:
    value = _read_json(path, default)
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise JsonDataError(f"Expected {path} to contain a JSON array of objects.")
    return value


def read_config_pool() -> list[dict]:
    return _read_list_store(CONFIG_POOL_JSON, [])


def write_config_pool(rows: list[dict]) -> None:
    _atomic_write_json(CONFIG_POOL_JSON, rows)


def read_assignments() -> dict:
    return _read_object_store(ASSIGNMENTS_JSON, {})


def write_assignments(data: dict) -> None:
    _atomic_write_json(ASSIGNMENTS_JSON, data)


def read_results() -> dict:
    return _read_object_store(RESULTS_JSON, {})


def write_results(data: dict) -> None:
    _atomic_write_json(RESULTS_JSON, data)


def read_history(limit: int = 1000) -> list[dict]:
    if not HISTORY_JSONL.exists():
        return []
    rows = []
    try:
        for line in HISTORY_JSONL.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError("history entry is not an object")
            rows.append(item)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise JsonDataError(f"Cannot read valid history from {HISTORY_JSONL}: {exc}") from exc
    return rows[-limit:]


def append_history(event_type: str, device_key: str = "", operator: str = "system", **fields) -> dict:
    record = {"timestamp": _now_iso(), "event_type": event_type,
              "device_key": device_key, "operator": operator}
    record.update({key: value for key, value in fields.items() if value is not None})
    HISTORY_JSONL.parent.mkdir(parents=True, exist_ok=True)
    with _exclusive_lock(HISTORY_LOCK):
        with HISTORY_JSONL.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    return record


def assignment_type(row: dict, default: str = "STATIC") -> str:
    value = str(row.get("assignment_type") or "").strip().upper()
    if value in ASSIGNMENT_TYPES:
        return value
    return default


def device_key(row: dict | None = None, *, serial: str = "", mac: str = "",
               client_id: str = "", ip: str = "") -> str:
    row = row or {}
    serial = serial or row.get("serial_number", "")
    mac = mac or row.get("mac_address", "")
    client_id = client_id or row.get("client_id", "")
    ip = ip or row.get("ip_address", "")
    if serial:
        return f"serial:{str(serial).strip().lower()}"
    if mac:
        return f"mac:{str(mac).strip().lower()}"
    if client_id:
        return f"client-id:{str(client_id).strip().lower()}"
    return f"ip:{str(ip).strip()}" if ip else ""


def config_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def netmask_prefix_length(netmask: str) -> str:
    """Return the CIDR mask length used by the compact UI field."""
    try:
        return str(ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen)
    except (ipaddress.NetmaskValueError, ValueError):
        return ""


def prefix_length_netmask(prefix: str) -> str:
    """Convert a UI mask length to the dotted netmask stored by the app."""
    if not re.fullmatch(r"\d{1,2}", prefix or ""):
        raise ValueError("Mask length must be an integer from 0 to 32.")
    length = int(prefix)
    if not 0 <= length <= 32:
        raise ValueError("Mask length must be an integer from 0 to 32.")
    return str(ipaddress.IPv4Network(f"0.0.0.0/{length}").netmask)


# --------------------------------------------------------- network selection -
def _ip_json(args):
    """Read Linux interface/route state without changing the host network."""
    if not shutil.which("ip"):
        return []
    try:
        r = subprocess.run(["ip", "-j"] + args, capture_output=True, text=True, check=True)
        return json.loads(r.stdout or "[]")
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
        return []


def network_interfaces() -> list[dict]:
    """Return interface state used by the UI and deploy safety gate."""
    links = {row.get("ifname"): row for row in _ip_json(["link", "show"])
             if row.get("ifname")}
    addresses = {}
    address_cidrs = {}
    for row in _ip_json(["-4", "addr", "show"]):
        addresses[row.get("ifname")] = [
            info.get("local") for info in row.get("addr_info", []) if info.get("local")
        ]
        address_cidrs[row.get("ifname")] = [
            f"{info.get('local')}/{info.get('prefixlen')}"
            for info in row.get("addr_info", [])
            if info.get("local") and info.get("prefixlen") is not None
        ]
    defaults = {row.get("dev") for row in _ip_json(["route", "show", "default"])
                if row.get("dev")}
    out = []
    for name in sorted(set(links) | set(addresses)):
        link = links.get(name, {})
        flags = set(link.get("flags", []))
        state = link.get("operstate", "UNKNOWN")
        ips = addresses.get(name, [])
        out.append({
            "name": name,
            "state": state,
            "up": state == "UP",
            "lower_up": "LOWER_UP" in flags,
            "addresses": ips,
            "address_cidrs": address_cidrs.get(name, []),
            "address_text": ", ".join(ips) or "no IPv4",
            "default_route": name in defaults,
        })
    return out


def validate_dhcp_pool(settings: dict | None = None) -> list[str]:
    """Validate DHCP pool structure before any config file is written."""
    s = settings or read_settings()
    errors = []
    values = {key: s.get(key, "") for key in
              ("server_ip", "subnet", "netmask", "range_low", "range_high")}
    if not all(values.values()):
        return ["ERROR: Server IP, subnet, netmask and both DHCP range values are required."]
    try:
        server = ipaddress.IPv4Address(values["server_ip"])
        low = ipaddress.IPv4Address(values["range_low"])
        high = ipaddress.IPv4Address(values["range_high"])
        network = ipaddress.IPv4Network(
            f"{values['subnet']}/{values['netmask']}", strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
        return [f"ERROR: Invalid DHCP IPv4/subnet/netmask value ({exc})."]

    if str(network.network_address) != values["subnet"]:
        errors.append(f"ERROR: Subnet must be the network address {network.network_address}.")
    if network.prefixlen >= 31:
        errors.append("ERROR: DHCP subnet must be /30 or larger; /31 and /32 have no usable pool.")
    if server not in network:
        errors.append(f"ERROR: Server IP {server} is outside subnet {network}.")
    if low not in network or high not in network:
        errors.append(f"ERROR: DHCP range must stay inside subnet {network}.")
    if low > high:
        errors.append("ERROR: Range low must not be greater than range high.")
    usable = set(network.hosts())
    for label, address in (("Server IP", server), ("Range low", low), ("Range high", high)):
        if address not in usable:
            errors.append(f"ERROR: {label} cannot be the network or broadcast address.")
    if low <= server <= high:
        errors.append("ERROR: DHCP range must not include the Server IP.")
    return errors


def dhcp_pool_suggestion(settings: dict | None = None) -> dict:
    """Suggest a pool from the selected ZTP interface without changing state."""
    s = settings or read_settings()
    ztp = s.get("ztp_interface", "")
    info = next((item for item in network_interfaces() if item["name"] == ztp), None)
    if not ztp:
        return {"ok": False, "errors": ["Select a ZTP interface first."]}
    if not info:
        return {"ok": False, "errors": [f"ZTP interface '{ztp}' was not found."]}

    candidates = []
    for cidr in info.get("address_cidrs", []):
        try:
            iface = ipaddress.IPv4Interface(cidr)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            continue
        if iface.ip.is_loopback or iface.ip.is_link_local:
            continue
        candidates.append(iface)
    if not candidates:
        return {"ok": False, "errors": [
            f"ZTP interface '{ztp}' has no usable static IPv4/CIDR yet."]}

    current_server = s.get("server_ip", "")
    selected = next((item for item in candidates if str(item.ip) == current_server), candidates[0])
    network = selected.network
    if network.prefixlen >= 31:
        return {"ok": False, "errors": [
            f"Interface address {selected} is too small for a DHCP pool."]}
    usable = list(network.hosts())
    usable_without_server = [address for address in usable if address != selected.ip]
    if not usable_without_server:
        return {"ok": False, "errors": [f"Subnet {network} has no usable DHCP address."]}

    low = next((address for address in usable_without_server
                if int(address) >= int(network.network_address) + 10),
               usable_without_server[0])
    high = usable_without_server[-1]
    if low > high:
        low, high = usable_without_server[0], usable_without_server[-1]

    return {
        "ok": True,
        "interface": ztp,
        "cidr": str(selected),
        "link_ready": bool(info.get("lower_up")),
        "values": {
            "server_ip": str(selected.ip),
            "subnet": str(network.network_address),
            "netmask": str(network.netmask),
            "prefix_length": str(network.prefixlen),
            "range_low": str(low),
            "range_high": str(high),
        },
        "warnings": ([] if info.get("lower_up") else
                     [f"ZTP interface '{ztp}' is currently down; DHCP cannot start yet."]),
    }


def network_checks(settings: dict | None = None) -> list[str]:
    """Explain interface/IP readiness; does not modify network configuration."""
    s = settings or read_settings()
    interfaces = {i["name"]: i for i in network_interfaces()}
    internet = s.get("internet_interface", "")
    ztp = s.get("ztp_interface", "")
    messages = []

    if not internet:
        messages.append("WARN: Internet interface is not selected.")
    else:
        info = interfaces.get(internet)
        if not info:
            messages.append(f"ERROR: Internet interface '{internet}' was not found.")
        elif not info["addresses"]:
            messages.append(f"WARN: Internet interface '{internet}' has no IPv4 address.")
        elif not info["default_route"]:
            messages.append(f"WARN: '{internet}' is selected for Internet but has no default route.")

    if not ztp:
        messages.append("WARN: ZTP interface is not selected; DHCP binding remains installer-managed.")
        return messages
    info = interfaces.get(ztp)
    if not info:
        messages.append(f"ERROR: ZTP interface '{ztp}' was not found.")
        return messages
    if internet and internet == ztp:
        messages.append("ERROR: Internet and ZTP interfaces must be different.")
    if not info["lower_up"]:
        messages.append(f"ERROR: ZTP interface '{ztp}' has no physical link (LOWER_UP).")
    if not info["addresses"]:
        messages.append(f"ERROR: ZTP interface '{ztp}' has no IPv4 address; DHCP/Option 66 cannot be used safely.")
    elif s.get("server_ip") and s["server_ip"] not in info["addresses"]:
        messages.append(
            f"ERROR: Server IP {s['server_ip']} is not assigned to ZTP interface '{ztp}' "
            f"({info['address_text']})."
        )
    if info.get("lower_up") and info.get("addresses"):
        messages.append("WARN: Verify that no other DHCP server is active on this ZTP L2/VLAN segment.")
    return messages


def _network_errors(settings: dict | None = None) -> list[str]:
    return [m for m in network_checks(settings) if m.startswith("ERROR:")]


def _network_warnings(settings: dict | None = None) -> list[str]:
    return [m for m in network_checks(settings) if m.startswith("WARN:")]


def apply_dhcp_interface(name: str) -> tuple[bool, str]:
    """Persist the selected DHCP interface with a recoverable backup."""
    if DEV_MODE:
        return True, "DEV_MODE: DHCP interface selection saved; service binding skipped."
    if not name:
        return True, "DHCP interface unchanged (no interface selected)."
    if not DHCP_INTERFACE_FILE.exists():
        return False, f"Cannot find {DHCP_INTERFACE_FILE}; install isc-dhcp-server first."
    try:
        old = DHCP_INTERFACE_FILE.read_text()
        new, count = re.subn(r"(?m)^INTERFACESv4=.*$", f'INTERFACESv4="{name}"', old)
        if count == 0:
            new = old.rstrip() + f'\nINTERFACESv4="{name}"\n'
        backup = DHCP_INTERFACE_FILE.with_name(DHCP_INTERFACE_FILE.name + ".ztp-app.bak")
        shutil.copy2(DHCP_INTERFACE_FILE, backup)
        tmp = DHCP_INTERFACE_FILE.with_name(DHCP_INTERFACE_FILE.name + ".tmp")
        tmp.write_text(new)
        os.replace(tmp, DHCP_INTERFACE_FILE)
        return True, f"DHCP interface set to {name}; backup: {backup}."
    except OSError as e:
        return False, f"Cannot set DHCP interface {name}: {e}"


# --------------------------------------------------------- credentials ------
def read_creds() -> dict:
    return _read_json(CREDS_JSON, {"default": None, "by_host": {}})


def write_creds(data: dict):
    _atomic_write_json(CREDS_JSON, data, mode=0o600)


def set_cred(scope: str, user: str, password: str):
    data = read_creds()
    entry = {"username": user, "password": password}
    if scope == "default":
        data["default"] = entry
    else:
        data.setdefault("by_host", {})[scope] = entry
    write_creds(data)


def get_cred(hostname: str):
    data = read_creds()
    entry = data.get("by_host", {}).get(hostname) or data.get("default")
    return (entry["username"], entry["password"]) if entry else (None, None)


def creds_overview() -> dict:
    data = read_creds()
    return {"default": (data.get("default") or {}).get("username", ""),
            "by_host": {h: e.get("username", "") for h, e in data.get("by_host", {}).items()}}


# ------------------------------------------------------------ configs -------
def _allowed(name: str) -> bool:
    return os.path.splitext(name)[1].lower() in ALLOWED_EXT


def list_configs():
    try:
        return sorted(f for f in os.listdir(NGINX_DIR) if _allowed(f))
    except FileNotFoundError:
        return []


def _metadata_models(value) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def sync_config_pool() -> list[dict]:
    """Discover files without deleting metadata or changing assigned state."""
    now = _now_iso()
    with _exclusive_lock(ALLOCATION_LOCK):
        rows = read_config_pool()
        by_name = {}
        duplicate_rows = []
        for row in rows:
            name = str(row.get("filename", "")).strip()
            if name and name not in by_name:
                row["filename"] = name
                row["supported_models"] = _metadata_models(row.get("supported_models"))
                row.setdefault("compatibility_group", "")
                row.setdefault("pool_name", "")
                row.setdefault("hostname", "")
                row.setdefault("allocation_order", len(by_name) + 1)
                row.setdefault("status", "AVAILABLE")
                by_name[name] = row
            elif name:
                duplicate_rows.append(row)
        changed = False
        for index, filename in enumerate(list_configs(), start=1):
            path = NGINX_DIR / filename
            if filename not in by_name:
                by_name[filename] = {
                    "filename": filename, "hostname": "", "supported_models": [],
                    "compatibility_group": "", "checksum": config_sha256(path),
                    "allocation_order": index, "status": "AVAILABLE", "assigned_device": "",
                    "created_at": now, "updated_at": now,
                }
                changed = True
            else:
                row = by_name[filename]
                if row.get("status") == "MISSING":
                    row["status"] = "AVAILABLE" if not row.get("assigned_device") else row.get("status")
                    changed = True
        for row in by_name.values():
            filename = row.get("filename", "")
            if filename and not (NGINX_DIR / filename).is_file() and row.get("status") != "MISSING":
                row["status"] = "MISSING"
                row["updated_at"] = now
                changed = True
        result = list(by_name.values()) + duplicate_rows
        if changed or not CONFIG_POOL_JSON.exists():
            write_config_pool(result)
        return result


def config_pool_errors(rows: list[dict] | None = None) -> list[str]:
    rows = sync_config_pool() if rows is None else rows
    errors = []
    seen = set()
    hostnames = set()
    for row in rows:
        filename = row.get("filename", "")
        if not filename:
            errors.append("Config pool entry is missing filename.")
            continue
        if filename in seen:
            errors.append(f"Config pool filename '{filename}' is duplicated.")
        seen.add(filename)
        hostname = row.get("hostname", "").strip()
        if hostname:
            if hostname in hostnames:
                errors.append(f"Config pool hostname '{hostname}' is duplicated.")
            hostnames.add(hostname)
        path = NGINX_DIR / filename
        if not path.is_file():
            errors.append(f"Config pool file '{filename}' is missing.")
            continue
        expected = row.get("checksum", "")
        if expected:
            try:
                actual = config_sha256(path)
            except OSError as exc:
                errors.append(f"Config pool file '{filename}' cannot be read: {exc}.")
            else:
                if actual != expected:
                    errors.append(f"Config pool checksum mismatch for '{filename}'.")
    return list(dict.fromkeys(errors))


def config_is_compatible(meta: dict, observed_model: str = "", compatibility_group: str = "") -> bool:
    supported = _metadata_models(meta.get("supported_models"))
    declared_group = str(meta.get("compatibility_group", "")).strip()
    observed_model = str(observed_model or "").strip()
    compatibility_group = str(compatibility_group or "").strip()
    if not supported and not declared_group:
        return True
    if observed_model and observed_model in supported:
        return True
    return bool(compatibility_group and declared_group and compatibility_group == declared_group)


def config_file_meta(filename: str, pool: list[dict] | None = None) -> dict | None:
    pool = sync_config_pool() if pool is None else pool
    return next((row for row in pool if row.get("filename") == filename), None)


def check_config_text(text: str, fname: str = "", settings: dict | None = None) -> list[str]:
    """Override-aware auto-checks. Full load-override configs are fine without a delete stmt."""
    low = text.lower()
    issues = []
    if "root-authentication" not in low:
        issues.append("no root-authentication -> ZTP commit will FAIL")
    enables_aiu = bool(re.search(r"set\s+chassis\s+auto-image-upgrade", low) or
                       re.search(r"chassis\s*\{[^}]*auto-image-upgrade\s*;", low, re.S))
    if enables_aiu:
        issues.append("enables 'chassis auto-image-upgrade' -> device will re-enter ZTP loop")
    if fname:
        url = f"http://{(settings or read_settings())['server_ip']}/configs/{fname}"
        if len(url) >= URL_MAX:
            issues.append(f"config URL is {len(url)} chars (>= {URL_MAX})")
    return issues


def config_file_errors(fname: str, settings: dict | None = None) -> list[str]:
    """Validate a mapped config before any DHCP candidate can be deployed."""
    if not fname:
        return []
    if Path(fname).name != fname or not _allowed(fname):
        return [f"Config file '{fname}' is not an allowed .txt/.conf filename."]
    path = NGINX_DIR / fname
    if not path.is_file():
        return [f"Config file '{fname}' does not exist in {NGINX_DIR}."]
    try:
        content = path.read_text(errors="replace")
    except (OSError, UnicodeError) as exc:
        return [f"Config file '{fname}' cannot be read: {exc}."]
    issues = check_config_text(content, fname, settings=settings)
    return [f"Config '{fname}': {issue}." for issue in issues]


def config_status(fname: str) -> list[str]:
    try:
        return check_config_text((NGINX_DIR / fname).read_text(errors="replace"), fname)
    except (FileNotFoundError, PermissionError):
        return ["cannot read file"]


def all_config_status():
    return {c: config_status(c) for c in list_configs()}


def config_references(fname: str):
    used = [d["hostname"] for d in read_devices() if d.get("specific_config_file") == fname]
    used += [p.get("label") or p.get("vendor_class") for p in read_profiles()
             if p.get("config_file") == fname]
    return used


# ------------------------------------------------------------ dhcpd ---------
def split_devices(rows):
    """Only devices WITH a specific config file get a dedicated DHCP entry.
    Devices without one are inventory/health-only and fall through to a Generic Profile."""
    serial_static = [r for r in rows if r.get("match_method") == "serial"
                     and r.get("serial_number") and assignment_type(r) == "STATIC"
                     and r.get("specific_config_file")]
    serial_auto = [r for r in rows if r.get("match_method") == "serial"
                   and r.get("serial_number") and assignment_type(r) == "AUTO"]
    mac_static = [r for r in rows if r.get("match_method") == "mac"
                  and r.get("mac_address") and assignment_type(r) == "STATIC"
                  and r.get("specific_config_file") and r.get("ip_address")]
    mac_auto = [r for r in rows if r.get("match_method") == "mac"
                and r.get("mac_address") and assignment_type(r) == "AUTO" and r.get("ip_address")]
    return serial_static, serial_auto, mac_static, mac_auto


def generate_dhcpd(settings=None, devices=None, profiles=None) -> str:
    s = read_settings() if settings is None else settings
    if not is_full_ztp(s):
        return "# FILE_SERVER_ONLY: ISC DHCP generation is disabled.\n"
    devices = read_devices() if devices is None else devices
    profile_rows = read_profiles() if profiles is None else profiles
    serial_devices, serial_auto, mac_devices, mac_auto = split_devices(devices)
    profiles = []
    for profile in profile_rows:
        item = dict(profile)
        item["match_expression"] = profile_match_expression(item)
        profiles.append(item)
    return render_template("dhcpd.j2",
        serial_devices=serial_devices, serial_auto_devices=serial_auto,
        mac_devices=mac_devices, mac_auto_devices=mac_auto, profiles=profiles,
        vm_ip=s["server_ip"], subnet=s["subnet"], netmask=s["netmask"],
        router=s["server_ip"], range_low=s["range_low"], range_high=s["range_high"])


def deployment_validation(settings=None, devices=None, profiles=None) -> list[str]:
    """Run every safety gate before a DHCP candidate is allowed to replace production."""
    settings = read_settings() if settings is None else settings
    devices = read_devices() if devices is None else devices
    profiles = read_profiles() if profiles is None else profiles
    # FILE_SERVER_ONLY must not run any ISC DHCP validation.  The reads above
    # are intentional: malformed JSON is still surfaced instead of becoming
    # an empty inventory silently.
    if not is_full_ztp(settings):
        return []
    errors = list(validate_dhcp_pool(settings))
    if not DEV_MODE:
        errors.extend(_network_errors(settings))
    errors.extend(config_pool_errors(sync_config_pool()))
    for row in devices:
        others = [item for item in devices if item is not row]
        errors.extend(validate_device_row(row, others, settings=settings))
    for profile in profiles:
        others = [item for item in profiles if item is not profile]
        errors.extend(validate_profile_row(profile, others, settings=settings))
    return list(dict.fromkeys(errors))


def _restore_dhcp_conf(backup: Path) -> str:
    try:
        if backup.exists():
            tmp = DHCPD_CONF.with_name(DHCPD_CONF.name + ".rollback.tmp")
            shutil.copy2(backup, tmp)
            os.replace(tmp, DHCPD_CONF)
        else:
            DHCPD_CONF.unlink(missing_ok=True)
        return ""
    except OSError as exc:
        return f"DHCP config rollback failed: {exc}"


def _restore_path_from_backup(path: Path, backup: Path) -> str:
    if not backup.exists():
        return ""
    try:
        tmp = path.with_name(path.name + ".rollback.tmp")
        shutil.copy2(backup, tmp)
        os.replace(tmp, path)
        return ""
    except OSError as exc:
        return f"Rollback failed for {path}: {exc}"


def _restart_dhcp_service() -> tuple[bool, str]:
    """Restart only ISC DHCP and return a useful error instead of raising."""
    cmd = ["systemctl", "restart", "isc-dhcp-server"]
    if os.geteuid() != 0:
        cmd = ["sudo"] + cmd
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    if result.returncode == 0:
        return True, ""
    return False, (result.stderr or result.stdout or "unknown restart error").strip()


def deploy_dhcpd(text: str, settings=None, devices=None, profiles=None):
    """Validate, syntax-check, atomically replace and restart DHCP with rollback."""
    try:
        settings = read_settings() if settings is None else settings
        devices = read_devices() if devices is None else devices
        profiles = read_profiles() if profiles is None else profiles
        errors = deployment_validation(settings, devices, profiles)
    except JsonDataError as exc:
        return False, f"JSON error; deploy stopped: {exc}"
    if not is_full_ztp(settings):
        return True, "FILE_SERVER_ONLY: DHCP generation, validation and restart skipped."
    if errors:
        return False, "Deployment blocked:\n" + "\n".join(errors)
    if not shutil.which("dhcpd"):
        return False, "Deployment blocked: dhcpd is not installed; candidate syntax cannot be checked."
    if not DEV_MODE and not shutil.which("systemctl"):
        return False, "Deployment blocked: systemctl is not available; service rollback cannot be guaranteed."
    try:
        DHCPD_CONF.parent.mkdir(parents=True, exist_ok=True)
        fd, candidate_name = tempfile.mkstemp(prefix=f".{DHCPD_CONF.name}.", suffix=".candidate",
                                              dir=DHCPD_CONF.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        candidate = Path(candidate_name)
        check = subprocess.run(["dhcpd", "-t", "-cf", str(candidate)], capture_output=True, text=True)
        if check.returncode != 0:
            candidate.unlink(missing_ok=True)
            detail = (check.stderr or check.stdout or "unknown syntax error").strip()
            return False, f"dhcpd -t FAILED; live config unchanged:\n{detail}"
        backup = DHCPD_CONF.with_name(DHCPD_CONF.name + ".ztp-app.bak")
        if DHCPD_CONF.exists():
            shutil.copy2(DHCPD_CONF, backup)
        os.replace(candidate, DHCPD_CONF)
    except (OSError, JsonDataError) as exc:
        try:
            if "candidate" in locals():
                candidate.unlink(missing_ok=True)
        except OSError:
            pass
        return False, f"DHCP candidate was not installed: {exc}"

    if DEV_MODE:
        return True, f"DEV_MODE: candidate installed atomically; service restart skipped. Backup: {backup}."

    ok, interface_msg = apply_dhcp_interface(settings.get("ztp_interface", ""))
    if not ok:
        rollback_msg = _restore_dhcp_conf(backup)
        rollback_msg = " ".join(part for part in (rollback_msg,
            _restore_path_from_backup(DHCP_INTERFACE_FILE,
                DHCP_INTERFACE_FILE.with_name(DHCP_INTERFACE_FILE.name + ".ztp-app.bak"))) if part)
        return False, f"DHCP interface update failed: {interface_msg}. {rollback_msg}".strip()

    ok, detail = _restart_dhcp_service()
    if ok:
        return True, f"DHCP deployed and isc-dhcp-server restarted. Backup: {backup}."

    rollback_msg = _restore_dhcp_conf(backup)
    rollback_msg = " ".join(part for part in (rollback_msg,
        _restore_path_from_backup(DHCP_INTERFACE_FILE,
            DHCP_INTERFACE_FILE.with_name(DHCP_INTERFACE_FILE.name + ".ztp-app.bak"))) if part)
    restored, restore_error = _restart_dhcp_service()
    restore_detail = f" DHCP service rollback restart failed: {restore_error}" if not restored else ""
    return False, (f"isc-dhcp-server restart failed; DHCP config rolled back. {rollback_msg}"
                   f"{restore_detail} Original error: {detail}")


def parse_leases() -> dict:
    out = {}
    if not LEASES_FILE.exists():
        return out
    try:
        text = LEASES_FILE.read_text(errors="replace")
    except PermissionError:
        return out
    for ip, body in re.findall(r"lease\s+(\S+)\s*\{(.*?)\}", text, re.DOTALL):
        mac = re.search(r"hardware ethernet\s+([0-9a-f:]+);", body, re.I)
        state = re.search(r"binding state\s+(\w+);", body)
        uid = re.search(r"\buid\s+([^;]+);", body, re.I)
        hostname = re.search(r"client-hostname\s+\"([^\"]+)\";", body, re.I)
        out[ip] = {
            "mac": mac.group(1).lower() if mac else "",
            "client_id": uid.group(1).strip().strip('"') if uid else "",
            "hostname": hostname.group(1) if hostname else "",
            "state": state.group(1) if state else "",
        }
    return out


def _lease_is_active(lease: dict | None) -> bool:
    return bool(lease and str(lease.get("state", "")).lower() in {"active", "binding"})


def option60_for_client(client_ip: str) -> str:
    """Best-effort raw vendor-class extraction; never used as a unique identity."""
    if not SYSLOG_FILE.exists():
        return ""
    try:
        lines = SYSLOG_FILE.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    value = ""
    for line in lines[-3000:]:
        if client_ip and client_ip not in line:
            continue
        match = re.search(r"(?:vendor-class-identifier|vendor-class|option\s*60)[^\"']*[\"']([^\"']+)[\"']", line, re.I)
        if match:
            value = match.group(1).strip()
    return value


def _row_matches_lease(row: dict, client_ip: str, lease: dict) -> bool:
    mac = str(lease.get("mac", "")).lower()
    client_id = str(lease.get("client_id", "")).lower()
    return bool((mac and row.get("mac_address", "").lower() == mac) or
                (client_id and row.get("client_id", "").lower() == client_id) or
                (row.get("ip_address") and row.get("ip_address") == client_ip))


def find_request_context(client_ip: str) -> tuple[dict | None, dict | None, dict | None, str]:
    """Resolve a request only through an active lease and an unambiguous mapping/profile."""
    leases = parse_leases()
    lease = leases.get(client_ip)
    if not _lease_is_active(lease):
        return None, None, lease, "LEASE_NOT_FOUND"
    devices = read_devices()
    matched = [row for row in devices if _row_matches_lease(row, client_ip, lease)]
    vendor = option60_for_client(client_ip)
    if not matched and vendor:
        serial_matches = [row for row in devices if row.get("serial_number") and
                          vendor.lower().endswith(str(row.get("serial_number")).lower())]
        matched = serial_matches
    if len(matched) > 1:
        return None, None, lease, "AMBIGUOUS_MAPPING"
    row = matched[0] if matched else None
    profiles = read_profiles()
    matched_profiles = []
    for profile in profiles:
        expression = profile_match_expression(profile)
        try:
            if vendor and re.search(expression, vendor, re.I):
                matched_profiles.append(profile)
        except re.error:
            continue
    if len(matched_profiles) > 1:
        return row, None, lease, "AMBIGUOUS_PROFILE"
    return row, (matched_profiles[0] if matched_profiles else None), lease, "OK"


def _assignment_filename_valid(filename: str, pool: list[dict]) -> tuple[bool, str]:
    meta = config_file_meta(filename, pool)
    if not meta:
        return False, "CONFIG_NOT_IN_POOL"
    path = NGINX_DIR / filename
    if not path.is_file() or meta.get("status") == "MISSING":
        return False, "CONFIG_MISSING"
    expected = meta.get("checksum", "")
    if expected:
        try:
            if config_sha256(path) != expected:
                return False, "CONFIG_CHECKSUM_MISMATCH"
        except OSError:
            return False, "CONFIG_MISSING"
    return True, ""


def _static_assignment_error(row: dict, pool: list[dict]) -> tuple[str, str]:
    filename = str(row.get("specific_config_file", "")).strip()
    if not filename:
        return "", ""
    errors = config_file_errors(filename, settings=read_settings())
    if errors:
        return filename, "STATIC_CONFIG_ERROR"
    meta = config_file_meta(filename, pool)
    if not meta:
        return filename, "STATIC_CONFIG_ERROR"
    if not config_is_compatible(meta, row.get("device_type", ""), row.get("compatibility_group", "")):
        return filename, "MODEL_MISMATCH"
    ok, reason = _assignment_filename_valid(filename, pool)
    return (filename, "" if ok else reason)


def _release_auto_locked(assignments: dict, pool: list[dict], key: str, reason: str) -> None:
    old = assignments.pop(key, None)
    if not old:
        return
    filename = old.get("filename", "")
    meta = config_file_meta(filename, pool)
    if meta:
        meta["status"] = "AVAILABLE"
        meta["assigned_device"] = ""
        meta["updated_at"] = _now_iso()
    append_history("RELEASE_AUTO", key, reason=reason, filename=filename)


def release_conflicting_auto_for_static(row: dict) -> None:
    """Static Mapping override is applied at save time, not deferred until next DHCP request."""
    wanted_key = device_key(row)
    sync_config_pool()
    with _exclusive_lock(ALLOCATION_LOCK):
        assignments = read_assignments(); pool = read_config_pool()
        keys = [key for key, item in assignments.items()
                if item.get("assignment_type") == "AUTO" and
                (key == wanted_key or (row.get("serial_number") and
                                       item.get("serial") == row.get("serial_number")) or
                 (row.get("mac_address") and item.get("mac", "").lower() == row.get("mac_address", "").lower()))]
        for key in keys:
            _release_auto_locked(assignments, pool, key, "STATIC_MAPPING")
        if row.get("specific_config_file"):
            meta = config_file_meta(row["specific_config_file"], pool)
            if meta:
                meta.update({"status": "RESERVED", "assigned_device": wanted_key, "updated_at": _now_iso()})
        if keys:
            write_config_pool(pool); write_assignments(assignments)
        elif row.get("specific_config_file"):
            write_config_pool(pool)


def _choose_auto_config(pool: list[dict], row: dict | None, profile: dict | None) -> tuple[dict | None, str]:
    source = row or profile or {}
    wanted_pool = str(source.get("pool_name", "")).strip()
    model = str(source.get("device_type", "")).strip()
    group = str(source.get("compatibility_group", "")).strip()
    candidates = [item for item in pool if item.get("status") == "AVAILABLE"
                  and (not wanted_pool or item.get("pool_name", "") == wanted_pool)]
    compatible = [item for item in candidates if config_is_compatible(item, model, group)]
    if compatible:
        compatible.sort(key=lambda item: (int(item.get("allocation_order", 0) or 0), item.get("filename", "")))
        return compatible[0], ""
    return None, "MODEL_MISMATCH" if candidates else "AUTO_POOL_EMPTY"


def _new_assignment(key: str, filename: str, row: dict | None, lease: dict, client_ip: str,
                    assignment_kind: str = "AUTO") -> dict:
    now = _now_iso()
    return {
        "device_key": key, "assignment_type": assignment_kind, "filename": filename,
        "status": "RESERVED", "state": "ASSIGNED", "assigned_at": now,
        "first_seen": now, "last_seen": now, "updated_at": now,
        "mac": lease.get("mac", ""), "client_id": lease.get("client_id", ""),
        "serial": (row or {}).get("serial_number", ""),
        "dhcp_ip": client_ip, "hostname": (row or {}).get("hostname", ""),
        "observed_model": (row or {}).get("device_type", ""), "request_count": 1,
        "fetch_count": 0, "fetch_times": [], "last_http_status": "", "last_error": "",
    }


def reserve_auto_assignment(client_ip: str, row: dict | None, profile: dict | None,
                            lease: dict, key: str) -> tuple[dict | None, str]:
    """Reserve one file while holding the single allocation lock."""
    sync_config_pool()
    with _exclusive_lock(ALLOCATION_LOCK):
        assignments = read_assignments()
        pool = read_config_pool()
        existing = assignments.get(key)
        if existing and existing.get("filename"):
            existing["request_count"] = int(existing.get("request_count", 0) or 0) + 1
            existing["last_seen"] = _now_iso()
            write_assignments(assignments)
            return existing, ""
        selected, reason = _choose_auto_config(pool, row, profile)
        if not selected:
            assignment = assignments.get(key) or _new_assignment(
                key, "", row or profile, lease, client_ip, "AUTO")
            assignment.update({"filename": "", "state": "REVIEW_REQUIRED",
                               "status": "FAILED", "last_error": reason,
                               "last_seen": _now_iso(), "updated_at": _now_iso()})
            assignments[key] = assignment
            write_assignments(assignments)
            append_history("REVIEW_REQUIRED", key, ip=client_ip, reason=reason)
            return assignment, reason
        filename = selected["filename"]
        selected["status"] = "RESERVED"
        selected["assigned_device"] = key
        selected["updated_at"] = _now_iso()
        assignment = _new_assignment(key, filename, row, lease, client_ip, "AUTO")
        assignments[key] = assignment
        write_config_pool(pool)
        write_assignments(assignments)
        append_history("RESERVE_AUTO", key, filename=filename, ip=client_ip)
        return assignment, ""


def _record_assignment_event(key: str, *, state: str | None = None, status: str | None = None,
                            http_status: str = "", error: str = "", bytes_sent: int = 0) -> dict | None:
    with _exclusive_lock(ALLOCATION_LOCK):
        assignments = read_assignments()
        assignment = assignments.get(key)
        if not assignment:
            return None
        now = _now_iso()
        assignment["updated_at"] = now
        assignment["last_seen"] = now
        if state:
            assignment["state"] = state
        if status:
            assignment["status"] = status
        if http_status:
            assignment["last_http_status"] = str(http_status)
        if error:
            assignment["last_error"] = error
        if bytes_sent:
            assignment["last_bytes_sent"] = bytes_sent
        write_assignments(assignments)
        return assignment


def _parse_time(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError, AttributeError):
        return None


def _ensure_static_runtime(key: str, row: dict, filename: str, client_ip: str, lease: dict) -> dict:
    with _exclusive_lock(ALLOCATION_LOCK):
        assignments = read_assignments()
        old = assignments.get(key)
        if old and old.get("assignment_type") == "AUTO" and old.get("filename") != filename:
            pool = read_config_pool()
            _release_auto_locked(assignments, pool, key, "STATIC_MAPPING")
            write_config_pool(pool)
            append_history("STATIC_OVERRIDE", key, filename=filename)
        assignment = assignments.get(key) or _new_assignment(key, filename, row, lease, client_ip, "STATIC")
        assignment.update({"assignment_type": "STATIC", "filename": filename,
                           "last_seen": _now_iso(), "state": assignment.get("state", "ASSIGNED")})
        pool = read_config_pool()
        meta = config_file_meta(filename, pool)
        if meta:
            meta.update({"status": "RESERVED", "assigned_device": key, "updated_at": _now_iso()})
            write_config_pool(pool)
        assignments[key] = assignment
        write_assignments(assignments)
        return assignment


def _fetch_times_in_window(assignment: dict, minutes: int) -> list[str]:
    cutoff = datetime.now(timezone.utc).timestamp() - max(0, minutes) * 60
    result = []
    for value in assignment.get("fetch_times", []):
        parsed = _parse_time(value)
        if parsed and parsed.timestamp() >= cutoff:
            result.append(value)
    return result


def _record_dynamic_fetch(key: str, filename: str, body: bytes, status_code: int = 200,
                         error: str = "") -> None:
    with _exclusive_lock(ALLOCATION_LOCK):
        assignments = read_assignments()
        assignment = assignments.get(key)
        if not assignment:
            return
        now = _now_iso()
        assignment["last_seen"] = now
        assignment["updated_at"] = now
        assignment["last_http_status"] = str(status_code)
        assignment["last_bytes_sent"] = len(body)
        assignment["fetch_times"] = _fetch_times_in_window(assignment, _safe_int(read_settings(), "repeated_fetch_window_minutes", 10))
        assignment["fetch_times"].append(now)
        assignment["fetch_count"] = int(assignment.get("fetch_count", 0) or 0) + 1
        if error:
            assignment["state"] = "FETCH_FAILED"
            assignment["status"] = "FAILED"
            assignment["last_error"] = error
        elif assignment["fetch_count"] > _safe_int(read_settings(), "repeated_fetch_limit", 5):
            assignment["state"] = "REPEATED_FETCH"
            assignment["status"] = "FETCHED"
        else:
            assignment["state"] = "FETCHED"
            assignment["status"] = "FETCHED"
        pool = read_config_pool()
        meta = config_file_meta(filename, pool)
        if meta:
            meta["status"] = "FAILED" if error else "FETCHED"
            meta["assigned_device"] = key
            meta["updated_at"] = now
            write_config_pool(pool)
        write_assignments(assignments)
    append_history("FETCH_FAILED" if error else "FETCH", key, filename=filename,
                   http_status=status_code, bytes_sent=len(body), message=error)


def dynamic_config_result(client_ip: str) -> tuple[bytes | None, str, int]:
    settings = read_settings()
    if not is_full_ztp(settings):
        return None, "FILE_SERVER_ONLY does not perform DHCP allocation or lease resolution.", 404
    row, profile, lease, reason = find_request_context(client_ip)
    if reason != "OK" or not lease:
        append_history(reason, ip=client_ip, message="Dynamic resolver did not find a unique active lease.")
        return None, reason, 404
    key = device_key(row, mac=lease.get("mac", ""), client_id=lease.get("client_id", ""), ip=client_ip)
    if not key:
        append_history("LEASE_NOT_FOUND", ip=client_ip)
        return None, "LEASE_NOT_FOUND", 404
    source = row or profile or {}
    kind = assignment_type(source, "AUTO")
    if kind == "DHCP_ONLY":
        with _exclusive_lock(ALLOCATION_LOCK):
            assignments = read_assignments()
            assignment = assignments.get(key) or _new_assignment(
                key, "", row or profile, lease, client_ip, "DHCP_ONLY")
            assignment.update({"assignment_type": "DHCP_ONLY", "filename": "",
                               "state": "DHCP_ONLY", "status": "DHCP_ONLY",
                               "last_seen": _now_iso(), "updated_at": _now_iso()})
            assignments[key] = assignment
            write_assignments(assignments)
        append_history("DHCP_ONLY", key, ip=client_ip)
        return None, "DHCP_ONLY", 204
    pool = sync_config_pool()
    if kind == "STATIC":
        filename, static_error = _static_assignment_error(source, pool)
        if static_error:
            if filename:
                _ensure_static_runtime(key, source, filename, client_ip, lease)
                _record_assignment_event(key, state="REVIEW_REQUIRED", status="FAILED", error=static_error)
            append_history(static_error, key, filename=filename, ip=client_ip)
            return None, static_error, 409
        if not filename:
            return None, "STATIC_CONFIG_ERROR", 409
        _ensure_static_runtime(key, source, filename, client_ip, lease)
    else:
        assignment, reserve_error = reserve_auto_assignment(client_ip, row, profile, lease, key)
        if reserve_error:
            append_history(reserve_error, key, ip=client_ip)
            return None, reserve_error, 409
        filename = assignment.get("filename", "")
        valid, file_error = _assignment_filename_valid(filename, pool)
        if not valid:
            _record_assignment_event(key, state="REVIEW_REQUIRED", status="FAILED", error=file_error)
            append_history(file_error, key, filename=filename, ip=client_ip)
            return None, file_error, 409
    _record_assignment_event(key, state="FETCHING", status="RESERVED")
    path = NGINX_DIR / filename
    try:
        body = path.read_bytes()
    except (OSError, FileNotFoundError) as exc:
        _record_dynamic_fetch(key, filename, b"", 404, "CONFIG_MISSING")
        return None, f"CONFIG_MISSING: {exc}", 404
    _record_dynamic_fetch(key, filename, body, 200)
    return body, filename, 200


def _dhcp_retry_counts() -> dict[str, int]:
    if not SYSLOG_FILE.exists():
        return {}
    try:
        lines = SYSLOG_FILE.read_text(errors="replace").splitlines()[-3000:]
    except OSError:
        return {}
    settings = read_settings()
    cutoff = datetime.now(timezone.utc).timestamp() - _safe_int(
        settings, "dhcp_retry_window_minutes", 5) * 60
    counts = {}
    for line in lines:
        if not re.search(r"DHCP(?:DISCOVER|REQUEST)", line, re.I):
            continue
        timestamp = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)", line)
        if timestamp:
            try:
                parsed = datetime.strptime(
                    f"{datetime.now().year} {timestamp.group(1)}", "%Y %b %d %H:%M:%S")
                parsed = parsed.replace(tzinfo=timezone.utc)
                if parsed.timestamp() < cutoff:
                    continue
            except ValueError:
                pass
        match = re.search(r"from\s+([0-9a-f:]{17})", line, re.I)
        if match:
            key = f"mac:{match.group(1).lower()}"
            counts[key] = counts.get(key, 0) + 1
    return counts


def refresh_runtime_states() -> dict:
    """Promote runtime states without ever changing COMPLETED/FAILED verification history."""
    settings = read_settings()
    now = datetime.now(timezone.utc)
    changed = False
    retry_counts = _dhcp_retry_counts()
    with _exclusive_lock(ALLOCATION_LOCK):
        assignments = read_assignments()
        for key, assignment in assignments.items():
            if assignment.get("state") == "COMPLETED" or assignment.get("status") == "COMPLETED":
                continue
            if retry_counts.get(key, 0) > _safe_int(settings, "dhcp_retry_limit", 10):
                if assignment.get("state") != "DHCP_RETRY_LOOP":
                    assignment["state"] = "DHCP_RETRY_LOOP"; assignment["last_error"] = "DHCP retry threshold exceeded"; changed = True
                continue
            assigned_at = _parse_time(assignment.get("assigned_at"))
            if (assigned_at and assignment.get("state") in {"ASSIGNED", "FETCHING"} and
                    (now - assigned_at).total_seconds() >= _safe_int(settings, "assigned_no_fetch_minutes", 5) * 60):
                assignment["state"] = "ASSIGNED_NO_FETCH"; changed = True
            fetch_times = _fetch_times_in_window(assignment, _safe_int(settings, "repeated_fetch_window_minutes", 10))
            if len(fetch_times) > _safe_int(settings, "repeated_fetch_limit", 5):
                assignment["state"] = "REPEATED_FETCH"; changed = True
            elif assignment.get("state") == "FETCHED":
                assignment["state"] = "PENDING_CHECK"; changed = True
        if changed:
            write_assignments(assignments)
    return read_assignments()


def provisioning_summary() -> dict:
    assignments = refresh_runtime_states()
    pool = sync_config_pool()
    counts = {key: 0 for key in ["total", "available", "assigned", "dhcp_only", "fetched", "pending_check", "completed", "failed"]}
    counts["total"] = len(pool)
    counts["available"] = sum(1 for item in pool if item.get("status") == "AVAILABLE")
    counts["assigned"] = sum(1 for item in assignments.values() if item.get("state") in {"ASSIGNED", "FETCHING"})
    counts["dhcp_only"] = sum(1 for item in assignments.values() if item.get("state") == "DHCP_ONLY")
    counts["fetched"] = sum(1 for item in assignments.values() if item.get("state") == "FETCHED")
    counts["pending_check"] = sum(1 for item in assignments.values() if item.get("state") in {"PENDING_CHECK", "REVIEW_REQUIRED", "ASSIGNED_NO_FETCH"})
    counts["completed"] = sum(1 for item in assignments.values() if item.get("state") == "COMPLETED")
    counts["failed"] = sum(1 for item in assignments.values() if item.get("state") in {"FAILED", "FETCH_FAILED", "DHCP_RETRY_LOOP"})
    alerts = [item for item in assignments.values() if item.get("state") in {"REVIEW_REQUIRED", "ASSIGNED_NO_FETCH", "FETCH_FAILED", "REPEATED_FETCH", "DHCP_RETRY_LOOP"}]
    return {"counts": counts, "alerts": alerts, "assignments": assignments, "pool": pool}


# ------------------------------------------------------------ health --------
def ping(ip, src=None):
    cmd = ["ping", "-c", "1", "-W", "1"]
    if src:
        cmd += ["-I", src]      # source address/interface — test routing from a chosen path
    cmd.append(ip)
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0
    except Exception:
        return False


def tcp_open(ip, port=SSH_PORT, timeout=2.0, src=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if src:
            s.bind((src, 0))
        s.connect((ip, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def ssh_hostname(ip, user, password, src=None):
    if not (user and password):
        return None
    try:
        import paramiko
    except ImportError:
        return None
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kw = {"port": SSH_PORT, "username": user, "password": password, "timeout": 5}
        if src:
            kw["source_address"] = (src, 0)
        cli.connect(ip, **kw)
        _, out, _ = cli.exec_command("show configuration system host-name | display set | no-more")
        data = out.read().decode(errors="replace")
        cli.close()
        m = re.search(r"host-name\s+(\S+);?", data)
        return m.group(1) if m else ""
    except Exception:
        return None


def health_one(dev: dict, src: str = None) -> dict:
    ip = dev.get("mgmt_ip") or dev.get("ip_address", "")     # post-ZTP mgmt IP first
    expected = dev.get("hostname", "")
    res = {"hostname": expected, "ip": ip, "src": src or "", "ping": False, "ssh": False,
           "status": "no-ip"}
    if not ip:
        return res
    res["ping"] = ping(ip, src)
    if not res["ping"]:
        res["status"] = "unreachable"; return res
    res["ssh"] = tcp_open(ip, src=src)
    if not res["ssh"]:
        res["status"] = "reachable (no SSH)"; return res
    user, pw = get_cred(expected)
    name = ssh_hostname(ip, user, pw, src)
    if name is None:
        res["status"] = "SSH open (no creds)"
    elif name == expected:
        res["status"] = "VERIFIED"
    else:
        res["status"] = f"hostname mismatch ({name})"
    return res


def run_health(devices, src: str = None):
    with ThreadPoolExecutor(max_workers=10) as ex:
        return {r["hostname"]: r for r in ex.map(partial(health_one, src=src), devices)}


def local_ipv4s() -> list[str]:
    """Local IPv4 addresses to offer as health-check source IPs (routing tests)."""
    ips = []
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True, text=True).stdout
        ips = re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    except Exception:
        pass
    return [ip for ip in ips if not ip.startswith("127.")]


def operator_name() -> str:
    return (request.authorization.username if request.authorization else "operator")


def provisioning_rows() -> list[dict]:
    summary = provisioning_summary()
    assignments = summary["assignments"]
    results = read_results()
    leases = {} if not is_full_ztp() else parse_leases()
    rows = []
    seen = set()
    for row in read_devices():
        key = device_key(row)
        seen.add(key)
        assignment = assignments.get(key, {})
        result = results.get(key, {})
        lease = leases.get(row.get("ip_address", ""), {})
        rows.append({
            "device_key": key, "serial": row.get("serial_number", ""),
            "mac": row.get("mac_address", "") or lease.get("mac", ""),
            "client_id": row.get("client_id", "") or lease.get("client_id", ""),
            "dhcp_ip": row.get("ip_address", ""),
            "observed_model": row.get("device_type", "") or assignment.get("observed_model", ""),
            "hostname": row.get("hostname", "") or assignment.get("hostname", ""),
            "config_filename": assignment.get("filename", "") or row.get("specific_config_file", ""),
            "assignment_type": assignment.get("assignment_type", assignment_type(row)),
            "config_status": assignment.get("status", ""),
            "state": assignment.get("state", "DHCP_SEEN"),
            "request_count": assignment.get("request_count", 0),
            "fetch_count": assignment.get("fetch_count", 0),
            "http_status": assignment.get("last_http_status", ""),
            "first_seen": assignment.get("first_seen", ""),
            "assigned_at": assignment.get("assigned_at", ""),
            "fetch_time": (assignment.get("fetch_times") or [""])[-1],
            "verify_time": result.get("verify_time", ""),
            "result": result.get("result", ""), "remarks": result.get("remarks", ""),
            "last_error": assignment.get("last_error", ""),
        })
    for key, assignment in assignments.items():
        if key in seen:
            continue
        result = results.get(key, {})
        rows.append({
            "device_key": key, "serial": "", "mac": assignment.get("mac", ""),
            "client_id": assignment.get("client_id", ""), "dhcp_ip": assignment.get("dhcp_ip", ""),
            "observed_model": assignment.get("observed_model", ""),
            "hostname": assignment.get("hostname", ""), "config_filename": assignment.get("filename", ""),
            "assignment_type": assignment.get("assignment_type", "AUTO"),
            "config_status": assignment.get("status", ""), "state": assignment.get("state", ""),
            "request_count": assignment.get("request_count", 0), "fetch_count": assignment.get("fetch_count", 0),
            "http_status": assignment.get("last_http_status", ""), "first_seen": assignment.get("first_seen", ""),
            "assigned_at": assignment.get("assigned_at", ""),
            "fetch_time": (assignment.get("fetch_times") or [""])[-1],
            "verify_time": result.get("verify_time", ""), "result": result.get("result", ""),
            "remarks": result.get("remarks", ""), "last_error": assignment.get("last_error", ""),
        })
    return rows


MAPPING_EXPORT_FIELDS = ["serial", "mac", "client_id", "dhcp_ip", "observed_model", "hostname",
                         "config_filename", "assignment_type", "config_status", "first_seen",
                         "assigned_at", "fetch_time", "verify_time", "result", "remarks"]
HISTORY_EXPORT_FIELDS = ["timestamp", "device_key", "serial", "mac", "ip", "event_type",
                         "old_value", "new_value", "filename", "http_status", "operator", "message"]


def export_history_rows() -> list[dict]:
    return [{field: row.get(field, "") for field in HISTORY_EXPORT_FIELDS} for row in read_history(100000)]


def xlsx_response(rows: list[dict], fields: list[str], filename: str):
    """Create XLSX only when the optional openpyxl dependency is installed."""
    try:
        from openpyxl import Workbook
    except ImportError:
        return Response("XLSX export requires openpyxl; install requirements.txt.\n", 503,
                        mimetype="text/plain")
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Export"
    sheet.append(fields)
    for row in rows:
        sheet.append([row.get(field, "") for field in fields])
    output = io.BytesIO()
    workbook.save(output)
    body = output.getvalue()
    return Response(body, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


# ------------------------------------------------------------ routes --------
@app.route("/ztp/config")
def dynamic_config():
    # Trust X-Real-IP only when the request came through the local Nginx
    # proxy; a device connecting directly to :8080 must not spoof a lease IP.
    remote = request.remote_addr or ""
    forwarded = request.headers.get("X-Real-IP", "").strip()
    client_ip = forwarded if remote in {"127.0.0.1", "::1"} and forwarded else remote
    body, detail, status = dynamic_config_result(client_ip)
    if status == 204:
        return Response("", status=204)
    if body is None:
        return Response(f"ZTP resolver: {detail}\n", status=status, mimetype="text/plain")
    return Response(body, status=200, mimetype="text/plain",
                    headers={"Cache-Control": "no-store", "X-ZTP-Config": detail})


@app.route("/provisioning")
def provisioning():
    settings = read_settings()
    summary = provisioning_summary()
    return render_template("provisioning.html", settings=settings, mode=settings.get("global_mode"),
                           rows=provisioning_rows(), pool=summary["pool"],
                           counts=summary["counts"], alerts=summary["alerts"],
                           configs=list_configs(), author=AUTHOR, version=VERSION)


@app.route("/provisioning/mode", methods=["POST"])
def provisioning_mode():
    mode = request.form.get("global_mode", "").strip().upper()
    if mode not in GLOBAL_MODES:
        flash("Mode must be FULL_ZTP or FILE_SERVER_ONLY.", "danger")
        return redirect(url_for("provisioning"))
    settings = read_settings(); old = settings.get("global_mode", "FULL_ZTP")
    settings["global_mode"] = mode
    write_settings(settings)
    append_history("MODE_CHANGE", operator=operator_name(), old_value=old, new_value=mode)
    flash(f"Mode changed to {mode}. No DHCP service was restarted.", "success")
    return redirect(url_for("provisioning"))


@app.route("/provisioning/config", methods=["POST"])
def provisioning_config_metadata():
    filename = os.path.basename(request.form.get("filename", "").strip())
    if not filename or not _allowed(filename) or not (NGINX_DIR / filename).is_file():
        flash("Config metadata was not saved: file is missing or filename is not allowed.", "danger")
        return redirect(url_for("provisioning"))
    supported = _metadata_models(request.form.get("supported_models", ""))
    group = request.form.get("compatibility_group", "").strip()
    hostname = request.form.get("hostname", "").strip()
    pool_name = request.form.get("pool_name", "").strip()
    try:
        order = int(request.form.get("allocation_order", "0") or 0)
    except ValueError:
        order = 0
    with _exclusive_lock(ALLOCATION_LOCK):
        pool = read_config_pool()
        if hostname and any(item.get("hostname") == hostname and item.get("filename") != filename for item in pool):
            flash(f"Config hostname '{hostname}' is already used by another file.", "danger")
            return redirect(url_for("provisioning"))
        row = config_file_meta(filename, pool)
        if not row:
            row = {"filename": filename, "created_at": _now_iso(), "status": "AVAILABLE", "assigned_device": ""}
            pool.append(row)
        row.update({"hostname": hostname, "supported_models": supported,
                    "compatibility_group": group, "pool_name": pool_name,
                    "allocation_order": order or len(pool), "checksum": config_sha256(NGINX_DIR / filename),
                    "updated_at": _now_iso()})
        write_config_pool(pool)
    append_history("CONFIG_METADATA", operator=operator_name(), filename=filename,
                   new_value=json.dumps({"hostname": hostname, "supported_models": supported,
                                         "compatibility_group": group, "pool_name": pool_name}))
    flash(f"Config metadata saved for {filename}.", "success")
    return redirect(url_for("provisioning"))


@app.route("/provisioning/release/<path:provision_key>", methods=["POST"])
def release_assignment(provision_key):
    with _exclusive_lock(ALLOCATION_LOCK):
        assignments = read_assignments()
        pool = read_config_pool()
        assignment = assignments.get(provision_key)
        if not assignment:
            flash("No Auto Assignment found for this device.", "warning")
            return redirect(url_for("provisioning"))
        if assignment.get("assignment_type") != "AUTO":
            flash("Only AUTO assignments can be released; STATIC mappings require an explicit mapping change.", "warning")
            return redirect(url_for("provisioning"))
        filename = assignment.get("filename", "")
        meta = config_file_meta(filename, pool)
        if meta:
            meta.update({"status": "AVAILABLE", "assigned_device": "", "updated_at": _now_iso()})
        assignments.pop(provision_key, None)
        write_config_pool(pool); write_assignments(assignments)
    append_history("RELEASE_AUTO", provision_key, operator=operator_name(), filename=filename)
    flash("Auto Assignment released; config returned to AVAILABLE.", "success")
    return redirect(url_for("provisioning"))


@app.route("/provisioning/reset/<path:provision_key>", methods=["POST"])
def reset_provisioning(provision_key):
    with _exclusive_lock(ALLOCATION_LOCK):
        assignments = read_assignments(); pool = read_config_pool(); results = read_results()
        old = assignments.pop(provision_key, None)
        if old:
            meta = config_file_meta(old.get("filename", ""), pool)
            if meta:
                meta.update({"status": "AVAILABLE", "assigned_device": "", "updated_at": _now_iso()})
        results.pop(provision_key, None)
        write_config_pool(pool); write_assignments(assignments); write_results(results)
    append_history("RESET", provision_key, operator=operator_name())
    flash("Provisioning runtime and verification result reset; history was kept.", "success")
    return redirect(url_for("provisioning"))


@app.route("/provisioning/retry/<path:provision_key>", methods=["POST"])
def retry_provisioning(provision_key):
    with _exclusive_lock(ALLOCATION_LOCK):
        assignments = read_assignments(); assignment = assignments.get(provision_key)
        if not assignment:
            flash("Cannot retry: assignment not found.", "danger")
            return redirect(url_for("provisioning"))
        assignment.update({"state": "ASSIGNED", "status": "RESERVED", "last_error": "", "updated_at": _now_iso()})
        write_assignments(assignments)
    append_history("RETRY", provision_key, operator=operator_name(), filename=assignment.get("filename", ""))
    flash("Device marked for retry; its existing config assignment was preserved.", "success")
    return redirect(url_for("provisioning"))


@app.route("/provisioning/verify/<path:provision_key>", methods=["POST"])
def verify_provisioning(provision_key):
    result = request.form.get("result", "").strip().upper()
    if result not in {"COMPLETED", "FAILED"}:
        flash("Verification result must be COMPLETED or FAILED.", "danger")
        return redirect(url_for("provisioning"))
    verification = {"serial": request.form.get("serial", "").strip(),
                    "model": request.form.get("model", "").strip(),
                    "hostname": request.form.get("hostname", "").strip(),
                    "result": result, "remarks": request.form.get("remarks", "").strip(),
                    "verify_time": _now_iso(), "operator": operator_name()}
    with _exclusive_lock(ALLOCATION_LOCK):
        results = read_results(); assignments = read_assignments(); pool = read_config_pool()
        results[provision_key] = verification
        if provision_key in assignments:
            assignments[provision_key].update({"state": result, "status": result, "updated_at": _now_iso()})
            meta = config_file_meta(assignments[provision_key].get("filename", ""), pool)
            if meta:
                meta.update({"status": result, "assigned_device": provision_key, "updated_at": _now_iso()})
        write_results(results); write_assignments(assignments); write_config_pool(pool)
    append_history("COMPLETE" if result == "COMPLETED" else "FAIL", provision_key,
                   operator=operator_name(), new_value=json.dumps(verification, ensure_ascii=False))
    flash(f"Verification saved as {result}.", "success" if result == "COMPLETED" else "warning")
    return redirect(url_for("provisioning"))


@app.route("/provisioning/timeline/<path:provision_key>")
def provisioning_timeline(provision_key):
    rows = [row for row in read_history(100000) if row.get("device_key") == provision_key]
    return jsonify({"device_key": provision_key, "events": rows})


@app.route("/")
def index():
    settings = read_settings()
    devices = read_devices()
    profiles = read_profiles()
    provisioning = provisioning_summary()
    network_messages = network_checks(settings) if is_full_ztp(settings) else []
    network_errors = _network_errors(settings) if is_full_ztp(settings) else []
    network_warnings = _network_warnings(settings) if is_full_ztp(settings) else []
    return render_template("index.html",
        configs=list_configs(), config_checks=all_config_status(),
        devices=devices, profiles=profiles, mapping_issues=mapping_issues(devices, profiles), settings=settings,
        interfaces=network_interfaces() if is_full_ztp(settings) else [], network_checks=network_messages,
        network_errors=network_errors, network_warnings=network_warnings,
        pool_errors=validate_dhcp_pool(settings) if is_full_ztp(settings) else [],
        pool_suggestion=dhcp_pool_suggestion(settings),
        pool_prefix_length=netmask_prefix_length(settings.get("netmask", "")),
        provisioning=provisioning, mode=settings.get("global_mode", "FULL_ZTP"),
        creds=creds_overview(), match_methods=MATCH_METHODS, dev_mode=DEV_MODE,
        allowed_ext=", ".join(sorted(ALLOWED_EXT)), author=AUTHOR, version=VERSION)


@app.route("/settings/suggest")
def settings_suggest():
    settings = read_settings()
    settings["ztp_interface"] = request.args.get("ztp_interface", "").strip()
    return jsonify(dhcp_pool_suggestion(settings))


@app.route("/api/network")
def network_api():
    settings = read_settings()
    checks = network_checks(settings) if is_full_ztp(settings) else []
    return jsonify({
        "mode": settings.get("global_mode", "FULL_ZTP"),
        "interfaces": network_interfaces() if is_full_ztp(settings) else [],
        "network_checks": checks,
        "network_errors": [m for m in checks if m.startswith("ERROR:")],
        "network_warnings": [m for m in checks if m.startswith("WARN:")],
        "pool_errors": validate_dhcp_pool(settings) if is_full_ztp(settings) else [],
    })


@app.route("/service/restart", methods=["POST"])
def service_restart():
    """Request a restart of this systemd service; never restart from DEV_MODE."""
    if DEV_MODE:
        return jsonify(ok=False, message="DEV_MODE: service restart skipped.")
    if not shutil.which("systemctl"):
        return jsonify(ok=False, message="systemctl is not available on this host."), 503
    try:
        result = subprocess.run(
            ["systemctl", "--no-block", "restart", "ztp-app.service"],
            capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return jsonify(ok=False, message=f"Could not request service restart: {exc}"), 503
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown systemd error").strip()
        return jsonify(ok=False, message=f"Service restart failed: {detail}"), 503
    return jsonify(ok=True, message="ZTP service restart requested. The page will reconnect shortly.")


@app.route("/settings", methods=["POST"])
def settings_save():
    s = {k: request.form.get(k, "").strip() for k in SETTINGS_FIELDS}
    current = read_settings()
    for key in SETTINGS_FIELDS:
        if not s.get(key):
            s[key] = current.get(key, DEFAULT_SETTINGS.get(key, ""))
    prefix = request.form.get("prefix_length", "").strip()
    if prefix:
        try:
            s["netmask"] = prefix_length_netmask(prefix)
        except ValueError as exc:
            flash(f"DHCP pool is not valid: {exc}", "danger")
            return redirect(url_for("index") + "#network-view")
    pool_errors = [] if not is_full_ztp(s) else validate_dhcp_pool(s)
    if pool_errors:
        flash("DHCP pool is not valid:\n" + "\n".join(pool_errors), "danger")
        return redirect(url_for("index"))
    save_mode = request.form.get("save_mode", "apply")
    if save_mode == "draft":
        write_settings(s)
        flash("Draft saved. DHCP was not restarted.", "info")
        return redirect(url_for("index") + "#network-view")
    if is_full_ztp(s) and request.form.get("confirm_dhcp") != "yes":
        flash("Confirm that the DHCP pool is correct and does not overlap another DHCP server before applying.", "warning")
        return redirect(url_for("index"))
    write_settings(s)
    ok, msg = deploy_dhcpd(generate_dhcpd())
    checks = network_checks(s) if is_full_ztp(s) else []
    if checks:
        # deploy_dhcpd() includes readiness errors in its message when the
        # production safety gate blocks a restart.  Add only lines that are
        # not already present so the UI does not show duplicate diagnostics.
        existing = set(msg.splitlines())
        extra = [line for line in checks if line not in existing]
        if extra:
            msg = msg + "\n" + "\n".join(extra)
    flash(f"DHCP pool and interface selection saved. {msg}", "success" if ok else "warning")
    return redirect(url_for("index") + "#network-view")


@app.route("/account/change_password", methods=["POST"])
def change_admin_password():
    data = _read_json(ADMIN_AUTH_JSON, {})
    current_user = data.get("username", "admin")
    cur_pw = request.form.get("current_password", "")
    new_user = request.form.get("new_username", "").strip() or current_user
    new_pw = request.form.get("new_password", "")
    if not check_password_hash(data.get("password_hash", ""), cur_pw):
        flash("Current password is incorrect.", "danger"); return redirect(url_for("index"))
    if len(new_pw) < 4:
        flash("New password must be at least 4 characters.", "danger"); return redirect(url_for("index"))
    _save_admin(new_user, new_pw)
    flash(f"Admin login updated (username: {new_user}). Your browser may still show the old "
          "prompt cached — re-enter the new credentials when asked.", "success")
    return redirect(url_for("index"))


@app.route("/set_creds", methods=["POST"])
def set_creds_route():
    scope = request.form.get("scope", "default").strip() or "default"
    user = request.form.get("username", "").strip()
    pw = request.form.get("password", "")
    if not (user and pw):
        flash("Username and password are required.", "danger"); return redirect(url_for("index"))
    set_cred(scope, user, pw)
    flash(f"SSH credentials saved for '{scope}'.", "success")
    return redirect(url_for("index"))


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("config_file")
    if not file or not file.filename:
        flash("No file selected.", "warning"); return redirect(url_for("index"))
    if not _allowed(file.filename):
        flash(f"Only {', '.join(sorted(ALLOWED_EXT))} files are allowed.", "danger"); return redirect(url_for("index"))
    name = os.path.basename(file.filename); data = file.read()
    try:
        (UPLOAD_DIR / name).write_bytes(data); (NGINX_DIR / name).write_bytes(data)
    except PermissionError:
        flash(f"Cannot write to {NGINX_DIR} (need sudo?).", "danger"); return redirect(url_for("index"))
    with _exclusive_lock(ALLOCATION_LOCK):
        pool = read_config_pool()
        meta = config_file_meta(name, pool)
        if not meta:
            meta = {"filename": name, "hostname": "", "supported_models": [],
                    "compatibility_group": "", "pool_name": "", "allocation_order": len(pool) + 1,
                    "status": "AVAILABLE", "assigned_device": "", "created_at": _now_iso()}
            pool.append(meta)
        meta.update({"checksum": hashlib.sha256(data).hexdigest(), "updated_at": _now_iso()})
        if meta.get("status") == "MISSING":
            meta["status"] = "AVAILABLE"
        write_config_pool(pool)
    append_history("UPLOAD_CONFIG", operator=operator_name(), filename=name)
    issues = check_config_text(data.decode("utf-8", errors="replace"), name)
    for w in issues:
        flash(f"[{name}] {w}", "warning")
    if not issues:
        flash(f"Uploaded {name} — all checks passed.", "success")
    return redirect(url_for("index"))


@app.route("/delete_config/<path:fname>", methods=["POST"])
def delete_config(fname):
    fname = os.path.basename(fname)   # strip any ../ segments — never touch a path
                                       # outside NGINX_DIR/UPLOAD_DIR
    if not fname or not _allowed(fname):
        flash("Invalid file name.", "danger"); return redirect(url_for("index"))
    force = request.form.get("force_delete") == "yes" and request.form.get("confirm_force") == "yes"
    refs = config_references(fname)
    pool = sync_config_pool()
    meta = config_file_meta(fname, pool)
    assigned = [key for key, item in read_assignments().items() if item.get("filename") == fname]
    if refs and not force:
        flash(f"Cannot delete {fname}: still used by {', '.join(refs)}. Use Force Delete only after review.", "danger"); return redirect(url_for("index"))
    if assigned and not force:
        flash(f"Cannot delete {fname}: active assignment(s) exist. Use Force Delete only after review.", "danger"); return redirect(url_for("index"))
    for d in (NGINX_DIR, UPLOAD_DIR):
        try:
            (d / fname).unlink(missing_ok=True)
        except (PermissionError, OSError):
            flash(f"Cannot remove {fname} (need sudo?).", "danger"); return redirect(url_for("index"))
    with _exclusive_lock(ALLOCATION_LOCK):
        rows = read_config_pool()
        item = config_file_meta(fname, rows)
        if item:
            item.update({"status": "MISSING", "updated_at": _now_iso()})
            write_config_pool(rows)
    append_history("FORCE_DELETE" if force else "DELETE_CONFIG", operator=operator_name(), filename=fname)
    flash(f"Deleted {fname}.", "success"); return redirect(url_for("index"))


@app.route("/deploy", methods=["POST"])
def deploy():
    method = request.form.get("match_method", "").strip()
    if method not in MATCH_METHODS:
        flash("Invalid match method.", "danger"); return redirect(url_for("index"))
    serial = request.form.get("serial_number", "").strip()
    mac    = request.form.get("mac_address", "").strip().lower()
    host   = request.form.get("hostname", "").strip()
    row = {"match_method": method,
           "serial_number": serial if method == "serial" else "",
           "mac_address": mac if method == "mac" else "",
           "device_type": request.form.get("device_type", "").strip(),
           "hostname": host,
           "ip_address": request.form.get("ip_address", "").strip(),
           "mgmt_ip": request.form.get("mgmt_ip", "").strip(),
           "client_id": request.form.get("client_id", "").strip(),
           "compatibility_group": request.form.get("compatibility_group", "").strip(),
           "specific_config_file": request.form.get("specific_config_file", "").strip(),
           "assignment_type": request.form.get("assignment_type", "STATIC").strip().upper() or "STATIC",
           "pool_name": request.form.get("pool_name", "").strip(),
           "option60_confirmed": request.form.get("option60_confirmed", "").strip()}
    if method == "serial" and not serial:
        flash("Serial Number is required for 'By Serial'.", "danger"); return redirect(url_for("index"))
    if method == "serial" and not SERIAL_RE.fullmatch(serial):
        flash("Serial Number must be alphanumeric only (it is embedded in a DHCP match regex).", "danger")
        return redirect(url_for("index"))
    if method == "mac" and not mac:
        flash("MAC Address is required for 'By MAC'.", "danger"); return redirect(url_for("index"))
    if not host:
        flash("Hostname is required.", "danger"); return redirect(url_for("index"))
    # Config file is OPTIONAL: leave blank to let the device use the shared Generic Profile
    # (matched by vendor-class). A By-MAC device only needs a DHCP IP if it has its own config.
    if method == "mac" and row["assignment_type"] == "AUTO" and not row["ip_address"]:
        flash("DHCP IP is required for a By-MAC Auto device so the resolver can find its lease.", "danger")
        return redirect(url_for("index"))
    if row["assignment_type"] not in ASSIGNMENT_TYPES:
        flash("Assignment type must be STATIC, AUTO or DHCP_ONLY.", "danger")
        return redirect(url_for("index"))

    existing = [r for r in read_devices() if r.get("hostname") != host]
    errors = validate_device_row(row, existing)
    if errors:
        flash("Mapping was not saved:\n" + "\n".join(errors), "danger")
        return redirect(url_for("index"))

    # optional per-device SSH credentials
    u, p = request.form.get("ssh_user", "").strip(), request.form.get("ssh_pass", "")
    if u and p:
        set_cred(host, u, p)

    rows = [r for r in read_devices() if r.get("hostname") != host]
    rows.append(row); write_devices(rows)
    if row["assignment_type"] == "STATIC":
        release_conflicting_auto_for_static(row)
    ok, msg = deploy_dhcpd(generate_dhcpd())
    append_history("STATIC_MAPPING" if row["assignment_type"] == "STATIC" else "SET_ASSIGNMENT_TYPE",
                   device_key(row), operator=operator_name(), filename=row.get("specific_config_file", ""),
                   new_value=row["assignment_type"])
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("index"))


@app.route("/delete/<hostname>", methods=["POST"])
def delete(hostname):
    rows = read_devices()
    removed = next((r for r in rows if r.get("hostname") == hostname), None)
    write_devices([r for r in rows if r.get("hostname") != hostname])
    if removed:
        key = device_key(removed)
        with _exclusive_lock(ALLOCATION_LOCK):
            assignments = read_assignments(); pool = read_config_pool()
            old = assignments.pop(key, None)
            if old and old.get("assignment_type") == "AUTO":
                meta = config_file_meta(old.get("filename", ""), pool)
                if meta:
                    meta.update({"status": "AVAILABLE", "assigned_device": "", "updated_at": _now_iso()})
            static_meta = config_file_meta(removed.get("specific_config_file", ""), pool)
            if static_meta and static_meta.get("assigned_device") == key:
                static_meta.update({"status": "AVAILABLE", "assigned_device": "", "updated_at": _now_iso()})
            write_config_pool(pool); write_assignments(assignments)
        append_history("DELETE_STATIC_MAPPING", key, operator=operator_name(), hostname=hostname)
    ok, msg = deploy_dhcpd(generate_dhcpd())
    flash(f"Deleted {hostname}. {msg}", "success" if ok else "warning")
    return redirect(url_for("index"))


@app.route("/add_profile", methods=["POST"])
def add_profile():
    p = {"label": request.form.get("label", "").strip(),
         "vendor_class": request.form.get("vendor_class", "").strip(),
         "match_mode": request.form.get("match_mode", "contains").strip() or "contains",
         "config_file": request.form.get("config_file", "").strip(),
         "assignment_type": request.form.get("assignment_type", "STATIC").strip().upper() or "STATIC",
         "pool_name": request.form.get("pool_name", "").strip(),
         "compatibility_group": request.form.get("compatibility_group", "").strip(),
         "option60_confirmed": request.form.get("option60_confirmed", "").strip()}
    existing = [r for r in read_profiles()
                if not (r.get("vendor_class") == p["vendor_class"]
                        and r.get("match_mode", "contains") == p["match_mode"])]
    errors = validate_profile_row(p, existing)
    if errors:
        flash("Profile was not saved:\n" + "\n".join(errors), "danger")
        return redirect(url_for("index"))
    if not p["label"]:
        p["label"] = p["vendor_class"]
    rows = [r for r in read_profiles()
            if not (r.get("vendor_class") == p["vendor_class"]
                    and r.get("match_mode", "contains") == p["match_mode"])]
    rows.append(p); write_profiles(rows)
    ok, msg = deploy_dhcpd(generate_dhcpd())
    append_history("PROFILE_UPDATE", operator=operator_name(), new_value=json.dumps(p, ensure_ascii=False))
    flash(f"Profile saved. {msg}", "success" if ok else "warning")
    return redirect(url_for("index"))


@app.route("/delete_profile/<int:idx>", methods=["POST"])
def delete_profile(idx):
    rows = read_profiles()
    if 0 <= idx < len(rows):
        removed = rows.pop(idx); write_profiles(rows)
        append_history("DELETE_PROFILE", operator=operator_name(),
                       old_value=json.dumps(removed, ensure_ascii=False))
        ok, msg = deploy_dhcpd(generate_dhcpd())
        flash(f"Profile removed. {msg}", "success" if ok else "warning")
    return redirect(url_for("index"))


def _csv_response(rows, fields, fname):
    buf = io.StringIO(); w = csv.DictWriter(buf, fieldnames=fields); w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k, "") for k in fields})
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.route("/export/<kind>.<fmt>")
def export(kind, fmt):
    if kind == "devices": rows, fields = read_devices(), DEVICE_FIELDS
    elif kind == "profiles": rows, fields = read_profiles(), PROFILE_FIELDS
    elif kind == "mapping": rows, fields = provisioning_rows(), MAPPING_EXPORT_FIELDS
    elif kind == "history": rows, fields = export_history_rows(), HISTORY_EXPORT_FIELDS
    else:
        flash("Unknown export.", "danger"); return redirect(url_for("index"))
    if fmt == "json":
        return Response(json.dumps(rows, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": f"attachment; filename={kind}.json"})
    if fmt == "xlsx":
        return xlsx_response(rows, fields, f"{kind}.xlsx")
    return _csv_response(rows, fields, f"{kind}.csv")


@app.route("/import/<kind>", methods=["POST"])
def import_data(kind):
    file = request.files.get("import_file")
    if not file or not file.filename:
        flash("No file selected.", "warning"); return redirect(url_for("index"))
    raw = file.read().decode("utf-8", errors="replace")
    fields = DEVICE_FIELDS if kind == "devices" else PROFILE_FIELDS
    try:
        rows = json.loads(raw) if file.filename.endswith(".json") else list(csv.DictReader(io.StringIO(raw)))
    except (json.JSONDecodeError, csv.Error) as e:
        flash(f"Parse error: {e}", "danger"); return redirect(url_for("index"))
    clean = [{k: str(r.get(k, "")).strip() for k in fields} for r in rows if isinstance(r, dict)]
    if kind == "devices":
        for device in clean:
            if not device.get("assignment_type"):
                device["assignment_type"] = "STATIC" if device.get("specific_config_file") else "DHCP_ONLY"
    if kind == "profiles":
        for profile in clean:
            profile["match_mode"] = profile.get("match_mode") or "contains"
    mode = request.form.get("mode", "merge")
    if kind == "devices":
        existing = [] if mode == "replace" else read_devices()
        names = {r["hostname"] for r in clean}
        candidate = [r for r in existing if r.get("hostname") not in names] + clean
        errors = []
        if len(names) != len(clean):
            errors.append("Import contains duplicate hostnames.")
        for row in clean:
            errors.extend(validate_device_row(row, [r for r in candidate if r is not row]))
        if errors:
            flash("Import was not saved:\n" + "\n".join(dict.fromkeys(errors)), "danger")
            return redirect(url_for("index"))
        write_devices(candidate)
        append_history("IMPORT_DEVICES", operator=operator_name(), new_value=str(len(clean)))
    else:
        existing = [] if mode == "replace" else read_profiles()
        vcs = {(r["vendor_class"], r.get("match_mode", "contains")) for r in clean}
        candidate = [r for r in existing if (r.get("vendor_class"), r.get("match_mode", "contains")) not in vcs] + clean
        errors = []
        if len(vcs) != len(clean):
            errors.append("Import contains duplicate vendor classes.")
        for profile in clean:
            errors.extend(validate_profile_row(profile, [r for r in candidate if r is not profile]))
        if errors:
            flash("Import was not saved:\n" + "\n".join(dict.fromkeys(errors)), "danger")
            return redirect(url_for("index"))
        write_profiles(candidate)
        append_history("IMPORT_PROFILES", operator=operator_name(), new_value=str(len(clean)))
    ok, msg = deploy_dhcpd(generate_dhcpd())
    flash(f"Imported {len(clean)} {kind} ({mode}). {msg}", "success" if ok else "warning")
    return redirect(url_for("index"))


@app.route("/bindings")
def bindings():
    devices = read_devices(); s = read_settings()
    full = is_full_ztp(s)
    leases = parse_leases() if full else {}
    src = (request.args.get("src") or request.args.get("src_sel") or "").strip() or None
    health = run_health(devices, src) if full and request.args.get("health") == "1" else {}
    fixed = [d["ip_address"] for d in devices if d.get("ip_address")]
    return render_template("bindings.html",
        devices=devices, leases=leases, health=health, settings=s, src=src or "",
        sources=local_ipv4s() if full else [], fixed_count=len(fixed), lease_count=len(leases),
        mode=s.get("global_mode", "FULL_ZTP"),
        creds_set=bool(read_creds().get("default") or read_creds().get("by_host")),
        author=AUTHOR, version=VERSION)


def _binding_rows(health: dict, leases: dict):
    rows = []
    for d in read_devices():
        h = health.get(d["hostname"], {})
        lease = leases.get(d.get("ip_address", ""), {})
        rows.append({
            "hostname": d.get("hostname", ""),
            "match_method": d.get("match_method", ""),
            "identifier": d.get("serial_number") or d.get("mac_address", ""),
            "device_type": d.get("device_type", ""),
            "config_file": d.get("specific_config_file", "") or "(shared profile)",
            "dhcp_ip": d.get("ip_address", ""),
            "mgmt_ip": d.get("mgmt_ip", ""),
            "checked_ip": h.get("ip", ""),
            "lease_state": lease.get("state", ""),
            "ping": "up" if h.get("ping") else ("down" if h else ""),
            "ssh": "open" if h.get("ssh") else ("closed" if h else ""),
            "provisioning": h.get("status", "not checked"),
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })
    return rows


@app.route("/export/bindings.csv")
def export_bindings():
    settings = read_settings()
    if not is_full_ztp(settings):
        return _csv_response(_binding_rows({}, {}), ["hostname", "match_method", "identifier", "device_type",
                                                     "config_file", "dhcp_ip", "mgmt_ip", "checked_ip",
                                                     "lease_state", "ping", "ssh", "provisioning", "timestamp"],
                             "ztp_bindings.csv")
    src = (request.args.get("src") or request.args.get("src_sel") or "").strip() or None
    health = run_health(read_devices(), src) if request.args.get("health") == "1" else {}
    rows = _binding_rows(health, parse_leases())
    fields = ["hostname", "match_method", "identifier", "device_type", "config_file",
              "dhcp_ip", "mgmt_ip", "checked_ip", "lease_state", "ping", "ssh",
              "provisioning", "timestamp"]
    return _csv_response(rows, fields, "ztp_bindings.csv")


# --- logs / troubleshooting -----------------------------------------------
def tail(path: Path, n: int = 300, grep: str = "") -> list[str]:
    if not path.exists():
        return []
    try:
        lines = path.read_text(errors="replace").splitlines()
    except PermissionError:
        return [f"(cannot read {path} — need sudo/permissions)"]
    if grep:
        lines = [l for l in lines if grep in l]
    return lines[-n:]


def _device_for(base: str, client_ip: str, devices, profiles, leases) -> str:
    """Resolve a config fetch to a device serial/hostname (or shared profile)."""
    if base == "config":
        for item in provisioning_rows():
            if item.get("dhcp_ip") == client_ip:
                return item.get("hostname") or item.get("device_key", "")
    for d in devices:
        if d.get("specific_config_file") == base:
            return d.get("serial_number") or d.get("hostname") or d.get("mac_address") or ""
    for p in profiles:
        if p.get("config_file") == base:
            return f"shared: {p.get('label') or p.get('vendor_class')}"
    for d in devices:                                   # fallback: fixed-address (By-MAC)
        if d.get("ip_address") == client_ip:
            return d.get("serial_number") or d.get("hostname") or ""
    mac = (leases.get(client_ip) or {}).get("mac", "")  # fallback: lease IP -> MAC -> device
    if mac:
        for d in devices:
            if d.get("mac_address", "").lower() == mac.lower():
                return d.get("serial_number") or d.get("hostname") or ""
    return ""


def nginx_config_fetches(n: int = 200) -> list[dict]:
    """Parse nginx access log for GET /configs/* — which client fetched which config + resolved device."""
    devices, profiles = read_devices(), read_profiles()
    leases = parse_leases() if is_full_ztp() else {}
    out = []
    # Include both legacy fixed-file fetches and the dynamic /ztp/config
    # resolver; the latter is the production path for AUTO assignments.
    for line in tail(NGINX_ACCESS, n=2000):
        m = re.search(r'(\d+\.\d+\.\d+\.\d+).*?\[([^\]]+)\].*?"(?:GET|HEAD)\s+(/(?:configs|ztp)/\S+)\s+[^\"]*"\s+(\d{3})(?:\s+(\d+)\s+(\S+))?', line)
        if m:
            base = os.path.basename(m.group(3))
            out.append({"client": m.group(1), "time": m.group(2), "file": m.group(3),
                        "status": m.group(4), "bytes_sent": m.group(5) or "",
                        "request_time": m.group(6) or "",
                        "device": _device_for(base, m.group(1), devices, profiles, leases)})
    return out[-n:]


def dhcp_option60_lines(n: int = 100) -> list[str]:
    """Return raw DHCP log lines that expose vendor-class / Option 60 data."""
    patterns = re.compile(r"vendor-class-identifier|vendor-class|option\s*60|option-60", re.I)
    return [line for line in tail(SYSLOG_FILE, n=2000) if patterns.search(line)][-n:]


LOG_SOURCES = {
    "dhcp":  lambda: tail(SYSLOG_FILE, 300, grep="dhcpd"),
    "nginx": lambda: [line for line in tail(NGINX_ACCESS, 2000)
                       if "/configs/" in line or "/ztp/config" in line][-300:],
    "leases": lambda: tail(LEASES_FILE, 400),
}


@app.route("/logs")
def logs():
    s = read_settings()
    full = is_full_ztp(s)
    return render_template("logs.html",
        dhcp_log="\n".join(LOG_SOURCES["dhcp"]()) if full else "",
        option60_log="\n".join(dhcp_option60_lines()) if full else "",
        fetches=nginx_config_fetches(),
        leases_log="\n".join(LOG_SOURCES["leases"]()) if full else "",
        syslog_path=str(SYSLOG_FILE), nginx_path=str(NGINX_ACCESS),
        leases_path=str(LEASES_FILE), settings=s, mode=s.get("global_mode", "FULL_ZTP"),
        author=AUTHOR, version=VERSION)


@app.route("/logs/export/<which>")
def logs_export(which):
    fn = LOG_SOURCES.get(which)
    if not fn:
        flash("Unknown log.", "danger"); return redirect(url_for("logs"))
    body = "\n".join(fn()) or "(empty / not available)"
    return Response(body, mimetype="text/plain",
                    headers={"Content-Disposition": f"attachment; filename=ztp_{which}.log"})


@app.route("/preview")
def preview():
    settings = read_settings()
    return app.response_class(generate_dhcpd(settings), mimetype="text/plain")


@app.route("/configs/<path:fname>")
def serve_config(fname):
    return send_from_directory(NGINX_DIR, fname)


def main():
    host = os.environ.get("ZTP_HOST", "0.0.0.0")
    port = int(os.environ.get("ZTP_PORT", "8080"))
    if DEV_MODE:
        app.run(host=host, port=port, debug=True)
        return
    try:
        from waitress import serve
        print(f"ZTP Manager (waitress) on http://{host}:{port}  — author {AUTHOR}")
        serve(app, host=host, port=port)
    except ImportError:
        print("waitress not installed; falling back to Flask server (NOT for production: pip install waitress)")
        app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
