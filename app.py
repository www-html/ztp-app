#!/usr/bin/env python3
"""
ZTP Web App (Flask) — vendor-neutral Juniper ZTP over HTTP (Nginx) + ISC-DHCP.  [v4]
Author: binh.trinh

Matching (method-driven, not model-hardcoded):
  - Specific "By Serial" -> if/elsif  option vendor-class-identifier ~= "<serial>$"
  - Specific "By MAC"     -> host { hardware ethernet ...; }
  - Generic Profile       -> elsif option vendor-class-identifier ~= "<vendor-class>"
File-server advertised via Option 66 (tftp-server-name).

v4: editable DHCP pool (settings.json), SSH credential store (creds.json, default +
per-device), config auto-checks (override-aware), bindings + ping/SSH health to a
post-ZTP management IP (any subnet), production WSGI (waitress).

Run:
  ZTP_DEV=1 python app.py            # dev (Flask reloader)
  python app.py                      # production via waitress (if installed)
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import partial
from pathlib import Path

from flask import (Flask, Response, flash, jsonify, redirect, render_template,
                   request, send_from_directory, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------- paths -----
APP_DIR      = Path(__file__).resolve().parent
NGINX_DIR    = Path(os.environ.get("ZTP_WEBROOT", "/var/www/html/configs"))
UPLOAD_DIR   = Path(os.environ.get("ZTP_UPLOADS", str(APP_DIR / "uploads")))
DEVICES_JSON = Path(os.environ.get("ZTP_DEVICES", str(APP_DIR / "devices.json")))
PROFILES_JSON= Path(os.environ.get("ZTP_PROFILES", str(APP_DIR / "generic_profiles.json")))
SETTINGS_JSON= Path(os.environ.get("ZTP_SETTINGS", str(APP_DIR / "settings.json")))
CREDS_JSON   = Path(os.environ.get("ZTP_CREDS", str(APP_DIR / "creds.json")))
ADMIN_AUTH_JSON = Path(os.environ.get("ZTP_ADMIN_FILE", str(APP_DIR / "admin_auth.json")))
SECRET_FILE  = Path(os.environ.get("ZTP_SECRET_FILE", str(APP_DIR / ".secret_key")))
DHCPD_CONF   = Path(os.environ.get("ZTP_DHCPD", "/etc/dhcp/dhcpd.conf"))
LEASES_FILE  = Path(os.environ.get("ZTP_LEASES", "/var/lib/dhcp/dhcpd.leases"))
SYSLOG_FILE  = Path(os.environ.get("ZTP_SYSLOG", "/var/log/syslog"))
NGINX_ACCESS = Path(os.environ.get("ZTP_NGINX_ACCESS", "/var/log/nginx/access.log"))
DHCP_INTERFACE_FILE = Path(os.environ.get("ZTP_DHCP_INTERFACE_FILE", "/etc/default/isc-dhcp-server"))
DEV_MODE     = os.environ.get("ZTP_DEV", "0") == "1"
SSH_PORT     = int(os.environ.get("ZTP_SSH_PORT", "22"))

# Default DHCP pool — 19.96.0.0/16 (per request; isolated L2 lab). Editable in the UI.
DEFAULT_SETTINGS = {
    "server_ip": os.environ.get("ZTP_VM_IP", "19.96.0.1"),
    "subnet":    os.environ.get("ZTP_SUBNET", "19.96.0.0"),
    "netmask":   os.environ.get("ZTP_NETMASK", "255.255.0.0"),
    "range_low": os.environ.get("ZTP_RANGE_LOW", "19.96.0.10"),
    "range_high":os.environ.get("ZTP_RANGE_HIGH", "19.96.255.254"),
    "internet_interface": os.environ.get("ZTP_INTERNET_INTERFACE", ""),
    "ztp_interface":      os.environ.get("ZTP_INTERFACE", ""),
}

ALLOWED_EXT   = {".txt", ".conf"}
MATCH_METHODS = ["serial", "mac"]
URL_MAX       = 256
SERIAL_RE       = re.compile(r"^[A-Za-z0-9]+$")
VENDOR_CLASS_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
MAC_RE          = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
PROFILE_REGEX_TEXT_RE = re.compile(r'^[^\r\n"]{1,160}$')
DEVICE_FIELDS = ["match_method", "serial_number", "mac_address", "device_type",
                 "hostname", "ip_address", "mgmt_ip", "specific_config_file"]
PROFILE_MATCH_MODES = ["contains", "regex"]
PROFILE_FIELDS = ["label", "vendor_class", "match_mode", "config_file"]
SETTINGS_FIELDS = ["server_ip", "subnet", "netmask", "range_low", "range_high",
                   "internet_interface", "ztp_interface"]
AUTHOR = "binh.trinh"
VERSION = "26.08.05"   # build version yy.mm.dd

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
    if DEV_MODE or request.path.startswith("/configs/"):
        return None
    auth = request.authorization
    if not auth or not _check_admin(auth.username, auth.password):
        return Response("Authentication required.", 401,
                        {"WWW-Authenticate": 'Basic realm="ZTP Manager"'})


# --------------------------------------------------------- json helpers -----
def _read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text() or json.dumps(default))
    except json.JSONDecodeError:
        return default


def read_devices():  return _read_json(DEVICES_JSON, [])
def write_devices(rows): DEVICES_JSON.write_text(json.dumps(rows, indent=2))
def read_profiles():
    rows = _read_json(PROFILES_JSON, [])
    for row in rows:
        row.setdefault("match_mode", "contains")
    return rows
def write_profiles(rows): PROFILES_JSON.write_text(json.dumps(rows, indent=2))


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


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
        serial = row.get("serial_number", "")
        mac = row.get("mac_address", "").lower()
        if row.get("match_method") == "serial" and serial:
            if not SERIAL_RE.fullmatch(serial):
                issues.append(f"{host}: Serial must be alphanumeric.")
            if serial in serials:
                issues.append(f"Duplicate Serial '{serial}' on {serials[serial]} and {host}.")
            serials[serial] = host
        if row.get("match_method") == "mac" and mac:
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


def validate_device_row(row: dict, existing=None) -> list[str]:
    """Validate form/import data before it can change the generated DHCP rules."""
    existing = read_devices() if existing is None else existing
    errors = []
    method = row.get("match_method", "")
    host = row.get("hostname", "")
    if method not in MATCH_METHODS:
        errors.append("Match method must be serial or mac.")
    if not host:
        errors.append("Hostname is required.")
    serial = row.get("serial_number", "")
    mac = row.get("mac_address", "").lower()
    if method == "serial" and not SERIAL_RE.fullmatch(serial):
        errors.append("Serial must contain letters and digits only.")
    if method == "mac" and not MAC_RE.fullmatch(mac):
        errors.append("MAC must use aa:bb:cc:dd:ee:ff format.")
    if method == "mac" and row.get("specific_config_file") and not row.get("ip_address"):
        errors.append("DHCP IP is required for a By-MAC device with its own config file.")
    for field in ("ip_address", "mgmt_ip"):
        value = row.get(field, "")
        if value and not _valid_ipv4(value):
            errors.append(f"{field} must be a valid IPv4 address.")
    for other in existing:
        if other.get("hostname") == host:
            continue
        if method == "serial" and serial and other.get("match_method") == "serial":
            other_serial = other.get("serial_number", "")
            if serial == other_serial:
                errors.append(f"Serial '{serial}' is already mapped to {other.get('hostname')}.")
            elif _serial_overlap(serial, other_serial):
                errors.append(f"Serial '{serial}' overlaps '{other_serial}' on {other.get('hostname')}.")
        if method == "mac" and mac and other.get("match_method") == "mac":
            if mac == other.get("mac_address", "").lower():
                errors.append(f"MAC '{mac}' is already mapped to {other.get('hostname')}.")
    return errors


def validate_profile_row(profile: dict, existing=None) -> list[str]:
    existing = read_profiles() if existing is None else existing
    errors = []
    vendor = profile.get("vendor_class", "")
    mode = profile.get("match_mode", "contains")
    if not vendor or not profile.get("config_file"):
        errors.append("Vendor class and config file are required.")
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
    s.update({k: v for k, v in _read_json(SETTINGS_JSON, {}).items() if k in SETTINGS_FIELDS and v})
    return s


def write_settings(s: dict):
    SETTINGS_JSON.write_text(json.dumps({k: s.get(k, "") for k in SETTINGS_FIELDS}, indent=2))


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
    return messages


def _network_errors(settings: dict | None = None) -> list[str]:
    return [m for m in network_checks(settings) if m.startswith("ERROR:")]


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
    fd = os.open(CREDS_JSON, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(CREDS_JSON, 0o600)
    except OSError:
        pass


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


def check_config_text(text: str, fname: str = "") -> list[str]:
    """Override-aware auto-checks. Full load-override configs are fine without a delete stmt."""
    low = text.lower()
    issues = []
    if "root-authentication" not in low:
        issues.append("no root-authentication -> ZTP commit will FAIL")
    enables_aiu = bool(re.search(r"set\s+chassis\s+auto-image-upgrade", low) or
                       re.search(r"chassis\s*\{[^}]*auto-image-upgrade\s*;", low, re.S))
    if enables_aiu and "delete chassis auto-image-upgrade" not in low:
        issues.append("enables 'chassis auto-image-upgrade' -> device will re-enter ZTP loop")
    if fname:
        url = f"http://{read_settings()['server_ip']}/configs/{fname}"
        if len(url) >= URL_MAX:
            issues.append(f"config URL is {len(url)} chars (>= {URL_MAX})")
    return issues


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
    serial = [r for r in rows if r.get("match_method") == "serial"
              and r.get("serial_number") and r.get("specific_config_file")]
    mac    = [r for r in rows if r.get("match_method") == "mac"
              and r.get("mac_address") and r.get("specific_config_file") and r.get("ip_address")]
    return serial, mac


def generate_dhcpd() -> str:
    s = read_settings()
    serial_devices, mac_devices = split_devices(read_devices())
    profiles = []
    for profile in read_profiles():
        item = dict(profile)
        item["match_expression"] = profile_match_expression(item)
        profiles.append(item)
    return render_template("dhcpd.j2",
        serial_devices=serial_devices, mac_devices=mac_devices, profiles=profiles,
        vm_ip=s["server_ip"], subnet=s["subnet"], netmask=s["netmask"],
        router=s["server_ip"], range_low=s["range_low"], range_high=s["range_high"])


def deploy_dhcpd(text: str):
    settings = read_settings()
    if not DEV_MODE:
        errors = _network_errors(settings)
        if errors:
            return False, "Network readiness failed; DHCP was not restarted:\n" + "\n".join(errors)
    try:
        DHCPD_CONF.parent.mkdir(parents=True, exist_ok=True)
        DHCPD_CONF.write_text(text)
    except PermissionError:
        return False, f"Cannot write {DHCPD_CONF} (need sudo?)."
    if shutil.which("dhcpd"):
        chk = subprocess.run(["dhcpd", "-t", "-cf", str(DHCPD_CONF)], capture_output=True, text=True)
        if chk.returncode != 0:
            return False, f"dhcpd -t FAILED — not restarting:\n{chk.stderr.strip()}"
    if DEV_MODE:
        return True, "DEV_MODE: dhcpd.conf written, service restart skipped."
    ok, msg = apply_dhcp_interface(settings.get("ztp_interface", ""))
    if not ok:
        return False, msg
    if not shutil.which("systemctl"):
        return True, "dhcpd.conf written (no systemctl here)."
    cmd = ["systemctl", "restart", "isc-dhcp-server", "nginx"]
    if os.geteuid() != 0:
        cmd = ["sudo"] + cmd     # only needed when the app isn't already root
    r = subprocess.run(cmd, capture_output=True, text=True)
    return (r.returncode == 0,
            "Services restarted." if r.returncode == 0 else f"Restart FAILED:\n{r.stderr.strip()}")


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
        out[ip] = {"mac": mac.group(1) if mac else "", "state": state.group(1) if state else ""}
    return out


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


# ------------------------------------------------------------ routes --------
@app.route("/")
def index():
    settings = read_settings()
    devices = read_devices()
    profiles = read_profiles()
    return render_template("index.html",
        configs=list_configs(), config_checks=all_config_status(),
        devices=devices, profiles=profiles, mapping_issues=mapping_issues(devices, profiles), settings=settings,
        interfaces=network_interfaces(), network_checks=network_checks(settings),
        pool_errors=validate_dhcp_pool(settings),
        pool_suggestion=dhcp_pool_suggestion(settings),
        pool_prefix_length=netmask_prefix_length(settings.get("netmask", "")),
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
    return jsonify({
        "interfaces": network_interfaces(),
        "network_checks": network_checks(settings),
        "pool_errors": validate_dhcp_pool(settings),
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
    prefix = request.form.get("prefix_length", "").strip()
    if prefix:
        try:
            s["netmask"] = prefix_length_netmask(prefix)
        except ValueError as exc:
            flash(f"DHCP pool is not valid: {exc}", "danger")
            return redirect(url_for("index") + "#network-view")
    pool_errors = validate_dhcp_pool(s)
    if pool_errors:
        flash("DHCP pool is not valid:\n" + "\n".join(pool_errors), "danger")
        return redirect(url_for("index"))
    save_mode = request.form.get("save_mode", "apply")
    if save_mode == "draft":
        write_settings(s)
        flash("Draft saved. DHCP was not restarted.", "info")
        return redirect(url_for("index") + "#network-view")
    if request.form.get("confirm_dhcp") != "yes":
        flash("Confirm that the DHCP pool is correct and does not overlap another DHCP server before applying.", "warning")
        return redirect(url_for("index"))
    write_settings(s)
    ok, msg = deploy_dhcpd(generate_dhcpd())
    checks = network_checks(s)
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
    refs = config_references(fname)
    if refs:
        flash(f"Cannot delete {fname}: still used by {', '.join(refs)}.", "danger"); return redirect(url_for("index"))
    for d in (NGINX_DIR, UPLOAD_DIR):
        try:
            (d / fname).unlink(missing_ok=True)
        except (PermissionError, OSError):
            flash(f"Cannot remove {fname} (need sudo?).", "danger"); return redirect(url_for("index"))
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
           "specific_config_file": request.form.get("specific_config_file", "").strip()}
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
    if method == "mac" and row["specific_config_file"] and not row["ip_address"]:
        flash("DHCP IP is required for a By-MAC device that has its own config file.", "danger")
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
    ok, msg = deploy_dhcpd(generate_dhcpd())
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("index"))


@app.route("/delete/<hostname>", methods=["POST"])
def delete(hostname):
    write_devices([r for r in read_devices() if r.get("hostname") != hostname])
    ok, msg = deploy_dhcpd(generate_dhcpd())
    flash(f"Deleted {hostname}. {msg}", "success" if ok else "warning")
    return redirect(url_for("index"))


@app.route("/add_profile", methods=["POST"])
def add_profile():
    p = {"label": request.form.get("label", "").strip(),
         "vendor_class": request.form.get("vendor_class", "").strip(),
         "match_mode": request.form.get("match_mode", "contains").strip() or "contains",
         "config_file": request.form.get("config_file", "").strip()}
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
    flash(f"Profile saved. {msg}", "success" if ok else "warning")
    return redirect(url_for("index"))


@app.route("/delete_profile/<int:idx>", methods=["POST"])
def delete_profile(idx):
    rows = read_profiles()
    if 0 <= idx < len(rows):
        rows.pop(idx); write_profiles(rows)
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
    else:
        flash("Unknown export.", "danger"); return redirect(url_for("index"))
    if fmt == "json":
        return Response(json.dumps(rows, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": f"attachment; filename={kind}.json"})
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
    ok, msg = deploy_dhcpd(generate_dhcpd())
    flash(f"Imported {len(clean)} {kind} ({mode}). {msg}", "success" if ok else "warning")
    return redirect(url_for("index"))


@app.route("/bindings")
def bindings():
    devices = read_devices(); s = read_settings()
    leases = parse_leases()
    src = (request.args.get("src") or request.args.get("src_sel") or "").strip() or None
    health = run_health(devices, src) if request.args.get("health") == "1" else {}
    fixed = [d["ip_address"] for d in devices if d.get("ip_address")]
    return render_template("bindings.html",
        devices=devices, leases=leases, health=health, settings=s, src=src or "",
        sources=local_ipv4s(), fixed_count=len(fixed), lease_count=len(leases),
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
    devices, profiles, leases = read_devices(), read_profiles(), parse_leases()
    out = []
    for line in tail(NGINX_ACCESS, n=2000, grep="/configs/"):
        m = re.search(r'(\d+\.\d+\.\d+\.\d+).*\[([^\]]+)\].*"(?:GET|HEAD)\s+(/configs/\S+)\s.*?"\s+(\d{3})', line)
        if m:
            base = os.path.basename(m.group(3))
            out.append({"client": m.group(1), "time": m.group(2), "file": m.group(3),
                        "status": m.group(4),
                        "device": _device_for(base, m.group(1), devices, profiles, leases)})
    return out[-n:]


LOG_SOURCES = {
    "dhcp":  lambda: tail(SYSLOG_FILE, 300, grep="dhcpd"),
    "nginx": lambda: tail(NGINX_ACCESS, 300, grep="/configs/"),
    "leases": lambda: tail(LEASES_FILE, 400),
}


@app.route("/logs")
def logs():
    s = read_settings()
    return render_template("logs.html",
        dhcp_log="\n".join(LOG_SOURCES["dhcp"]()),
        fetches=nginx_config_fetches(),
        leases_log="\n".join(LOG_SOURCES["leases"]()),
        syslog_path=str(SYSLOG_FILE), nginx_path=str(NGINX_ACCESS),
        leases_path=str(LEASES_FILE), settings=s, author=AUTHOR, version=VERSION)


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
    return app.response_class(generate_dhcpd(), mimetype="text/plain")


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
