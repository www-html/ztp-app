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

from flask import (Flask, Response, flash, redirect, render_template, request,
                   send_from_directory, url_for)
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
DEV_MODE     = os.environ.get("ZTP_DEV", "0") == "1"
SSH_PORT     = int(os.environ.get("ZTP_SSH_PORT", "22"))

# Default DHCP pool — 19.96.0.0/16 (per request; isolated L2 lab). Editable in the UI.
DEFAULT_SETTINGS = {
    "server_ip": os.environ.get("ZTP_VM_IP", "19.96.0.1"),
    "subnet":    os.environ.get("ZTP_SUBNET", "19.96.0.0"),
    "netmask":   os.environ.get("ZTP_NETMASK", "255.255.0.0"),
    "range_low": os.environ.get("ZTP_RANGE_LOW", "19.96.0.10"),
    "range_high":os.environ.get("ZTP_RANGE_HIGH", "19.96.255.254"),
}

ALLOWED_EXT   = {".txt", ".conf"}
MATCH_METHODS = ["serial", "mac"]
URL_MAX       = 256
SERIAL_RE       = re.compile(r"^[A-Za-z0-9]+$")
VENDOR_CLASS_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
DEVICE_FIELDS = ["match_method", "serial_number", "mac_address", "device_type",
                 "hostname", "ip_address", "mgmt_ip", "specific_config_file"]
PROFILE_FIELDS = ["label", "vendor_class", "config_file"]
SETTINGS_FIELDS = ["server_ip", "subnet", "netmask", "range_low", "range_high"]
AUTHOR = "binh.trinh"
VERSION = "26.07.01"   # build version yy.mm.dd

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
def read_profiles(): return _read_json(PROFILES_JSON, [])
def write_profiles(rows): PROFILES_JSON.write_text(json.dumps(rows, indent=2))


def read_settings() -> dict:
    s = dict(DEFAULT_SETTINGS)
    s.update({k: v for k, v in _read_json(SETTINGS_JSON, {}).items() if k in SETTINGS_FIELDS and v})
    return s


def write_settings(s: dict):
    SETTINGS_JSON.write_text(json.dumps({k: s.get(k, "") for k in SETTINGS_FIELDS}, indent=2))


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
    return render_template("dhcpd.j2",
        serial_devices=serial_devices, mac_devices=mac_devices, profiles=read_profiles(),
        vm_ip=s["server_ip"], subnet=s["subnet"], netmask=s["netmask"],
        router=s["server_ip"], range_low=s["range_low"], range_high=s["range_high"])


def deploy_dhcpd(text: str):
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
    return render_template("index.html",
        configs=list_configs(), config_checks=all_config_status(),
        devices=read_devices(), profiles=read_profiles(), settings=read_settings(),
        creds=creds_overview(), match_methods=MATCH_METHODS, dev_mode=DEV_MODE,
        allowed_ext=", ".join(sorted(ALLOWED_EXT)), author=AUTHOR, version=VERSION)


@app.route("/settings", methods=["POST"])
def settings_save():
    s = {k: request.form.get(k, "").strip() for k in SETTINGS_FIELDS}
    if not all(s.values()):
        flash("All DHCP pool fields are required.", "danger"); return redirect(url_for("index"))
    write_settings(s)
    ok, msg = deploy_dhcpd(generate_dhcpd())
    flash(f"DHCP pool saved. {msg}", "success" if ok else "warning")
    return redirect(url_for("index"))


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
         "config_file": request.form.get("config_file", "").strip()}
    if not (p["vendor_class"] and p["config_file"]):
        flash("Vendor-class and config file are required.", "danger"); return redirect(url_for("index"))
    if not VENDOR_CLASS_RE.fullmatch(p["vendor_class"]):
        flash("Vendor-class may only contain letters, digits, '.', '_', '-' "
              "(it is embedded in a DHCP match regex).", "danger")
        return redirect(url_for("index"))
    if not p["label"]:
        p["label"] = p["vendor_class"]
    rows = [r for r in read_profiles() if r.get("vendor_class") != p["vendor_class"]]
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
    mode = request.form.get("mode", "merge")
    if kind == "devices":
        existing = [] if mode == "replace" else read_devices()
        names = {r["hostname"] for r in clean}
        write_devices([r for r in existing if r.get("hostname") not in names] + clean)
    else:
        existing = [] if mode == "replace" else read_profiles()
        vcs = {r["vendor_class"] for r in clean}
        write_profiles([r for r in existing if r.get("vendor_class") not in vcs] + clean)
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
    return render_template("logs.html",
        dhcp_log="\n".join(LOG_SOURCES["dhcp"]()),
        fetches=nginx_config_fetches(),
        leases_log="\n".join(LOG_SOURCES["leases"]()),
        syslog_path=str(SYSLOG_FILE), nginx_path=str(NGINX_ACCESS),
        leases_path=str(LEASES_FILE), author=AUTHOR, version=VERSION)


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
