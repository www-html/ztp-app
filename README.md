# ztp-app v4 — vendor-neutral Juniper ZTP over HTTP

GUI (Flask) to drive ZTP on an isolated **L2** segment: upload full configs to Nginx,
map devices → config, generate/validate `dhcpd.conf`, reserve Auto Pool files safely,
then complete operator verification. Static Mapping remains backward compatible.
Author: **binh.trinh**.

## Matching model (method-driven, not model-hardcoded)
- **By Serial** → `if/elsif option vendor-class-identifier ~= "<serial>$"` (anchored regex, no offset).
- **By MAC** → `host { hardware ethernet ...; fixed-address ...; }` (highest precedence).
- **Generic Profile** (user-defined vendor-class → config) → fallback in the same `if/elsif` chain.
- File-server advertised via **Option 66** (`tftp-server-name`). Config files: `.txt` / `.conf`.

## Feature summary
- Upload + **auto-checks** per file (column *Checks*): root-authentication, URL < 256, and
  **override-aware** auto-image-upgrade (a full load-override config omits the stanza → OK; only
  flagged if it *enables* `chassis auto-image-upgrade` without a delete).
- **Delete** uploaded configs (blocked if still referenced).
- **Import/Export** devices & profiles in CSV + JSON (bulk).
- **DHCP pool editable in the UI** (server IP / subnet / netmask / range). Default **192.168.250.0/24**
  (RFC1918). Server IP = Option 66 + gateway.
- **SSH credentials in the UI**: a Default plus per-device/site (scope = hostname); also inline in
  the device form. Stored in `creds.json` (chmod 600), passwords never displayed.
- **Bindings & Health**: binding table + DHCP leases + ping/SSH health. Health targets the
  **Management IP (post-ZTP)** which may be in a different/other subnet (multi-subnet supported;
  the server needs an L3 route). `VERIFIED` = SSH in and hostname matches.
- Browser tab favicon **Z+**; production WSGI via **waitress** (no Flask dev-server warning).
- **Config file is optional** per device: leave blank → the device uses the shared **Generic Profile**
  (matched by vendor-class) and is still tracked in Bindings & Health. A dedicated DHCP entry is only
  emitted when a device has its own config file.
- Health check **source IP** selector (test routing from a specific local address/path).
- **Export** the binding/health result (serial → config → status) as CSV.
- **Logs tab** for troubleshooting: dhcpd activity, nginx **config fetches** (which client pulled which
  config, 200/404), and DHCP leases — each exportable.
- **Provisioning** supports `FULL_ZTP` and `FILE_SERVER_ONLY`. Per-device/profile assignment is
  `STATIC`, `AUTO`, or `DHCP_ONLY`; Auto Pool uses `fcntl.flock`, atomic JSON stores and append-only
  `history.jsonl`. HTTP 200 is `FETCHED`, never automatic completion.
- Export mapping/history as CSV or XLSX (`openpyxl`). Dynamic Auto Pool delivery uses `/ztp/config`
  behind the bundled Nginx proxy and checks the active DHCP lease before allocation.

## Structure
```
ztp-app/
  app.py
  devices.json            static_mappings.json  generic_profiles.json
  settings.json           creds.json (0600)
  config_pool.json        assignments.json  results.json  history.jsonl
  uploads/  templates/{index.html, provisioning.html, dhcpd.j2, bindings.html}
  requirements.txt  deploy/{install.sh, ztp-app.service, ztp-nginx-site.conf}
```

## Run — dev (WSL, no root)
```bash
cd ~/projects/ZTP/ZTP/ztp-app
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
ZTP_DEV=1 ZTP_WEBROOT=./_webroot ZTP_DHCPD=./_dhcpd.conf python app.py   # http://localhost:8080
```

## Run — production (waitress)
```bash
. .venv/bin/activate
python app.py            # waitress on :8080 (set ZTP_PORT to change). No dev-server warning.
```

## Package on the real VM (VMware, bridged into the L2 ZTP segment)
```bash
sudo BRIDGE_IF=ens37 deploy/install.sh
# installs nginx + isc-dhcp-server, venv+deps, copies app to /opt/ztp-app,
# enables ztp-app.service (waitress :8080) + nginx; seeds a valid dhcpd.conf.
# Then open  http://<vm-ip>:8080  -> set DHCP pool + SSH credentials, upload configs, map devices.
```

## Verifying success (Bindings & Health)
Open **Bindings & Health → Run health check**:
- **DHCP lease** → device reached ZTP and got an IP.
- **Ping** → booted, reachable at its mgmt IP.
- **SSH** → TCP/22 open (mgmt plane up).
- **VERIFIED** → SSH login + `host-name` matches → correct config on correct device
  (needs SSH credentials set in the UI).

## Readiness checklist before a real run
1. VM NIC bridged into the **same L2 broadcast domain** as the devices (no router in between, or a DHCP relay).
2. DHCP pool set (UI) for that segment; `isc-dhcp-server` bound to the bridged interface (`/etc/default/isc-dhcp-server`).
3. Each uploaded config shows **Checks = OK** (root-auth present; not enabling auto-image-upgrade; URL < 256).
4. Devices mapped (By-Serial / By-MAC) or a Generic Profile exists; `Preview dhcpd.conf` then `dhcpd -t` passes.
5. SSH credentials set (Default and/or per-device) if you want **VERIFIED**.
6. Management IPs reachable from the VM (routes to those subnets) for health/verify.
7. `nginx` serving `http://<server>/configs/*`; `dhcpd.leases` readable by the app.

## Key env overrides
| Var | Default | Meaning |
|---|---|---|
| ZTP_WEBROOT | /var/www/html/configs | Nginx config dir |
| ZTP_DHCPD | /etc/dhcp/dhcpd.conf | generated dhcpd.conf |
| ZTP_LEASES | /var/lib/dhcp/dhcpd.leases | leases for the binding view |
| ZTP_PORT / ZTP_HOST | 8080 / 0.0.0.0 | web bind |
| ZTP_DEV | 0 | 1 = Flask dev server, skip service restart, **and skip admin login** |
| ZTP_SSH_PORT | 22 | SSH port for health |
| ZTP_ADMIN_USER | admin | GUI login username (HTTP Basic Auth), first-run only |
| ZTP_ADMIN_PASSWORD | admin | GUI login password, first-run only — change via UI after |
| ZTP_SECRET | *(random, persisted)* | Flask session/flash signing key |

DHCP pool and SSH credentials are managed **in the UI** (settings.json / creds.json), not env.

## Security notes (read before exposing beyond an isolated lab)
- The whole GUI is behind **HTTP Basic Auth** except `/configs/*`, which Junos devices hit
  unauthenticated during ZTP (by design — they can't present credentials). Default login
  on first start (`ZTP_DEV` unset) is **admin / admin** (or `ZTP_ADMIN_USER`/`ZTP_ADMIN_PASSWORD`
  if set) — **change it immediately** at Dashboard -> Admin Login, or before exposing the VM
  beyond a throwaway lab.
- The service runs as **root** (needed to write `dhcpd.conf` and restart services) —
  keep the GUI reachable only from a trusted management network, and rotate the admin
  password via `ZTP_ADMIN_PASSWORD` + deleting `admin_auth.json` if it may have leaked.
- `serial_number` / `vendor_class` are embedded directly into an ISC-DHCP match regex —
  the app now restricts both to alphanumeric (+ `.`/`_`/`-` for vendor-class) to prevent
  a malformed or malicious value from widening the match and misdirecting a config to
  the wrong device.
- HTTP Basic Auth sends credentials base64-encoded, not encrypted — put this behind
  TLS (reverse proxy) or restrict access at the network layer if the management
  segment isn't already trusted end-to-end.

## Residual technical notes
- `~= "<serial>$"` assumes the serial is at the END of Option 60 (`Juniper-<model>-<serial>`).
  Confirm the real VCI with `tcpdump -ni <if> port 67 -v` or the dhcpd log.
- `~=` is a regex (Ubuntu's isc-dhcp-server has regex support). Serials are alphanumeric → safe.
- The default pool is RFC1918 `192.168.250.0/24`; choose a non-overlapping RFC1918 subnet for the
  actual ZTP VLAN and never expose the DHCP service to production networks.
- The app validates `dhcpd -t` before restarting; on failure it does NOT restart and surfaces the error.
