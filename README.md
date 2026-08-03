# ztp-app v26.08.09

Vendor-neutral Juniper ZTP operations console: Flask + Nginx + optional ISC DHCP. It runs on an isolated L2 ZTP VLAN; devices receive DHCP, fetch a config over HTTP, and commit it themselves.

## Operating modes

| Mode | DHCP | Resolver | Intended use |
|---|---|---|---|
| `ZTP_PROVISIONING` | network + ZTP options | `/ztp/config` | full provisioning; `STATIC` or opt-in `AUTO` |
| `DHCP_FILE_SERVER` | network parameters only | none | DHCP plus manual `/configs/<file>` downloads |
| `FILE_SERVER_ONLY` | disabled/stopped | none | Nginx/Flask file server only |

`FULL_ZTP` is migrated to `ZTP_PROVISIONING`. Legacy `DHCP_ONLY` records remain readable/auditable but cannot be created or resolved into a config.

## Safety guarantees

- DHCP candidate is generated, checked with `dhcpd -t`, backed up, atomically installed, and rolled back if restart fails. DHCP deployment restarts only `isc-dhcp-server`; Nginx is not restarted.
- Persistent state lives in `/var/lib/ztp-app`; legacy app-directory JSON is migrated once. JSON writes use temp + `fsync` + `os.replace()` and backups.
- `STATIC` is exact and never falls back. `AUTO` requires `auto_pool_enabled=true` plus exact model/group or explicit `allow_any_model=true`. Unknown/mismatch/metadata errors are visible.
- Config uploads are checksum-aware (`ADDED`, `UPDATED`, `UNCHANGED`, `PROTECTED`, `FAILED`). Reserved/fetching/delivered/active files cannot be overwritten or deleted.
- ZTP delivery is promoted only after structured Nginx reconciliation proves a complete response. Partial 200 and HTTP errors remain visible failures; cursors survive log rotation.
- Export/import ZIP has a manifest and checksums and excludes credentials, admin hashes, and the Flask secret. Import validates and backs up before atomic restore; it never starts DHCP.

## Install on Ubuntu VM

Use an Ubuntu VM/appliance with a bridged NIC on the ZTP VLAN. WSL2 NAT is not suitable for a real DHCP server.

```bash
cd ~/projects/ztp-app
sudo BRIDGE_IF=<ztp-interface> deploy/install.sh
```

The installer creates a Python venv, Nginx, `/var/lib/ztp-app`, and `ztp-app.service`. It does not automatically start DHCP when a mode is selected; use the UI Apply action after the interface and pool checks pass.

## UI workflow

1. Settings → choose mode. Entering `FILE_SERVER_ONLY` requires confirmation to stop/disable DHCP. Entering a DHCP mode is saved without starting until Apply.
2. Refresh interfaces; select Internet and ZTP interfaces. The ZTP interface must be physically linked, have IPv4 equal to Server IP, and differ from Internet.
3. Suggest the pool using CIDR mask length; verify subnet/ranges and that no other DHCP server shares the L2 segment.
4. Upload config files. New files are disabled from Auto Pool until metadata is reviewed.
5. Overview → open **Mapping setup (advanced)** to add a Specific Device or Generic Profile. Confirm raw DHCP Option 60 before serial/vendor rules.
6. Test one device, inspect Logs, then scale out. HTTP 200 alone is not delivery; only complete bytes promote a file to `DELIVERED`.

## Development and tests

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
ZTP_DEV=1 ZTP_WEBROOT=./_webroot ZTP_DHCPD=./_dhcpd.conf python app.py
python -m unittest -v
```

The deploy and rollback path is intentionally production-gated: inspect the candidate and the readiness panel before connecting devices.
