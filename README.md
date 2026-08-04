# ztp-app v26.09.0

Vendor-neutral Juniper ZTP operations console: Flask + Nginx + optional ISC DHCP. It runs on an isolated L2 ZTP VLAN; devices receive DHCP, fetch a config over HTTP, and commit it themselves.

## Operating modes

| Mode | DHCP | Resolver | Intended use |
|---|---|---|---|
| `ZTP_PROVISIONING` | network + ZTP options | `/ztp/config` | MAC-first ordered project allocation |
| `DHCP_FILE_SERVER` | network parameters only | none | DHCP plus manual `/configs/<file>` downloads |
| `FILE_SERVER_ONLY` | disabled/stopped | none | Nginx/Flask file server only |

`FULL_ZTP` is migrated to `ZTP_PROVISIONING`. Legacy `DHCP_ONLY` records remain readable/auditable but cannot be created or resolved into a config.

## Safety guarantees

- DHCP candidate is generated, checked with `dhcpd -t`, backed up, atomically installed, and rolled back if restart fails. DHCP deployment restarts only `isc-dhcp-server`; Nginx is not restarted.
- Canonical project, device assignment, and config ownership live in `/var/lib/ztp-app/provisioning_state.json` and commit under one global lock with temp + `fsync` + `os.replace()`.
- The resolver uses normalized MAC as its identity. It does not select a file by serial, model, Option 60, static profile, or syslog; existing assignments are always reused.
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

### One Windows 11 laptop topology

Do not run the production DHCP listener inside WSL2. WSL2/NAT does not reliably deliver Layer-2 DHCP broadcasts to the Linux namespace, so Windows Wireshark may see `DHCPDISCOVER` while `dhcpd` in WSL sees nothing. Use two NICs: Wi-Fi for Internet and a USB/Ethernet NIC for ZTP. Create a Hyper-V **External Virtual Switch** bound only to the ZTP NIC, then attach an Ubuntu VM to that switch. Put the VM's bridged interface on the ZTP subnet and install/run `isc-dhcp-server` there. WSL2 may remain the development/UI environment.

On Windows 11 Home, use VirtualBox with **Bridged Adapter** bound to the ZTP NIC instead of Hyper-V. Do not use Wi-Fi sharing, NAT, or a router between the VM and the ZTP switch.

## UI workflow

1. Settings → choose mode. Entering `FILE_SERVER_ONLY` requires confirmation to stop/disable DHCP. Entering a DHCP mode is saved without starting until Apply.
2. Refresh interfaces; select Internet and ZTP interfaces. The ZTP interface must be physically linked, have IPv4 equal to Server IP, and differ from Internet.
3. Suggest the pool using CIDR mask length; verify subnet/ranges and that no other DHCP server shares the L2 segment.
4. Upload and validate the ordered config pool. Set the expected project size, resolve activation checks, and change the project to `ACTIVE`.
5. Use the recent client view for operations and CSV/XLSX for the full persistent mapping. Archive never deletes history; delivered reset requires review and a separate config release.
6. Test two or three devices, verify unique MAC-to-file ownership and complete-byte delivery, then scale out.

`/configs/` is blocked in `ZTP_PROVISIONING` so devices cannot bypass the resolver. Directory listing remains available in `DHCP_FILE_SERVER` and `FILE_SERVER_ONLY`; authenticated config viewing remains available in the application UI.

## State migration

On first startup, legacy `assignments.json` and `config_pool.json` are backed up under `migration-backup-provisioning-v1` and migrated idempotently. Legacy files remain as compatibility snapshots. Migrated/new projects start `PAUSED` and preserve existing assignments until an operator activates the project.

## Development and tests

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
ZTP_DEV=1 ZTP_WEBROOT=./_webroot ZTP_DHCPD=./_dhcpd.conf python app.py
python -m unittest -v
```

The deploy and rollback path is intentionally production-gated: inspect the candidate and the readiness panel before connecting devices.
