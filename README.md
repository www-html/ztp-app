# ztp-app v27.0.0

Serial-first Juniper ZTP operations console using Flask, Nginx and ISC DHCP on an isolated Layer-2 deployment network.

## What changed in v27

- DHCP Option 60 is stored in `dhcpd.leases` as `vendor-string`; syslog is troubleshooting-only.
- Serial Number is the provisioning identity. MAC and DHCP IP are observations only.
- Resolver priority is: existing serial assignment, exact-serial Device Override, exact-prefix Vendor Profile.
- Every Vendor Profile has one device model and one named config pool. There is no global `AVAILABLE` fallback.
- UI results are only `In Progress`, `Completed`, and `Error`.
- Operators can test Option 60, release an assignment, export deployment reports and reset the workspace safely.
- Legacy MAC keys, Specific Device rows, Contains/Regex profiles and `VERIFIED` states remain migratable and auditable.

## Operating modes

- `ZTP_PROVISIONING`: DHCP, lease Option 60 capture, automatic `/ztp/config` resolver and manual `/ztp/config/<filename>` download.
- `DHCP_FILE_SERVER`: DHCP network parameters plus manual file download; no automatic assignment.
- `FILE_SERVER_ONLY`: file server only. This advanced mode stops and disables ISC DHCP.

Changing mode does not delete settings, leases, assignments, configs, profiles or logs.

## Serial-first allocation

Supported Option 60 examples:

```text
Juniper-ex4100-h-12mp-GE4825AW015
Juniper-ex4100-24p-GE4825AW016
Juniper-ex4100-24t-GE4825AW017
```

The application splits each value into a literal vendor/model prefix and an alphanumeric serial suffix. A new assignment is rejected when Option 60 is unavailable, the serial cannot be parsed, the profile is ambiguous, the named pool is empty, the config model differs or another serial owns the file.

Recommended profiles:

```text
EX4100-H-12MP
Vendor Prefix: Juniper-ex4100-h-12mp-
Device Model: EX4100-H-12MP
Config Pool: OXISANTA_EX4100_H_12MP

EX4100-24P
Vendor Prefix: Juniper-ex4100-24p-
Device Model: EX4100-24P
Config Pool: OXISANTA_EX4100_24P

EX4100-24T
Vendor Prefix: Juniper-ex4100-24t-
Device Model: EX4100-24T
Config Pool: OXISANTA_EX4100_24T
```

Existing `OXISANTA_EX4100_PCxx` inventory is migrated to model `EX4100-H-12MP` and pool `OXISANTA_EX4100_H_12MP`. Office/MGMT filenames are not included by this automatic migration.

## Operator workflow

1. Open Settings and apply `ZTP Provisioning`.
2. Refresh interfaces, select different Internet and ZTP interfaces, then validate the RFC1918 DHCP subnet and pool.
3. Upload configs in Config Inventory. Set one Model, Pool and allocation order on every allocatable file.
4. Create a Vendor Profile with the exact prefix, model and pool.
5. Use Test Option 60 with a real value such as `Juniper-ex4100-h-12mp-GE4825AW015`.
6. Set the deployment project to `ACTIVE` only after activation checks pass.
7. Connect one device. Confirm Serial Number, model, config and result under Deployment Status before scaling out.
8. `Completed` means the server delivered HTTP 200 with exactly the expected file byte count. It does not claim that Junos committed the configuration.

A Device Override matches one exact serial and can select either one exact config or one named pool. Existing assignment always remains first priority.

## Manual config download

- Automatic resolver: `GET /ztp/config`
- Explicit file: `GET /ztp/config/<filename>`

In ZTP mode, an explicit file download requires an active lease with a valid serial. An Available file becomes owned by that serial; the same serial may download it again, while another serial receives `CONFIG_OWNERSHIP_CONFLICT`. Manual download never selects a fallback pool or changes another assignment.

## State and safety

- Canonical state: `/var/lib/ztp-app/provisioning_state.json`.
- Project, assignment and config ownership changes use one `fcntl` allocation lock.
- JSON writes use backup, temp file, `fsync` and `os.replace()`.
- Audit history remains append-only JSONL.
- DHCP deploy validates a candidate with `dhcpd -t`, backs up the active file, atomically replaces it, restarts only `isc-dhcp-server` and rolls back on failure.
- Config validation requires `root-authentication`, blocks `chassis auto-image-upgrade`, checks file existence and URL length.
- Migration backs up state before converting MAC keys to serial keys. Records without a serial become `SERIAL_NOT_PARSED`; their owned config is not returned to the pool automatically.

`Reset for Retest` clears leases, observed clients, assignments, runtime/download records and ownership while keeping settings, configs, profiles, overrides, logs and audit history.

`Reset Clean Workspace` also removes uploaded configs, config metadata, overrides and profiles. Both presets stop DHCP, create a backup, update state atomically, move parser cursors to EOF, restart/validate DHCP and restore the backup if the operation fails.

## Install on an Ubuntu VM

Use a bridged Ubuntu VM connected directly to the isolated ZTP NIC/VLAN. WSL2 NAT does not reliably carry DHCP broadcasts from physical switches.

```bash
cd ~/ztp-app
sudo env BRIDGE_IF=eth1 ZTP_MODE=ZTP_PROVISIONING bash deploy/install.sh
sudo nginx -t
sudo systemctl restart ztp-app.service nginx isc-dhcp-server
sudo systemctl status ztp-app.service nginx isc-dhcp-server --no-pager
```

The installer creates `/opt/ztp-app/.venv`; do not use system `pip` or `sudo pip`.

## Update and rollback

```bash
cd ~/ztp-app
git status --short
git pull --ff-only origin main
sudo env BRIDGE_IF=eth1 ZTP_MODE=ZTP_PROVISIONING bash deploy/install.sh
```

Verify:

```bash
sudo dhcpd -t -cf /etc/dhcp/dhcpd.conf
systemctl is-active ztp-app.service nginx isc-dhcp-server
grep -n 'set vendor-string' /etc/dhcp/dhcpd.conf
```

Rollback source by checking out the previous known-good commit and rerunning the installer. Runtime state remains under `/var/lib/ztp-app`; use Export All before major maintenance.

## Development and tests

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
ZTP_DEV=1 python -m unittest -v
```
