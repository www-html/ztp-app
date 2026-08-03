#!/usr/bin/env bash
set -euo pipefail

# Recover the last atomically backed-up DHCP candidate and config state.
# This script never changes Git or runtime JSON; it only restores the named
# production files after an operator has stopped DHCP.
[ "$(id -u)" -eq 0 ] || { echo "Run as root" >&2; exit 1; }

DHCPD_CONF="${ZTP_DHCPD:-/etc/dhcp/dhcpd.conf}"
DHCP_BACKUP="${DHCPD_CONF}.ztp-app.bak"
if [ -f "$DHCP_BACKUP" ]; then
  install -m 0644 "$DHCP_BACKUP" "$DHCPD_CONF"
  dhcpd -t -cf "$DHCPD_CONF"
  systemctl restart isc-dhcp-server
  echo "Restored $DHCPD_CONF from $DHCP_BACKUP"
else
  echo "No DHCP backup found at $DHCP_BACKUP" >&2
  exit 1
fi
