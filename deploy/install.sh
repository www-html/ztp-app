#!/usr/bin/env bash
# install.sh — provision the ZTP Manager appliance on Ubuntu (VMware VM, bridged into the L2 ZTP domain).
# Run as root.  Idempotent.
set -euo pipefail

APP_SRC="$(cd "$(dirname "$0")/.." && pwd)"   # the ztp-app/ directory
APP_DST="/opt/ztp-app"
BRIDGE_IF="${BRIDGE_IF:-ens37}"               # NIC bridged to the access switch (L2)
export DEBIAN_FRONTEND=noninteractive
[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }

echo "==> [1/6] Packages"
apt-get update -qq
apt-get install -y isc-dhcp-server nginx python3-venv python3-pip >/dev/null

echo "==> [2/6] App -> $APP_DST"
mkdir -p "$APP_DST"
cp -r "$APP_SRC"/. "$APP_DST"/
python3 -m venv "$APP_DST/.venv"
"$APP_DST/.venv/bin/pip" install -q --upgrade pip
"$APP_DST/.venv/bin/pip" install -q -r "$APP_DST/requirements.txt"

echo "==> [3/6] Nginx web root (serves http://<server>/configs/*)"
mkdir -p /var/www/html/configs
chown -R www-data:www-data /var/www/html/configs
systemctl enable --now nginx

echo "==> [4/6] DHCP listen interface = $BRIDGE_IF"
sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$BRIDGE_IF\"/" /etc/default/isc-dhcp-server 2>/dev/null \
  || echo "INTERFACESv4=\"$BRIDGE_IF\"" >> /etc/default/isc-dhcp-server
# Seed a minimal valid dhcpd.conf so the service can start before first deploy.
[ -s /etc/dhcp/dhcpd.conf ] || cat > /etc/dhcp/dhcpd.conf <<'EOF'
default-lease-time 600; max-lease-time 7200;
subnet 19.96.0.0 netmask 255.255.0.0 { range 19.96.0.10 19.96.255.254; }
EOF

echo "==> [5/6] systemd unit (waitress on :8080)"
install -m 0644 "$APP_DST/deploy/ztp-app.service" /etc/systemd/system/ztp-app.service
systemctl daemon-reload
systemctl enable --now ztp-app.service

echo "==> [6/6] Validate + start DHCP"
if dhcpd -t -cf /etc/dhcp/dhcpd.conf >/dev/null 2>&1; then
  systemctl enable --now isc-dhcp-server
else
  echo "WARN: dhcpd.conf invalid — fix in the UI before enabling isc-dhcp-server."
fi

IP="$(hostname -I | awk '{print $1}')"
echo "Done. Open the UI at http://$IP:8080  (Dashboard -> set DHCP pool + credentials)."
echo "Make sure $BRIDGE_IF is bridged into the same L2 domain as the devices."
echo
echo "Admin login defaults to admin/admin (or ZTP_ADMIN_USER/ZTP_ADMIN_PASSWORD if set"
echo "in ztp-app.service before first start). CHANGE IT NOW at Dashboard -> Admin Login."
echo "(admin_auth.json is chmod 600 under /opt/ztp-app; delete it to reset to defaults.)"
