#!/usr/bin/env bash
# install.sh — provision the ZTP Manager appliance on Ubuntu (VMware VM, bridged into the L2 ZTP domain).
# Run as root.  Idempotent.
set -euo pipefail

APP_SRC="$(cd "$(dirname "$0")/.." && pwd)"   # the ztp-app/ directory
APP_DST="/opt/ztp-app"
BRIDGE_IF="${BRIDGE_IF:-ens37}"               # NIC bridged to the access switch (L2)
ZTP_MODE="${ZTP_MODE:-ZTP_PROVISIONING}"      # ZTP_PROVISIONING, DHCP_FILE_SERVER or FILE_SERVER_ONLY
ZTP_MODE="${ZTP_MODE/FULL_ZTP/ZTP_PROVISIONING}"
case "$ZTP_MODE" in
  ZTP_PROVISIONING|DHCP_FILE_SERVER|FILE_SERVER_ONLY) ;;
  *) echo "ZTP_MODE must be ZTP_PROVISIONING, DHCP_FILE_SERVER or FILE_SERVER_ONLY" >&2; exit 1 ;;
esac
export DEBIAN_FRONTEND=noninteractive
[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }

echo "==> [1/6] Packages"
apt-get update -qq
apt-get install -y nginx python3-venv python3-pip >/dev/null
if [ "$ZTP_MODE" != "FILE_SERVER_ONLY" ]; then
  apt-get install -y isc-dhcp-server >/dev/null
fi

echo "==> [2/6] App -> $APP_DST"
mkdir -p "$APP_DST"
cp -r "$APP_SRC"/. "$APP_DST"/
mkdir -p /var/lib/ztp-app
# Persistent state survives application updates.  Never overwrite an
# existing runtime file from the previous installation.
for state in devices.json static_mappings.json generic_profiles.json settings.json creds.json provisioning_state.json config_pool.json assignments.json results.json history.jsonl device_runtime.json download_records.json parser_cursors.json admin_auth.json .secret_key; do
  [ -e "$APP_DST/$state" ] && [ -e "/var/lib/ztp-app/$state" ] || [ ! -e "$APP_DST/$state" ] || cp -an "$APP_DST/$state" "/var/lib/ztp-app/$state"
done
chown -R root:root /var/lib/ztp-app
chmod 700 /var/lib/ztp-app
python3 -m venv "$APP_DST/.venv"
"$APP_DST/.venv/bin/pip" install -q --upgrade pip
"$APP_DST/.venv/bin/pip" install -q -r "$APP_DST/requirements.txt"

echo "==> [3/6] Nginx web root (serves http://<server>/configs/*)"
mkdir -p /var/www/html/configs
chown -R www-data:www-data /var/www/html/configs
install -m 0644 "$APP_DST/deploy/ztp-nginx-site.conf" /etc/nginx/sites-available/ztp-app
ln -sfn /etc/nginx/sites-available/ztp-app /etc/nginx/sites-enabled/ztp-app
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable --now nginx
systemctl reload nginx

echo "==> [4/6] Runtime mode = $ZTP_MODE"
if [ "$ZTP_MODE" != "FILE_SERVER_ONLY" ]; then
  echo "    DHCP listen interface = $BRIDGE_IF"
  sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$BRIDGE_IF\"/" /etc/default/isc-dhcp-server 2>/dev/null \
    || echo "INTERFACESv4=\"$BRIDGE_IF\"" >> /etc/default/isc-dhcp-server
  # Seed an RFC1918 candidate; the UI replaces it only after dhcpd -t passes.
  [ -s /etc/dhcp/dhcpd.conf ] || cat > /etc/dhcp/dhcpd.conf <<'EOF'
default-lease-time 600; max-lease-time 7200;
subnet 192.168.250.0 netmask 255.255.255.0 { range 192.168.250.10 192.168.250.254; }
EOF
else
  echo "    FILE_SERVER_ONLY: isc-dhcp-server is not installed or configured."
fi

echo "==> [5/6] systemd unit (waitress on :8080)"
sed -i "s/^Environment=ZTP_MODE=.*/Environment=ZTP_MODE=$ZTP_MODE/" "$APP_DST/deploy/ztp-app.service"
grep -q '^Environment=ZTP_DATA_DIR=' "$APP_DST/deploy/ztp-app.service" || sed -i "/Environment=ZTP_WEBROOT=/a Environment=ZTP_DATA_DIR=/var/lib/ztp-app" "$APP_DST/deploy/ztp-app.service"
install -m 0644 "$APP_DST/deploy/ztp-app.service" /etc/systemd/system/ztp-app.service
systemctl daemon-reload
systemctl enable --now ztp-app.service

echo "==> [6/6] Validate + start services"
if [ "$ZTP_MODE" != "FILE_SERVER_ONLY" ] && [ "${APPLY_DHCP_ON_INSTALL:-0}" = "1" ]; then
  if dhcpd -t -cf /etc/dhcp/dhcpd.conf >/dev/null 2>&1; then
    systemctl enable --now isc-dhcp-server
  else
    echo "WARN: dhcpd.conf invalid — fix in the UI before enabling isc-dhcp-server."
  fi
fi

IP="$(hostname -I | awk '{print $1}')"
echo "Done. Open the UI at http://$IP:8080  (Settings -> choose mode, interfaces and DHCP pool)."
echo "Make sure $BRIDGE_IF is bridged into the same L2 domain as the devices."
echo
echo "Admin login defaults to admin/admin (or ZTP_ADMIN_USER/ZTP_ADMIN_PASSWORD if set"
echo "in ztp-app.service before first start). Change it before production use."
echo "(admin_auth.json is chmod 600 under /opt/ztp-app; delete it to reset to defaults.)"
