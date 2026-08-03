# ztp-app v26.08.09 — hướng dẫn vận hành

`ztp-app` là bảng điều khiển Flask cho Juniper ZTP trên một VLAN/L2 cô lập. Thiết bị nhận DHCP, tải file từ Nginx và tự commit. App không SSH để đẩy cấu hình trực tiếp.

## Ba operating mode

- `ZTP_PROVISIONING`: DHCP cấp mạng và mọi client dùng `/ztp/config`; resolver chọn file theo `STATIC` hoặc `AUTO`.
- `DHCP_FILE_SERVER`: DHCP chỉ cấp IP/subnet/gateway/DNS; không có Option ZTP, không assignment. Người vận hành tải file trực tiếp từ `/configs/<filename>`.
- `FILE_SERVER_ONLY`: chỉ Nginx/Flask và file download; ISC DHCP không được chạy, không lease/parser/resolver.

`FULL_ZTP` cũ được tự động đổi thành `ZTP_PROVISIONING`. `DHCP_ONLY` cũ chỉ được giữ để đọc/audit, không thể tạo mới và không được resolver cấp file.

## Quick Start trên UI

1. **Settings → Operating mode**: chọn mode. Khi vào `FILE_SERVER_ONLY`, xác nhận stop/disable DHCP. Khi vào mode DHCP, chọn **Apply** mới validate candidate và start/enable; chỉ Save thì không tự start.
2. **Settings → Network**: bấm **Refresh interfaces**, chọn Internet interface và ZTP interface, kiểm tra link/IPv4. Bấm **Suggest pool**, nhập `Mask length` (ví dụ `24`), rà lại Server IP/range và xác nhận không có DHCP server khác cùng L2.
3. **Config Files**: upload `.conf`/`.txt`. File mới mặc định không vào Auto Pool. Bật Auto Pool tại bảng metadata, rồi khai báo model/group hoặc `Allow any model`.
4. **Overview → Mapping setup (advanced)**: `STATIC` = file cố định; `AUTO` = resolver chọn file đã opt-in. Serial chỉ dùng khi đã xác nhận serial nằm cuối Option 60; MAC cần DHCP IP khi có reservation.
5. **Logs**: xem raw Option 60, DHCP lease và structured Nginx fetch. Chỉ response đủ bytes mới chuyển `DELIVERED`/`DOWNLOADED`; HTTP 200 partial là lỗi cần xem lại.
6. Test một thiết bị trước, sau đó mới mở rộng batch. Không còn bước Health/SSH/manual verification trong workflow chính.

## Cài trên Ubuntu VM

WSL2 NAT không phù hợp làm DHCP server cho switch thật. Dùng Ubuntu VM/appliance có NIC bridged vào đúng VLAN ZTP:

```bash
cd ~/projects/ztp-app
sudo BRIDGE_IF=<ztp-interface> deploy/install.sh
```

Script tạo venv, cài dependency, Nginx, thư mục bền vững `/var/lib/ztp-app` và systemd service. Runtime JSON/config không bị ghi đè khi cập nhật. DHCP chỉ được enable/start khi operator Apply trong UI (hoặc đặt `APPLY_DHCP_ON_INSTALL=1` khi thật sự cần).

Kiểm tra:

```bash
systemctl is-active ztp-app.service
systemctl is-active nginx
ip -br link
ip -br -4 addr
```

## An toàn và rollback

- Mọi JSON dùng temp + `fsync` + `os.replace()` và có `.bak`; JSON hỏng làm deploy dừng.
- DHCP deploy sinh candidate, chạy `dhcpd -t`, backup `/etc/dhcp/dhcpd.conf`, atomic replace; restart lỗi sẽ restore và restart bản backup. Không restart Nginx khi deploy DHCP.
- File config có checksum; file đang reserved/fetching/delivered/active download không được ghi đè/xóa. Cùng checksum trả `UNCHANGED`; file mới là `ADDED`; thay đổi không bị bảo vệ là `UPDATED` và giữ metadata.
- **Export all** tạo ZIP có manifest/checksum, không chứa credentials/admin secret. **Import all** preview/validate trước, backup trước restore, không tự start DHCP.
- Dừng khẩn cấp: `sudo systemctl stop isc-dhcp-server` rồi `sudo systemctl stop ztp-app.service`. Không dùng `git reset --hard` để rollback runtime.

## Kiểm tra trước ZTP thật

1. ZTP interface có `LOWER_UP`, IPv4 đúng bằng Server IP và khác Internet interface.
2. Pool nằm trong RFC1918 subnet đúng VLAN, không chứa server IP, IP tĩnh hay dynamic pool overlap.
3. Chỉ dùng file đã pass `root-authentication`, không bật `chassis auto-image-upgrade`, URL dưới giới hạn.
4. Xác nhận raw Option 60 bằng `sudo tcpdump -ni <if> -vvv -s0 'port 67 or port 68'`.
5. Preview candidate, kiểm tra `dhcpd -t`, test một thiết bị, xem Logs rồi mới triển khai batch.

## Development và test

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
ZTP_DEV=1 ZTP_WEBROOT=./_webroot ZTP_DHCPD=./_dhcpd.conf python app.py
python -m unittest -v
```

Version hiện tại: **26.08.09**.
