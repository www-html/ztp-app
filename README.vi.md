# ztp-app v26.09.0 — hướng dẫn vận hành

`ztp-app` là bảng điều khiển Flask cho Juniper ZTP trên một VLAN/L2 cô lập. Thiết bị nhận DHCP, tải file từ Nginx và tự commit. App không SSH để đẩy cấu hình trực tiếp.

## Ba operating mode

- `ZTP_PROVISIONING`: DHCP cấp mạng; thiết bị chỉ dùng `/ztp/config`. MAC claim file `AVAILABLE` tiếp theo theo `allocation_order` và luôn nhận lại đúng file đã claim.
- `DHCP_FILE_SERVER`: DHCP chỉ cấp IP/subnet/gateway/DNS; không có Option ZTP, không assignment. Người vận hành tải file trực tiếp từ `/configs/<filename>`.
- `FILE_SERVER_ONLY`: chỉ Nginx/Flask và file download; ISC DHCP không được chạy, không lease/parser/resolver.

`FULL_ZTP` cũ được tự động đổi thành `ZTP_PROVISIONING`. `DHCP_ONLY` cũ chỉ được giữ để đọc/audit, không thể tạo mới và không được resolver cấp file.

## Quick Start trên UI

1. **Settings → Operating mode**: chọn mode. Khi vào `FILE_SERVER_ONLY`, xác nhận stop/disable DHCP. Khi vào mode DHCP, chọn **Apply** mới validate candidate và start/enable; chỉ Save thì không tự start.
2. **Settings → Network**: bấm **Refresh interfaces**, chọn Internet interface và ZTP interface, kiểm tra link/IPv4. Bấm **Suggest pool**, nhập `Mask length` (ví dụ `24`), rà lại Server IP/range và xác nhận không có DHCP server khác cùng L2.
3. **Config Files**: upload các config đã chuẩn bị, kiểm tra checksum và `allocation_order`. Với nhóm EX4100, đặt `Pool name` của các file `OXISANTA_EX4100_PCxx` là `OXISANTA_EX4100`. File `AVAILABLE` mới trong đúng pool sẽ được cấp; `ASSIGNED`, `DELIVERED`, `VERIFIED` và `REVIEW_REQUIRED` được bảo vệ.
4. **Overview → Project control**: đặt số thiết bị dự kiến, xử lý các activation check, rồi chuyển project sang `ACTIVE`. `PAUSED` chặn MAC mới nhưng vẫn cho thiết bị đã assignment tải lại file cũ.
5. **Recent provisioning clients**: filter theo state, MAC/serial/config/IP/thời gian. Dùng **Verify** sau khi xác nhận thiết bị đã load/commit đúng; **Archive** chỉ ẩn khỏi recent UI và không xóa báo cáo.
6. **Logs**: xem 200 audit event gần nhất và raw log khi troubleshooting. Chỉ response đủ bytes mới chuyển `DELIVERED`; HTTP 200 partial không được coi là thành công.

### Gắn Vendor ID EX4100 vào pool OXISANTA

Trong **Overview → Mapping setup (advanced) → Generic Profile**, tạo profile:

- Vendor Option 60: `Juniper-ex4100-h-12mp-xxx`
- Match: `Contains`
- Assignment: `AUTO`
- Allocation pool: `OXISANTA_EX4100`
- Option 60 confirmed: `Yes`

Trong **Config Files**, đặt `Pool name` của từng file `OXISANTA_EX4100_PC01.conf`, `OXISANTA_EX4100_PC02.conf`, ... thành `OXISANTA_EX4100` và đặt `Order` theo thứ tự cấp phát. EX4100 chỉ lấy file `AVAILABLE` trong pool này; nếu pool rỗng app dừng với `PROFILE_POOL_EMPTY`, không fallback sang EX4400.

Trong `ZTP_PROVISIONING`, `/configs/` bị chặn để client không bypass resolver. Directory listing chỉ hoạt động trong `DHCP_FILE_SERVER` và `FILE_SERVER_ONLY`. Specific Device/Generic Profile vẫn không làm thay đổi identity MAC-first; Generic Profile `AUTO` có thể giới hạn allocation vào `Pool name` tương ứng.

## State và migration v26.09

- State canonical nằm tại `/var/lib/ztp-app/provisioning_state.json`; project, device assignment và config ownership được commit cùng một allocation lock và một atomic replace.
- Lần khởi động đầu tiên tự backup `config_pool.json` và `assignments.json` vào `migration-backup-provisioning-v1`, sau đó migrate idempotent. File cũ được giữ làm compatibility snapshot, không bị xóa.
- Project mới/migrated mặc định `PAUSED`. Operator phải review validation rồi chuyển `ACTIVE`; assignment cũ vẫn được giữ.
- Full mapping CSV/XLSX luôn lấy toàn bộ persistent state, không phụ thuộc giới hạn 100 client trên UI.

## Cài trên Ubuntu VM

WSL2 NAT không phù hợp làm DHCP server cho switch thật. Dùng Ubuntu VM/appliance có NIC bridged vào đúng VLAN ZTP:

```bash
cd ~/projects/ztp-app
sudo BRIDGE_IF=<ztp-interface> deploy/install.sh
```

Script tạo venv, cài dependency, Nginx, thư mục bền vững `/var/lib/ztp-app` và systemd service. Runtime JSON/config không bị ghi đè khi cập nhật. DHCP chỉ được enable/start khi operator Apply trong UI (hoặc đặt `APPLY_DHCP_ON_INSTALL=1` khi thật sự cần).

### Chỉ có một laptop Windows 11

Không chạy DHCP production trực tiếp trong WSL2. WSL2/NAT không chuyển ổn định DHCP broadcast Layer-2 vào Ubuntu; có thể Wireshark trên Windows thấy `DHCPDISCOVER` nhưng `dhcpd` trong WSL không thấy gói. Dùng hai NIC: Wi-Fi cho Internet và USB/LAN NIC cho ZTP. Tạo Hyper-V **External Virtual Switch** chỉ gắn với NIC ZTP, sau đó gắn Ubuntu VM vào switch này. Đặt IP tĩnh cho NIC VM trên subnet ZTP và chạy `isc-dhcp-server` trong VM. WSL2 vẫn có thể dùng để phát triển/UI.

Nếu Windows 11 Home không có Hyper-V, dùng VirtualBox với **Bridged Adapter** gắn vào NIC ZTP. Không dùng Wi-Fi sharing, NAT hoặc router ở giữa VM và switch ZTP.

Kiểm tra:

```bash
systemctl is-active ztp-app.service
systemctl is-active nginx
ip -br link
ip -br -4 addr
```

## An toàn và rollback

- Provisioning runtime dùng một canonical JSON, temp + `fsync` + `os.replace()`; JSON hỏng làm deploy dừng.
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

## Update Ubuntu VM an toàn

Không xóa hoặc reset `/var/lib/ztp-app`:

```bash
cd ~/projects/ztp-app
git pull --ff-only origin main
sudo BRIDGE_IF=<ztp-interface> deploy/install.sh
sudo systemctl restart ztp-app.service
sudo systemctl is-active ztp-app.service nginx
```

Rollback source: checkout commit trước, chạy lại installer; state/runtime vẫn giữ nguyên. Trước rollback nên dùng **Export all data**.

Version hiện tại: **26.09.0**.
