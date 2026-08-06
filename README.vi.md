# ztp-app v28.1.0 — hướng dẫn vận hành

v28.1.0 bổ sung thời gian browser dạng ngắn, nhập network bằng CIDR, pagination,
favicon và layout workflow gọn hơn. v28.0.0 bổ sung navigation ngang, hướng dẫn workflow, thời gian theo trình duyệt,
import CSV Serial-to-Config có preview và bộ reconcile trạng thái chạy độc lập.

`ztp-app` là công cụ Juniper ZTP theo Serial Number, chạy bằng Flask, Nginx và ISC DHCP trên một mạng Layer-2 ZTP cô lập.

## Điểm chính của v27

- DHCP Option 60 được lưu vào `dhcpd.leases` dưới tên `vendor-string`.
- Serial Number là identity duy nhất để chọn và giữ ownership của config.
- MAC và DHCP IP chỉ là `observed_mac`, `current_dhcp_ip`, `last_seen`; không dùng để chọn config.
- Thứ tự xử lý: assignment cũ theo serial → Device Override → Vendor Profile → file Available trong đúng named pool.
- Không fallback sang toàn bộ config Available.
- Model và pool được tách tuyệt đối.
- UI chỉ hiển thị ba kết quả: `In Progress`, `Completed`, `Error`.
- Có Test Option 60, Release Assignment, Deployment Report và hai preset Reset Workspace.
- Vendor Profile đã lưu được hiển thị và chỉnh sửa theo luồng `Option 60 prefix → model → pool → filename pattern`.
- Pattern như `OXISANTA_EX4100_PC*` chỉ được áp dụng bên trong đúng named pool, không tạo global fallback.

## Hai mode chính

- `ZTP Provisioning`: bật DHCP, ghi Option 60 vào lease, bật resolver tự động `/ztp/config` và cho tải file thủ công `/ztp/config/<filename>`.
- `DHCP + Manual File Server`: DHCP chỉ cấp thông số mạng; người vận hành chọn file thủ công.

`File Server Only` nằm trong Advanced và sẽ stop/disable ISC DHCP. Đổi mode không xóa network settings, DHCP settings, leases, clients, assignments, configs, profiles hoặc logs.

## Option 60 và Serial Number

Thiết bị Juniper gửi các chuỗi như:

```text
Juniper-ex4100-h-12mp-GE4825AW015
Juniper-ex4100-24p-GE4825AW016
Juniper-ex4100-24t-GE4825AW017
```

App tự tách:

```text
Vendor/model prefix: Juniper-ex4100-h-12mp-
Serial Number: GE4825AW015
```

Không cần viết regex trên UI. Nếu lease không có Option 60, suffix serial không hợp lệ, profile không khớp hoặc khớp nhiều profile, app dừng và không cấp config.

## Tạo Vendor Profile

Vào `Settings → Vendor Profile` và tạo riêng theo từng model:

```text
Profile Name: EX4100-H-12MP
Vendor Prefix: Juniper-ex4100-h-12mp-
Device Model: EX4100-H-12MP
Config Pool: OXISANTA_EX4100_H_12MP
```

```text
Profile Name: EX4100-24P
Vendor Prefix: Juniper-ex4100-24p-
Device Model: EX4100-24P
Config Pool: OXISANTA_EX4100_24P
```

```text
Profile Name: EX4100-24T
Vendor Prefix: Juniper-ex4100-24t-
Device Model: EX4100-24T
Config Pool: OXISANTA_EX4100_24T
```

Các file `OXISANTA_EX4100_PCxx` cũ được migrate sang model `EX4100-H-12MP` và pool `OXISANTA_EX4100_H_12MP`. File có tên `OFF_SW` hoặc `MGMT` không bị đưa tự động vào pool này.

## Quy trình ZTP từng bước

### Bước 1 — Chuẩn bị mạng

Vào `Settings → DHCP Network`:

1. Bấm `Refresh Interfaces`.
2. Chọn Internet Interface và ZTP Interface khác nhau.
3. Kiểm tra ZTP interface có link và IPv4 đúng bằng Server IP.
4. Kiểm tra Subnet, Mask Length, Range Low và Range High.
5. Xác nhận đây là mạng ZTP cô lập, không có DHCP server khác.
6. Bấm `Save & Apply DHCP`.

### Bước 2 — Chuẩn bị Config Inventory

Vào `Config Inventory`:

1. Upload hoặc Bulk Upload các file `.conf`/`.txt`.
2. Chọn các file chưa dùng.
3. Đặt đúng `Model`, `Pool` và `First order`.
4. Bấm `Update Selected`.
5. Kiểm tra mỗi file hiển thị đúng Model và Pool trước khi ZTP.

Một pool chỉ được chứa config của một model. EX4100-24P không thể nhận config EX4100-24T hoặc EX4100-H-12MP.

### Bước 3 — Test Option 60

Vào `Settings → Test Option 60`, nhập giá trị thật:

```text
Juniper-ex4100-h-12mp-GE4825AW015
```

Kết quả phải hiển thị đúng:

```text
Matched profile: EX4100-H-12MP
Model: EX4100-H-12MP
Serial: GE4825AW015
Pool: OXISANTA_EX4100_H_12MP
```

### Bước 4 — Device Override nếu cần

Chỉ tạo Device Override khi một serial cần file/pool khác quy tắc chung:

- `Serial Number`: bắt buộc, exact match.
- `Expected Model`: bắt buộc.
- `Exact Config`: chọn đúng một file; hoặc
- `Named Pool`: chọn pool dành riêng.

Không có Device Override theo MAC. Assignment cũ của serial vẫn ưu tiên cao nhất; phải Release Assignment trước khi đổi override đang sử dụng.

### Bước 5 — Kích hoạt và test một thiết bị

1. Mở `Settings → Deployment Control`.
2. Xử lý hết activation errors.
3. Chuyển project sang `ACTIVE`.
4. Chỉ kết nối một switch đầu tiên.
5. Mở `Overview → Deployment Status`.
6. Kiểm tra Serial Number, Model, Config File và Result.
7. Mở `View Details` để kiểm tra Observed MAC, DHCP IP, Raw Option 60, profile, pool, HTTP status và byte count.

`Completed` chỉ có nghĩa server đã gửi đúng file cho đúng serial và đủ toàn bộ số byte. App không khẳng định Junos đã commit thành công.

### Bước 6 — Mở rộng triển khai

Chỉ cắm thêm thiết bị khi switch test đầu tiên có đúng serial/model/config. Nếu có `Error`, mở Logs và Troubleshooting trước khi tiếp tục.

## Tải config thủ công

- Resolver tự động: `http://192.168.250.1/ztp/config`
- File cụ thể: `http://192.168.250.1/ztp/config/<filename>`

Trong ZTP mode, tải file cụ thể vẫn yêu cầu active DHCP lease và Serial Number hợp lệ:

- File Available: cho tải và gán ownership cho serial.
- File đã thuộc cùng serial: cho tải lại.
- File thuộc serial khác: trả `CONFIG_OWNERSHIP_CONFLICT`.

Manual download không tự chọn pool và không đổi assignment khác.

## Release Assignment

Trong `Deployment Status` hoặc `Config Inventory`, bấm `Release Assignment`:

- Xóa assignment hiện tại của serial.
- Trả file về Available.
- Xóa runtime/download state hiện tại.
- Giữ Device Override, Vendor Profile, logs và audit history.

Nếu Device Override còn tồn tại, lần ZTP sau serial sẽ lại nhận file/pool trong override.

## Logs và báo cáo

Logs mặc định chỉ hiển thị 50 event với Serial, Config, Result và message dễ hiểu. Dùng `Load Older` để xem thêm. Raw DHCP, Option 60, HTTP và audit nằm trong `Troubleshooting`.

`Export Deployment Report` tạo XLSX gồm:

- `Summary`: Expected, Observed, Completed, In Progress, Error, Remaining và tổng hợp theo model.
- `Devices`: Serial Number, Model, Config File, Result, Last Update.

## Reset Workspace

`Reset for Retest` xóa leases, observed clients, assignments, runtime/download records và config ownership; vẫn giữ network/DHCP settings, uploaded configs, Device Overrides, Vendor Profiles, logs và audit history.

`Reset Clean Workspace` xóa thêm uploaded configs, config metadata, Device Overrides, Vendor Profiles và deployment results; vẫn giữ network/DHCP settings, logs và audit history.

Reset sẽ stop DHCP, backup state, làm sạch lease/state bằng atomic write, đưa parser cursor tới EOF, restart/validate DHCP và rollback nếu lỗi.

## Cài và update Ubuntu VM

Không dùng WSL2 NAT làm DHCP production. Dùng Ubuntu VM có NIC bridged trực tiếp vào cổng/VLAN ZTP.

```bash
cd ~/ztp-app
git status --short
git pull --ff-only origin main
sudo env BRIDGE_IF=eth1 ZTP_MODE=ZTP_PROVISIONING bash deploy/install.sh
sudo nginx -t
sudo systemctl restart ztp-app.service nginx isc-dhcp-server
sudo systemctl status ztp-app.service nginx isc-dhcp-server --no-pager
```

Installer sử dụng `/opt/ztp-app/.venv`. Không chạy `sudo pip` hoặc cài dependency vào system Python.

Kiểm tra Option 60 capture:

```bash
grep -n 'set vendor-string' /etc/dhcp/dhcpd.conf
grep -n 'vendor-string' /var/lib/dhcp/dhcpd.leases
sudo dhcpd -t -cf /etc/dhcp/dhcpd.conf
```

Kiểm tra service:

```bash
systemctl is-active ztp-app.service
systemctl is-active nginx
systemctl is-active isc-dhcp-server
```

## Rollback

Trước update lớn, dùng `Export All Data`. Nếu source mới lỗi:

1. Stop `isc-dhcp-server`.
2. Checkout commit production trước đó.
3. Chạy lại `deploy/install.sh`.
4. Chạy `dhcpd -t`.
5. Restart và kiểm tra ba service.

State thật nằm trong `/var/lib/ztp-app` và không bị `git pull` ghi đè.

## Development và test

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
ZTP_DEV=1 python -m unittest -v
```

Version hiện tại: **28.1.0**.
