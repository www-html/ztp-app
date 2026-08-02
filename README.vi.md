# ztp-app — Hướng dẫn tiếng Việt

`ztp-app` là giao diện Flask để điều khiển **Juniper ZTP** trên một mạng L2 cô lập. Công cụ không SSH để đẩy cấu hình trực tiếp; thiết bị sẽ nhận DHCP, lấy đường dẫn cấu hình qua DHCP Option 43/66, tải file từ Nginx qua HTTP rồi tự nạp cấu hình.

## Luồng hoạt động

1. Thiết bị khởi động trong mạng ZTP và gửi DHCP Discover.
2. `isc-dhcp-server` cấp địa chỉ IP trong pool và quảng bá IP máy chủ qua Option 66.
3. DHCP Option 43 chỉ ra `configs/<file>` và phương thức `http`.
4. Thiết bị tải `http://<server-ip>/configs/<file>` từ Nginx.
5. Junos nạp cấu hình, commit và khởi động lại theo nội dung cấu hình.
6. Trang **Bindings & Health** kiểm tra lease, ping, TCP/22, SSH và hostname.

## Điều kiện mạng bắt buộc

Máy chạy ZTP phải có NIC hoặc VM NIC **bridged vào cùng L2/VLAN** với thiết bị. WSL2 mặc định dùng NAT, vì vậy không nên dùng WSL laptop làm DHCP server cho thiết bị thật. Dùng Ubuntu VM/appliance có NIC riêng nối vào mạng ZTP cô lập.

Không chạy DHCP server này trên mạng production. Pool mặc định `19.96.0.0/16` chỉ dành cho lab cô lập; hãy đổi sang subnet RFC1918 phù hợp với thiết kế thực tế.

## Chạy development trong WSL (không cấp DHCP thật)

```bash
cd ~/projects/ztp-app
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
ZTP_DEV=1 \
ZTP_WEBROOT=./_webroot \
ZTP_DHCPD=./_dhcpd.conf \
ZTP_PORT=8080 \
python app.py
```

Mở `http://localhost:8080`. `ZTP_DEV=1` bỏ qua admin login và không restart service hệ thống; chỉ dùng để xem giao diện, upload file, preview DHCP và kiểm thử dữ liệu.

README tiếng Anh có đường dẫn cũ; với bản clone hiện tại dùng `~/projects/ztp-app` như trên.

## Cài production trên Ubuntu VM

Trong VM, tại thư mục repo:

```bash
sudo BRIDGE_IF=ens37 deploy/install.sh
```

Thay `ens37` bằng NIC thực sự nối vào ZTP VLAN. Script cài Nginx, `isc-dhcp-server`, Python virtual environment và systemd service `ztp-app.service`; service chạy Waitress trên port `8080`.

Sau khi cài:

1. Mở `http://<server-ip>:8080`.
2. Đăng nhập lần đầu bằng `admin/admin` nếu chưa đặt biến môi trường khác.
3. Đổi admin password ngay tại **Dashboard → Admin Login**.
4. Đặt DHCP pool đúng với VLAN ZTP.
5. Kiểm tra interface DHCP trong `/etc/default/isc-dhcp-server`.

Không chạy script production trong WSL laptop; script cần quyền root, systemd, Nginx, DHCP và NIC bridged.

## Chuẩn bị file cấu hình

Dashboard chỉ nhận file `.txt` hoặc `.conf`. Mỗi file được kiểm tra sơ bộ:

- Có `root-authentication`; nếu thiếu, commit ZTP sẽ thất bại.
- Không bật `chassis auto-image-upgrade` nếu không có chủ ý giữ thiết bị trong vòng ZTP.
- URL cấu hình phải ngắn hơn 256 ký tự.

Các kiểm tra này không thay thế việc kiểm tra cú pháp Junos trên thiết bị. Luôn xác nhận cấu hình theo model, Junos version và kiểu nạp (`load override`, `load merge` hoặc format tương ứng).

## Chọn cách mapping thiết bị

### By Serial

Nhập serial chính xác như phần cuối của DHCP Option 60, ví dụ:

```text
Juniper-ex2300-48p-ZG1234
```

Serial cần nhập là `ZG1234`. App sinh điều kiện regex kết thúc bằng serial (`<serial>$`). Thiết bị nhận IP động từ DHCP range; không cần nhập DHCP IP.

Xác nhận Option 60 thật bằng DHCP log hoặc:

```bash
sudo tcpdump -ni <interface> port 67 -v
```

### By MAC

Nhập MAC chassis/management mà thiết bị gửi trong DHCP, cùng một DHCP IP cố định. App sinh `host { hardware ethernet ...; fixed-address ...; }`; cách này có độ ưu tiên cao nhất.

### Generic Profile

Dùng khi nhiều thiết bị cùng vendor-class dùng chung một file. `vendor_class` phải khớp chuỗi Option 60 thật, ví dụ `Juniper-ex2300`. Thiết bị có thể không cần file riêng trong phần mapping.

## Trình tự thao tác trên Dashboard

1. **DHCP Pool & SSH Credentials**: đặt server IP, subnet, netmask và range.
2. **Config Files**: upload `.conf`/`.txt`, chờ cột **Checks = OK**.
3. Thêm **Specific Device Mapping** hoặc **Generic Profile**.
4. Chọn file cấu hình nếu thiết bị cần file riêng.
5. Nhấn **Save & Deploy** hoặc lưu profile.
6. Mở **Preview dhcpd.conf** để review rule trước khi cho thiết bị boot.
7. Xác nhận `dhcpd -t` pass; app chỉ restart DHCP/Nginx sau khi kiểm tra này thành công.

## Xác minh thiết bị đã nhận đúng cấu hình

Trong **Bindings & Health → Run health check**:

- **DHCP lease**: thiết bị đã nhận lease.
- **Config fetch status 200** trong **Logs**: thiết bị đã tải file từ Nginx.
- **Ping**: thiết bị reachable ở IP sau ZTP.
- **SSH**: TCP/22 mở.
- **VERIFIED**: app đăng nhập SSH và hostname thực tế khớp hostname đã khai báo.

`mgmt_ip` được ưu tiên cho health check sau ZTP. Nếu bỏ trống, app dùng DHCP IP. Máy chủ phải có route L3 tới các management subnet đó.

## Rollback an toàn

Trước khi deploy production, sao lưu ít nhất:

```bash
sudo cp -a /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.before-ztp
sudo cp -a /opt/ztp-app /opt/ztp-app.before-ztp
```

Nếu cần dừng dịch vụ:

```bash
sudo systemctl stop ztp-app.service
sudo systemctl stop isc-dhcp-server
sudo systemctl stop nginx
```

Không dùng `git reset --hard` hoặc `git clean -fdx` để rollback dữ liệu runtime. `devices.json`, `generic_profiles.json`, `settings.json`, `creds.json` và các file upload là dữ liệu vận hành, không nằm trong Git.

## Lưu ý bảo mật

- Đổi ngay `admin/admin` trước khi mở GUI ngoài lab.
- GUI dùng HTTP Basic Auth; không expose qua mạng không tin cậy nếu chưa có TLS hoặc ACL.
- `/configs/*` không yêu cầu login vì thiết bị Junos cần tải file trong ZTP.
- `creds.json` chứa SSH password, chỉ bảo vệ bằng permission `0600`; bảo vệ filesystem và backup.
- App hiện chấp nhận SSH host key mới tự động cho health check; không xem đây là kiểm tra danh tính máy chủ đầy đủ.
- Giới hạn máy truy cập port `8080`, DHCP và Nginx vào mạng quản trị/ZTP cần thiết.

## Làm việc với ChatGPT/Codex

Có thể dùng ChatGPT/Codex để đọc repo, kiểm tra cấu hình, tạo mapping, review `dhcpd.conf`, phân tích log và hướng dẫn rollback. Trước mọi thay đổi nên yêu cầu:

```text
Kiểm tra git status trước. Chỉ thay đổi file trong phạm vi đã nêu.
Preview và validate dhcpd.conf trước khi deploy.
Không restart DHCP/Nginx hoặc tác động thiết bị nếu chưa được tôi xác nhận.
Sau thay đổi phải báo diff, kết quả verify và rollback.
```

ChatGPT không tự thay thế được DHCP server, NIC bridged hoặc quyền truy cập vật lý tới thiết bị; các thành phần đó phải tồn tại ở VM/appliance trong mạng ZTP.

