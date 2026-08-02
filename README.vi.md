# ztp-app — Hướng dẫn tiếng Việt

Giao diện hiện tại: **v26.08.05 — UI v2**. Dashboard dùng phong cách operations console với các khu vực **Overview**, **Network**, **Devices**, **Configs**, **Validation** và **Administration** để tách thao tác thường dùng khỏi cấu hình nâng cao. **Health** và **Logs** dùng cùng layout; thông tin raw/ít dùng được collapse.

## Quick Start trên giao diện

1. Mở **Network** và bấm **Refresh interfaces** sau khi cắm/cấu hình card mạng.
2. Chọn Internet interface và ZTP interface; dùng **Suggest pool** để tính DHCP pool. Nhập **Mask length** dạng CIDR, ví dụ `24`, không cần nhập netmask dotted.
3. Xác nhận pool, bấm **Save draft / Apply DHCP** và kiểm tra readiness.
4. Upload config trong **Configs**, thêm mapping trong **Devices**.
5. Mở **Health** để chạy health check; mở **Logs** để kiểm tra lease và HTTP `200`.

Nút **Restart ZTP service** chỉ restart `ztp-app.service`, không restart DHCP hoặc Nginx. Nút này yêu cầu service chạy dưới systemd/root; `DEV_MODE` luôn bỏ qua restart.

## Runbook ZTP đầy đủ — làm theo đúng thứ tự

### Bước 1 — Chuẩn bị topology

1. Dùng Ubuntu VM/appliance có NIC **bridged** vào đúng VLAN ZTP. Không dùng WSL2 NAT làm DHCP server cho switch thật.
2. NIC Internet dùng để cập nhật package và truy cập GUI; NIC ZTP chỉ nối vào switch/thiết bị cần provision.
3. Tắt hoặc cô lập mọi DHCP server khác trên VLAN ZTP.
4. Ghi lại cổng switch, model thiết bị, IP quản trị dự kiến và file config tương ứng.
5. Chưa cho thiết bị boot nếu Dashboard còn báo **Blocked**.

### Bước 2 — Cài service trên Ubuntu VM

```bash
cd ~/projects/ztp-app
sudo BRIDGE_IF=<ztp-interface> deploy/install.sh
```

Thay `<ztp-interface>` bằng tên NIC thật, ví dụ `ens37` hoặc `eth1`. Kiểm tra:

```bash
systemctl is-active ztp-app.service
systemctl is-active isc-dhcp-server
systemctl is-active nginx
ip -br link
ip -br -4 addr
```

Nếu service không chạy, dừng ở đây và xem `journalctl -u ztp-app.service -n 100 --no-pager`.

### Bước 3 — Đăng nhập và khóa tài khoản

1. Mở `http://<server-ip>:8080`.
2. Đăng nhập lần đầu bằng `admin/admin` nếu chưa đổi thông tin.
3. Vào **Administration → Admin login**, đặt username/password mới.
4. Chỉ cho phép máy quản trị truy cập port `8080`.

### Bước 4 — Chuẩn bị interface và DHCP pool

1. Vào **Network**, bấm **Refresh interfaces**.
2. Chọn **Internet interface** và **ZTP interface (DHCP)**.
3. Bảo đảm ZTP interface có `UP`, có IPv4 và IPv4 đó là **Server IP**.
4. Bấm **Suggest pool**.
5. Kiểm tra `Server IP`, `Subnet`, `Mask length`, `Range low`, `Range high`.
6. Bật checkbox xác nhận pool không chồng lấn DHCP server/gateway/IP tĩnh khác.
7. Bấm **Preview DHCP**, sau đó **Save draft / Apply DHCP**.
8. Chỉ tiếp tục khi **Network readiness = Passed**, không còn lỗi `LOWER_UP`, `no IPv4` hoặc `dhcpd -t FAILED`.

### Bước 5 — Upload và kiểm tra config

1. Vào **Configs → Upload config**.
2. Chọn file `.conf` hoặc `.txt` đúng model/Junos version.
3. Chỉ dùng file có trạng thái **OK**.
4. Tự kiểm tra thêm trên lab/test device; kiểm tra của app không thay thế `commit check` trên thiết bị.

### Bước 6 — Đọc DHCP Option 60 của thiết bị

Trước khi tạo Serial hoặc Generic Profile, bắt một DHCP request thật:

```bash
sudo tcpdump -ni <ztp-interface> -vvv -s0 'port 67 or port 68'
```

Ghi lại chính xác chuỗi **Option 60 / vendor-class-identifier**. Không tự đoán model string.

### Bước 7 — Tạo mapping

Trong **Devices**:

- Dùng **Generic Profile** nếu nhiều thiết bị có cùng Option 60 pattern và dùng cùng config.
- Dùng **Specific Device → Serial** nếu một thiết bị cần config riêng.
- Dùng **Specific Device → MAC** nếu thiết bị không có Serial ổn định; khi có config riêng phải nhập DHCP IP.
- Specific rule được ưu tiên trước Generic rule.
- Với Generic Profile, chọn `Contains (literal)` cho chuỗi đơn giản hoặc `Regex` khi thật sự cần. Ví dụ `qfx5120-48YM?$` match suffix `qfx5120-48Y` và `qfx5120-48YM`.
- Bấm **Preview DHCP** và kiểm tra thứ tự rule trước khi cho thiết bị boot.

### Bước 8 — Test một thiết bị

1. Chỉ cắm một thiết bị vào VLAN ZTP.
2. Mở **Logs** và theo dõi DHCP lease/config fetch.
3. Reboot hoặc khởi động ZTP trên thiết bị.
4. Xác nhận lease DHCP được cấp đúng pool.
5. Xác nhận HTTP config fetch trả `200`.
6. Vào **Health → Run health check**; kiểm tra Ping, SSH và `VERIFIED` hostname.
7. Nếu sai config hoặc sai mapping, dừng batch và sửa rule trước.

### Bước 9 — Triển khai theo batch

Chỉ sau khi một thiết bị đã pass toàn bộ bước trên, mới cắm thêm các thiết bị cùng nhóm. Mỗi model/config khác nhau phải có ít nhất một thiết bị test riêng.

### Bước 10 — Rollback

Nếu cần dừng ngay:

```bash
sudo systemctl stop isc-dhcp-server
sudo systemctl stop ztp-app.service
```

Sau đó xóa mapping/profile sai trên UI, khôi phục file config/DHCP đã backup, chạy `dhcpd -t`, rồi mới start lại service. Không dùng `git reset --hard` để rollback dữ liệu runtime.

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

## Chọn interface Internet và ZTP trên Dashboard

Dashboard có hai lựa chọn:

- **Internet interface**: card đi ra Internet, dùng để kiểm tra route/package. UI chỉ lưu và kiểm tra, không tự đổi default route của Linux/Windows.
- **ZTP interface (DHCP)**: card nối vào switch/VLAN ZTP. App dùng lựa chọn này để ghi `INTERFACESv4` trong `/etc/default/isc-dhcp-server`.

ZTP interface phải có link vật lý và phải có IPv4 đúng bằng `Server IP`. Nếu interface chưa có IP, UI vẫn cho lưu lựa chọn để chuẩn bị trước, nhưng production DHCP restart sẽ bị chặn và hiển thị lỗi. DHCP có thể nhận broadcast ở interface không có IP trong một số hệ thống, nhưng không thể quảng bá Option 66 tới địa chỉ server hợp lệ hoặc phục vụ HTTP ổn định; vì vậy không xem trạng thái không có IP là ready.

Nút **Suggest pool** đọc IPv4/CIDR của interface và đề xuất `Server IP`, `Subnet`, `Mask length` và DHCP range. Đây chỉ là gợi ý; phải kiểm tra lại pool, tránh gateway/IP tĩnh/DHCP server khác và tick xác nhận trước khi lưu. Backend vẫn lưu netmask dotted bên trong để tương thích `dhcpd.conf` và dữ liệu cũ. Backend cũng kiểm tra subnet, range, broadcast/network address và không cho range chứa `Server IP`.

UI không tự cấu hình IP, bridge, Windows Firewall hoặc default route. Các phần đó phải được chuẩn bị ở OS/WSL trước. Khi chuyển sang máy khác, UI sẽ đọc lại danh sách interface và trạng thái hiện tại thay vì giả định tên `eth1`.

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

Trên UI, phần **Devices** tách thành hai cách:

- **Specific Device**: một thiết bị cụ thể; dùng khi cần match chính xác theo Serial/MAC, cấp DHCP IP cố định hoặc dùng file cấu hình riêng.
- **Generic Profile**: một nhóm thiết bị; match theo vendor class và dùng chung một file cấu hình.

Thứ tự match là Specific MAC/Serial trước, sau đó mới fallback sang Generic Profile. Trong Specific Device, `DHCP IP` chỉ có tác dụng với By-MAC, `Management IP` là địa chỉ dùng cho health check sau ZTP, còn để trống `Specific config file` sẽ dùng Generic Profile.

### Quy tắc Required / Optional và kiểu match

- `Required`: `ZTP interface`, các trường DHCP pool (`Server IP`, `Subnet`, `Mask length`, `Range low`, `Range high`), `Hostname`, cùng định danh đang chọn (`Serial number` hoặc `MAC address`). Generic Profile bắt buộc có `Vendor class` và `Config file`.
- `Optional`: `Internet interface`, `Device type` (chỉ là nhãn), `Management IP`, `Specific config file`, và SSH override. `DHCP IP` thường là optional, nhưng bắt buộc khi chọn **By-MAC** và gán `Specific config file`.
- `Exact match`: MAC là địa chỉ hardware khớp chính xác. `Hostname` phải khớp chính xác với hostname app đọc được trong health check. Các giá trị IP/pool cũng phải là IPv4 hợp lệ và nằm đúng subnet.
- `Pattern match`: Serial được dùng như phần cuối của Option 60 (`serial$`), vì vậy nhập đúng suffix alphanumeric; Serial chưa hỗ trợ regex tự do. Generic Profile có hai chế độ: `Contains (literal)` để tìm chuỗi an toàn, hoặc `Regex` để nhập biểu thức như `qfx5120-48YM?$`. Regex tối đa 160 ký tự, không được chứa dấu quote hoặc newline và phải compile hợp lệ.

Nói ngắn gọn: UI có chữ **Exact** thì phải copy đúng giá trị thiết bị; `Contains (literal)` không dùng wildcard; `Regex` cho phép các toán tử regex nhưng phải test với Option 60 thật trước production.

App cũng rà soát trước khi lưu/import: duplicate MAC/Serial, Serial suffix bị chồng lấn, Vendor class bị overlap, MAC/IP sai định dạng đều bị chặn. Thứ tự DHCP rule vẫn có ý nghĩa, vì vậy không nên cố tình tạo hai pattern có thể cùng match. Việc kiểm tra này không thay thế bước bắt DHCP Option 60 thực tế; hãy capture Option 60 của từng model trước khi bật rule Serial hoặc Generic.

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

1. **DHCP Pool & SSH Credentials**: chọn ZTP interface, bấm **Suggest pool from selected ZTP interface**, kiểm tra các giá trị và xác nhận pool không chồng lấn mạng/DHCP khác.
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
