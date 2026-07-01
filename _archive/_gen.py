import os
os.environ.setdefault("ZTP_DEV", "1")
os.environ.setdefault("ZTP_WEBROOT", "/tmp/wr")
os.environ.setdefault("ZTP_DEVICES", "/tmp/dev.json")
os.environ.setdefault("ZTP_DHCPD", "/tmp/out.conf")
import app as a
a.write_devices([
    {"model": "EX2300", "serial_number": "ZG12345", "mac_address": "",
     "hostname": "ex-a", "ip_address": "192.168.1.120", "specific_config_file": "ex-a.conf"},
    {"model": "EX2300", "serial_number": "ZG99999", "mac_address": "",
     "hostname": "ex-b", "ip_address": "192.168.1.121", "specific_config_file": "ex-b.conf"},
    {"model": "SRX320", "serial_number": "", "mac_address": "2c:6b:f5:01:02:03",
     "hostname": "srx-1", "ip_address": "192.168.1.122", "specific_config_file": "srx.conf"},
])
with a.app.app_context():
    open("/tmp/out.conf", "w").write(a.generate_dhcpd())
print("generated /tmp/out.conf")
