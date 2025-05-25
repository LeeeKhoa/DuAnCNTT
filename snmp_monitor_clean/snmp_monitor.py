import time
import datetime
import ipaddress
import requests
from pysnmp.hlapi import *
import smtplib
from email.mime.text import MIMEText
from sheets_writer import GoogleSheetsWriter

# CONFIG CẢNH BÁO (bật/tắt, cooldown)
ALERT_CONFIG = {
    "cpu": {"enabled": True, "threshold": 90, "cooldown_sec": 600},     # 10 phút
    "ram": {"enabled": True, "threshold": 90, "cooldown_sec": 600},
    "disk": {"enabled": True, "threshold": 80, "cooldown_sec": 900},
    "uptime": {"enabled": True, "threshold_sec": 600, "cooldown_sec": 1800},
    "network": {"enabled": True, "threshold_percent": 80, "cooldown_sec": 600},
    "offline": {"enabled": True, "cooldown_sec": 60},
    "nohost": {"enabled": True, "cooldown_sec": 600},      # subnet không host nào
}

class AlertManager:
    _alert_state = {}

    TELEGRAM_TOKEN = "7724834226:AAHv2sQoR4_UPrEuxc2qIA7MgSZaYEo7E6U"
    TELEGRAM_CHAT_ID = "1910835997"
    GMAIL_USER = "tancang1704@gmail.com"        
    GMAIL_PASS = "zrrg qbil itfc vlzg"     

    @classmethod
    def send_mail_gmail(cls, subject, body, to_email=None):
        if not cls.GMAIL_USER or not cls.GMAIL_PASS:
            print("[ERROR] Chưa cấu hình GMAIL_USER và GMAIL_PASS!")
            return
        if not to_email:
            to_email = cls.GMAIL_USER
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = cls.GMAIL_USER
        msg['To'] = to_email
        try:
            with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                smtp.starttls()
                smtp.login(cls.GMAIL_USER, cls.GMAIL_PASS)
                smtp.sendmail(cls.GMAIL_USER, [to_email], msg.as_string())
            print("[OK] Đã gửi mail Gmail.")
        except Exception as e:
            print(f"[ERROR] Gửi mail Gmail thất bại: {e}")

    @classmethod
    def send_alert(cls, message, alert_key=None, cooldown_sec=300, value=None, send_gmail=False, gmail_subject=None):
        """
        Chỉ gửi alert nếu hết cooldown hoặc giá trị đã thay đổi đáng kể.
        Nếu send_gmail=True thì gửi Gmail với subject (nếu có).
        """
        now = time.time()
        if alert_key:
            last = cls._alert_state.get(alert_key)
            if last:
                last_time, last_value = last
                if now - last_time < cooldown_sec and (value is None or value == last_value):
                    # Vẫn đang cooldown & không đổi giá trị, bỏ qua
                    return
            cls._alert_state[alert_key] = (now, value)
        # Gửi Telegram
        url = f"https://api.telegram.org/bot{cls.TELEGRAM_TOKEN}/sendMessage"
        payload = {'chat_id': cls.TELEGRAM_CHAT_ID, 'text': message, 'parse_mode': 'Markdown'}
        try:
            requests.post(url, data=payload, timeout=3)
        except Exception as e:
            print(f"[ERROR] Gửi Telegram thất bại: {e}")
        # Gửi Gmail nếu được yêu cầu
        if send_gmail:
            subject = gmail_subject if gmail_subject else "SNMP ALERT"
            cls.send_mail_gmail(subject, message)

    @classmethod
    def clear_alert(cls, alert_key):
        if alert_key in cls._alert_state:
            del cls._alert_state[alert_key]

class SNMPMonitor:
    def __init__(self, ip, community='public'):
        self.ip = ip
        self.community = community
        self.interface_index = self.find_interface(keywords=["Intel", "MediaTek"])
        self.memory_index = self.find_physical_memory()

    def snmp_get(self, oid):
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(self.community, mpModel=0),
                UdpTransportTarget((self.ip, 161), timeout=2.0, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            if errorIndication or errorStatus:
                return None
            for varBind in varBinds:
                return varBind[1]
        except Exception:
            return None

    def is_host_up(self):
        test_oid = '1.3.6.1.2.1.1.1.0'
        result = self.snmp_get(test_oid)
        return result is not None

    def get_all_cpu_loads(self):
        cpu_loads = []
        try:
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(self.community, mpModel=0),
                UdpTransportTarget((self.ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.25.3.3.1.2')),
                lexicographicMode=False
            ):
                if errorIndication or errorStatus:
                    break
                for oid, val in varBinds:
                    try:
                        cpu_loads.append(int(val))
                    except:
                        continue
        except Exception:
            pass
        return cpu_loads

    def find_interface(self, keywords=["Intel", "MediaTek"]):
        try:
            for (_, _, _, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(self.community, mpModel=0),
                UdpTransportTarget((self.ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.2')),
                lexicographicMode=False
            ):
                for oid, val in varBinds:
                    if any(kw.lower() in str(val).lower() for kw in keywords):
                        return int(str(oid).split('.')[-1])
        except Exception:
            pass
        return None

    def find_physical_memory(self):
        try:
            for (_, _, _, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(self.community, mpModel=0),
                UdpTransportTarget((self.ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.25.2.3.1.3')),
                lexicographicMode=False
            ):
                for oid, val in varBinds:
                    if "Physical Memory" in str(val):
                        return int(str(oid).split('.')[-1])
        except Exception:
            pass
        return None

    def get_mac_address(self):
        try:
            for (_, _, _, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(self.community, mpModel=0),
                UdpTransportTarget((self.ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.6')),
                lexicographicMode=False
            ):
                for oid, val in varBinds:
                    if self.interface_index and str(oid).endswith(f".{self.interface_index}"):
                        return ':'.join(['%02x' % b for b in bytes(val)])
        except Exception:
            pass
        return "Unknown"

    def collect_all_metrics(self):
        now = datetime.datetime.now()
        now_str = now.strftime('%Y-%m-%d %H:%M:%S')

        # 1. Host mất kết nối SNMP (OFFLINE)
        if ALERT_CONFIG['offline']['enabled'] and not self.is_host_up():
            msg = (f"❌ *SNMP ALERT*\n"
                   f"Thiết bị `{self.ip}` *mất kết nối* hoặc *tắt nguồn*.\n"
                   f"⏰ Thời điểm: {now_str}")
            AlertManager.send_alert(
                msg,
                alert_key=f"{self.ip}_offline",
                cooldown_sec=ALERT_CONFIG['offline']['cooldown_sec'],
                send_gmail=True,
                gmail_subject=f"Thiết bị mất kết nối SNMP: {self.ip}"
            )
            return {
                'timestamp': now_str,
                'state': 'off',
                'ip_address': self.ip,
                'mac_address': 'Unknown',
                'total_ram_mb': 0,
                'used_ram_mb': 0,
                'link_speed': 0,
                'bytes_in': 0,
                'bytes_out': 0,
                'network_in_mbps': 0,
                'network_out_mbps': 0,
                'cpu_load_percent': 0,
                'uptime_seconds': 0,
                'disk_used_mb': 0,
                'disk_total_mb': 0
            }
        AlertManager.clear_alert(f"{self.ip}_offline")

        # 2. Network, Disk, RAM, CPU, Uptime...
        oid_in = f'1.3.6.1.2.1.2.2.1.10.{self.interface_index}'
        oid_out = f'1.3.6.1.2.1.2.2.1.16.{self.interface_index}'
        oid_speed = f'1.3.6.1.2.1.2.2.1.5.{self.interface_index}'

        in1 = self.snmp_get(oid_in)
        out1 = self.snmp_get(oid_out)
        time.sleep(5)
        in2 = self.snmp_get(oid_in)
        out2 = self.snmp_get(oid_out)

        net_in = (int(in2) - int(in1)) * 8 / 5 / 1_000_000 if in1 and in2 else 0
        net_out = (int(out2) - int(out1)) * 8 / 5 / 1_000_000 if out1 and out2 else 0
        link_speed = self.snmp_get(oid_speed)
        link_speed_mbps = float(round(int(link_speed)/1_000_000, 2)) if link_speed else 0

        oid_total = f'1.3.6.1.2.1.25.2.3.1.5.{self.memory_index}'
        oid_free = f'1.3.6.1.2.1.25.2.3.1.6.{self.memory_index}'
        oid_alloc = f'1.3.6.1.2.1.25.2.3.1.4.{self.memory_index}'

        total_blocks = self.snmp_get(oid_total)
        free_blocks = self.snmp_get(oid_free)
        alloc_unit = self.snmp_get(oid_alloc)

        total_mb = int(total_blocks) * int(alloc_unit) / 1024 / 1024 if total_blocks and alloc_unit else 0
        free_mb = int(free_blocks) * int(alloc_unit) / 1024 / 1024 if free_blocks and alloc_unit else 0
        used_mb = total_mb - free_mb if total_mb and free_mb else 0

        cpu_list = self.get_all_cpu_loads()
        avg_cpu = round(sum(cpu_list) / len(cpu_list), 2) if cpu_list else 0

        uptime = self.snmp_get('1.3.6.1.2.1.1.3.0')
        uptime_sec = float(round(int(uptime)/100, 2)) if uptime else 0

        disk_used = self.snmp_get('1.3.6.1.2.1.25.2.3.1.6.1')
        disk_total = self.snmp_get('1.3.6.1.2.1.25.2.3.1.5.1')

        disk_used_mb = int(disk_used) * 4096 / 1024 / 1024 if disk_used else 0
        disk_total_mb = int(disk_total) * 4096 / 1024 / 1024 if disk_total else 0

        # --- ALERTS ---
        # a) CPU > threshold
        if ALERT_CONFIG['cpu']['enabled'] and avg_cpu > ALERT_CONFIG['cpu']['threshold']:
            msg = (f"🔥 *CẢNH BÁO CPU*\n"
                   f"Thiết bị `{self.ip}` vượt ngưỡng CPU: *{avg_cpu}%*\n"
                   f"Ngưỡng: {ALERT_CONFIG['cpu']['threshold']}%\n"
                   f"⏰ {now_str}")
            AlertManager.send_alert(msg, alert_key=f"{self.ip}_cpu_high", cooldown_sec=ALERT_CONFIG['cpu']['cooldown_sec'], value=avg_cpu)
        else:
            AlertManager.clear_alert(f"{self.ip}_cpu_high")

        # b) RAM > threshold
        ram_percent = (used_mb / total_mb * 100) if total_mb else 0
        if ALERT_CONFIG['ram']['enabled'] and ram_percent > ALERT_CONFIG['ram']['threshold']:
            msg = (f"📊 *CẢNH BÁO RAM*\n"
                   f"Thiết bị `{self.ip}` vượt ngưỡng RAM: *{ram_percent:.1f}%*\n"
                   f"Đang dùng: {used_mb:.1f} MB / {total_mb:.1f} MB\n"
                   f"Ngưỡng: {ALERT_CONFIG['ram']['threshold']}%\n"
                   f"⏰ {now_str}")
            AlertManager.send_alert(msg, alert_key=f"{self.ip}_ram_high", cooldown_sec=ALERT_CONFIG['ram']['cooldown_sec'], value=ram_percent)
        else:
            AlertManager.clear_alert(f"{self.ip}_ram_high")

        # c) Disk > threshold
        if ALERT_CONFIG['disk']['enabled'] and disk_total_mb and (disk_used_mb / disk_total_mb * 100) > ALERT_CONFIG['disk']['threshold']:
            usage_percent = round(100 * disk_used_mb / disk_total_mb, 2)
            msg = (f"💾 *CẢNH BÁO DISK*\n"
                   f"Thiết bị `{self.ip}` gần đầy ổ đĩa!\n"
                   f"Disk used: {disk_used_mb:.1f} MB / {disk_total_mb:.1f} MB ({usage_percent}%)\n"
                   f"Ngưỡng: {ALERT_CONFIG['disk']['threshold']}%\n"
                   f"⏰ {now_str}")
            AlertManager.send_alert(msg, alert_key=f"{self.ip}_disk_high", cooldown_sec=ALERT_CONFIG['disk']['cooldown_sec'], value=usage_percent)
        else:
            AlertManager.clear_alert(f"{self.ip}_disk_high")

        # d) Uptime < threshold (máy vừa reset)
        if ALERT_CONFIG['uptime']['enabled'] and uptime_sec < ALERT_CONFIG['uptime']['threshold_sec'] and uptime_sec > 0:
            msg = (f"🔄 *CẢNH BÁO UPTIME*\n"
                   f"Thiết bị `{self.ip}` vừa khởi động lại! (uptime: {uptime_sec} giây)\n"
                   f"Ngưỡng: < {ALERT_CONFIG['uptime']['threshold_sec']} giây\n"
                   f"⏰ {now_str}")
            AlertManager.send_alert(msg, alert_key=f"{self.ip}_uptime_low", cooldown_sec=ALERT_CONFIG['uptime']['cooldown_sec'], value=uptime_sec)
        else:
            AlertManager.clear_alert(f"{self.ip}_uptime_low")

        # e) Network spike/drop (> threshold % link speed)
        net_threshold = ALERT_CONFIG['network']['threshold_percent'] / 100.0 * link_speed_mbps
        if ALERT_CONFIG['network']['enabled'] and link_speed_mbps > 0:
            net_spike = (net_in > net_threshold) or (net_out > net_threshold)
            if net_spike:
                msg = (f"🌐 *CẢNH BÁO TRAFFIC*\n"
                       f"Thiết bị `{self.ip}` có traffic mạng cao bất thường!\n"
                       f"In: {net_in:.2f} Mbps | Out: {net_out:.2f} Mbps\n"
                       f"Ngưỡng: {ALERT_CONFIG['network']['threshold_percent']}% của {link_speed_mbps:.2f} Mbps\n"
                       f"⏰ {now_str}")
                AlertManager.send_alert(msg, alert_key=f"{self.ip}_net_spike", cooldown_sec=ALERT_CONFIG['network']['cooldown_sec'], value=(net_in, net_out))
            else:
                AlertManager.clear_alert(f"{self.ip}_net_spike")

        # --- Return metrics log for sheets ---
        return {
            'timestamp': now_str,
            'state': 'on',
            'ip_address': self.ip,
            'mac_address': self.get_mac_address(),
            'total_ram_mb': float(round(total_mb, 2)),
            'used_ram_mb': float(round(used_mb, 2)),
            'link_speed': link_speed_mbps,
            'bytes_in': int(in2) if in2 else 0,
            'bytes_out': int(out2) if out2 else 0,
            'network_in_mbps': float(round(net_in, 2)),
            'network_out_mbps': float(round(net_out, 2)),
            'cpu_load_percent': float(avg_cpu),
            'uptime_seconds': uptime_sec,
            'disk_used_mb': float(round(disk_used_mb, 2)),
            'disk_total_mb': float(round(disk_total_mb, 2))
        }

    def export_to_gsheets(self, data, creds_file, sheet_name, tab_name="SNMPData"):
        writer = GoogleSheetsWriter(creds_file, sheet_name)
        writer.write_logs(tab_name, [data])
        

# === Cảnh báo nếu subnet không phát hiện host SNMP nào ===
def discover_snmp_hosts(subnet="192.168.1.0/24", community="public", timeout=0.5):
    reachable_hosts = []
    for ip in ipaddress.IPv4Network(subnet):
        ip_str = str(ip)
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=0),
                UdpTransportTarget((ip_str, 161), timeout=timeout, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))
            )
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            if not errorIndication and not errorStatus:
                reachable_hosts.append(ip_str)
        except Exception:
            continue

    alert_key = f"subnet_{subnet}_nohost"
    if ALERT_CONFIG['nohost']['enabled']:
        if not reachable_hosts:
            msg = (f"🚨 *SNMP MONITOR ALERT*\n"
                   f"KHÔNG PHÁT HIỆN ĐƯỢC HOST SNMP NÀO TRÊN DẢI `{subnet}`!\n"
                   f"Toàn bộ thiết bị SNMP đều offline hoặc không phản hồi.\n"
                   f"⏰ {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            AlertManager.send_alert(
                msg,
                alert_key=alert_key,
                cooldown_sec=ALERT_CONFIG['nohost']['cooldown_sec'],
                send_gmail=True,
                gmail_subject=f"KHÔNG PHÁT HIỆN HOST SNMP ({subnet})"
            )
        else:
            AlertManager.clear_alert(alert_key)
    return reachable_hosts

