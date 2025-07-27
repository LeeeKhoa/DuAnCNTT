# snmp_monitor.py - Hệ thống giám sát SNMP với cấu hình tách riêng
import time
import datetime
import ipaddress
import requests
from pysnmp.hlapi import *
import smtplib
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.text import MIMEText
from sheets_writer import GoogleSheetsWriter
from config import Config  # Import cấu hình

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Sử dụng cấu hình từ Config class
ALERT_CONFIG = Config.ALERT_CONFIG

def load_trusted_macs(filepath="Trust_Devices.txt"):
    """Tải danh sách MAC address tin cậy với xử lý lỗi"""
    try:
        with open(filepath, "r", encoding='utf-8') as f:
            macs = set()
            for line in f:
                mac = line.strip().lower()
                if mac and ':' in mac:  # Kiểm tra định dạng MAC cơ bản
                    macs.add(mac)
            print(f"[OK] Đã tải {len(macs)} địa chỉ MAC tin cậy")
            return macs
    except FileNotFoundError:
        print(f"[CẢNH BÁO] File {filepath} không tồn tại. Đang tạo file mới...")
        try:
            with open(filepath, "w", encoding='utf-8') as f:
                f.write("# Danh sách địa chỉ MAC tin cậy (mỗi dòng một địa chỉ)\n")
                f.write("# Ví dụ: aa:bb:cc:dd:ee:ff\n")
            return set()
        except Exception as e:
            print(f"[LỖI] Không thể tạo file {filepath}: {e}")
            return set()
    except Exception as e:
        print(f"[CẢNH BÁO] Không đọc được file MAC tin cậy: {e}")
        return set()

TRUSTED_MACS = load_trusted_macs()

class AlertManager:
    """Quản lý cảnh báo sử dụng cấu hình từ Config"""
    _alert_state = {}
    
    # Sử dụng cấu hình từ Config class
    TELEGRAM_TOKEN = Config.TELEGRAM_TOKEN
    TELEGRAM_CHAT_ID = Config.TELEGRAM_CHAT_ID
    GMAIL_USER = Config.GMAIL_USER
    GMAIL_PASS = Config.GMAIL_PASSWORD
    TELEGRAM_PROXY = Config.TELEGRAM_PROXY

    @classmethod
    def send_mail_gmail(cls, subject, body, to_email=None):
        """Gửi thông báo qua Gmail"""
        if not cls.GMAIL_USER or not cls.GMAIL_PASS:
            print("[LỖI] Chưa cấu hình thông tin Gmail!")
            return False
        
        if not to_email:
            to_email = cls.GMAIL_USER

        try:
            msg = MIMEText(body, 'plain', 'utf-8')
            msg['Subject'] = subject
            msg['From'] = cls.GMAIL_USER
            msg['To'] = to_email

            with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                smtp.starttls()
                smtp.login(cls.GMAIL_USER, cls.GMAIL_PASS)
                smtp.sendmail(cls.GMAIL_USER, [to_email], msg.as_string())

            print("[OK] Đã gửi email Gmail thành công")
            return True

        except smtplib.SMTPAuthenticationError:
            print("[LỖI] Xác thực Gmail thất bại. Kiểm tra tên đăng nhập/mật khẩu")
            return False
        except smtplib.SMTPException as e:
            print(f"[LỖI] Lỗi SMTP: {e}")
            return False
        except Exception as e:
            print(f"[LỖI] Gửi Gmail thất bại: {e}")
            return False

    @classmethod
    def send_alert(cls, message, alert_key=None, cooldown_sec=300, value=None, send_gmail=False, gmail_subject=None):
        """Gửi cảnh báo với quản lý thời gian chờ"""
        now = time.time()
        
        # Kiểm tra thời gian chờ
        if alert_key:
            last = cls._alert_state.get(alert_key)
            if last:
                last_time, last_value = last
                if now - last_time < cooldown_sec and (value is None or value == last_value):
                    return False
            cls._alert_state[alert_key] = (now, value)

        # Gửi Telegram
        telegram_success = cls._send_telegram(message)
        
        # Gửi Gmail nếu được yêu cầu
        gmail_success = True
        if send_gmail:
            subject = gmail_subject if gmail_subject else "Cảnh báo SNMP"
            gmail_success = cls.send_mail_gmail(subject, message)
        
        return telegram_success or gmail_success

    @classmethod
    def _send_telegram(cls, message):
        """Gửi thông báo qua Telegram"""
        url = f"https://api.telegram.org/bot{cls.TELEGRAM_TOKEN}/sendMessage"
        payload = {
            'chat_id': cls.TELEGRAM_CHAT_ID,
            'text': message,
            'parse_mode': 'Markdown'
        }
        
        try:
            response = requests.post(
                url,
                data=payload,
                timeout=10,
                proxies=cls.TELEGRAM_PROXY if cls.TELEGRAM_PROXY.get('http') else None,
                verify=False
            )
            
            if response.status_code == 200:
                print("[OK] Đã gửi cảnh báo Telegram thành công")
                return True
            else:
                print(f"[LỖI] Lỗi API Telegram: {response.status_code}")
                return False
                
        except requests.exceptions.ProxyError:
            print("[LỖI] Kết nối proxy thất bại")
            return False
        except requests.exceptions.Timeout:
            print("[LỖI] Hết thời gian chờ Telegram")
            return False
        except Exception as e:
            print(f"[LỖI] Gửi Telegram thất bại: {e}")
            return False

    @classmethod
    def clear_alert(cls, alert_key):
        """Xóa trạng thái cảnh báo"""
        if alert_key in cls._alert_state:
            del cls._alert_state[alert_key]

class SNMPMonitor:
    def __init__(self, ip, community='public'):
        """Khởi tạo SNMP Monitor với hệ thống cache"""
        self.ip = ip
        self.community = community
        self._cache = {}
        self._cache_timeout = 30
        
        # Tìm kiếm các chỉ số quan trọng trước
        print(f"[THÔNG TIN] Đang khởi tạo giám sát SNMP cho {ip}...")
        self.interface_index = self.find_interface(keywords=["Intel", "MediaTek", "Ethernet", "Wi-Fi"])
        self.memory_index = self.find_physical_memory()
        
        if not self.interface_index:
            print(f"[CẢNH BÁO] Không tìm thấy giao diện mạng phù hợp cho {ip}")
        if not self.memory_index:
            print(f"[CẢNH BÁO] Không tìm thấy chỉ số bộ nhớ vật lý cho {ip}")

    def snmp_get(self, oid, timeout=2.0, retries=1):
        """Lấy dữ liệu SNMP được tối ưu với xử lý lỗi toàn diện"""
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(self.community, mpModel=0),
                UdpTransportTarget((self.ip, 161), timeout=timeout, retries=retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            if errorIndication:
                return None
            if errorStatus:
                return None
                
            for varBind in varBinds:
                return varBind[1]
                
        except Exception:
            return None

    def snmp_get_cached(self, oid, cache_key=None):
        """Lấy dữ liệu SNMP với cơ chế cache"""
        if cache_key is None:
            cache_key = oid
            
        now = time.time()
        
        # Kiểm tra cache
        if cache_key in self._cache:
            cached_time, cached_value = self._cache[cache_key]
            if now - cached_time < self._cache_timeout:
                return cached_value
        
        # Thực hiện truy vấn SNMP
        result = self.snmp_get(oid)
        
        # Lưu vào cache
        if result is not None:
            self._cache[cache_key] = (now, result)
            
        return result

    def is_host_up(self):
        """Kiểm tra thiết bị có trực tuyến qua SNMP không"""
        test_oid = '1.3.6.1.2.1.1.1.0'  # sysDescr
        result = self.snmp_get(test_oid, timeout=3.0)
        return result is not None

    def get_all_cpu_loads(self):
        """Lấy tất cả tỷ lệ tải CPU"""
        cpu_loads = []
        try:
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(self.community, mpModel=0),
                UdpTransportTarget((self.ip, 161), timeout=5.0),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.25.3.3.1.2')),
                lexicographicMode=False
            ):
                if errorIndication or errorStatus:
                    break
                    
                for oid, val in varBinds:
                    try:
                        cpu_load = int(val)
                        if 0 <= cpu_load <= 100:  # Kiểm tra tỷ lệ CPU hợp lệ
                            cpu_loads.append(cpu_load)
                    except (ValueError, TypeError):
                        continue
                        
        except Exception:
            pass
            
        return cpu_loads

    def find_interface(self, keywords=["Intel", "MediaTek", "Ethernet", "Wi-Fi"]):
        """Tìm card mạng bằng key word"""
        try:
            for (_, _, _, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(self.community, mpModel=0),
                UdpTransportTarget((self.ip, 161), timeout=5.0),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.2')),
                lexicographicMode=False
            ):
                for oid, val in varBinds:
                    interface_desc = str(val).lower()
                    if any(kw.lower() in interface_desc for kw in keywords):
                        index = int(str(oid).split('.')[-1])
                        print(f"[OK] Tìm thấy giao diện: {val} (chỉ số: {index})")
                        return index
        except Exception as e:
            print(f"[LỖI] Tìm giao diện thất bại: {e}")
            
        return None

    def find_physical_memory(self):
        """Tìm chỉ số RAM"""
        try:
            for (_, _, _, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(self.community, mpModel=0),
                UdpTransportTarget((self.ip, 161), timeout=5.0),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.25.2.3.1.3')),
                lexicographicMode=False
            ):
                for oid, val in varBinds:
                    storage_desc = str(val).lower()
                    if "physical memory" in storage_desc or "ram" in storage_desc:
                        index = int(str(oid).split('.')[-1])
                        print(f"[OK] Tìm thấy bộ nhớ: {val} (chỉ số: {index})")
                        return index
        except Exception as e:
            print(f"[LỖI] Tìm bộ nhớ thất bại: {e}")
            
        return None

    def get_mac_address(self):
        """Lấy địa chỉ MAC với chuyển đổi kiểu dữ liệu phù hợp"""
        try:
            if not self.interface_index:
                return "Unknown"
                
            oid = f'1.3.6.1.2.1.2.2.1.6.{self.interface_index}'
            result = self.snmp_get(oid)
            
            if result is None:
                return "Unknown"
            
            # Xử lý các kiểu biểu diễn địa chỉ MAC khác nhau
            try:
                # Thử chuyển đổi OctetString thành bytes
                mac_bytes = bytes(result)
                if len(mac_bytes) == 6:
                    return ':'.join(['%02x' % b for b in mac_bytes])
                else:
                    return str(result)
            except:
                # Fallback thành biểu diễn chuỗi
                mac_str = str(result)
                if len(mac_str) == 17 and ':' in mac_str:  # Định dạng MAC chuẩn
                    return mac_str.lower()
                else:
                    return mac_str
                    
        except Exception as e:
            print(f"[LỖI] Lấy địa chỉ MAC thất bại: {e}")
            return "Unknown"

    def get_mac_address_cached(self):
        """Phiên bản cache của get_mac_address"""
        cache_key = f"mac_{self.interface_index}"
        return self.snmp_get_cached(f'1.3.6.1.2.1.2.2.1.6.{self.interface_index}' if self.interface_index else '1.3.6.1.2.1.2.2.1.6.1', cache_key)

    def get_network_metrics_optimized(self):
        """Thu thập số liệu mạng được tối ưu"""
        if not self.interface_index:
            return 0, 0, 0
            
        oid_in = f'1.3.6.1.2.1.2.2.1.10.{self.interface_index}'
        oid_out = f'1.3.6.1.2.1.2.2.1.16.{self.interface_index}'
        oid_speed = f'1.3.6.1.2.1.2.2.1.5.{self.interface_index}'
        
        # Đo lần đầu
        in1 = self.snmp_get(oid_in)
        out1 = self.snmp_get(oid_out)
        
        if in1 is None or out1 is None:
            return 0, 0, 0
        
        # Thời gian chờ (giảm từ 5s xuống 3s)
        time.sleep(3)
        
        # Đo lần thứ hai
        in2 = self.snmp_get(oid_in)
        out2 = self.snmp_get(oid_out)
        
        if in2 is None or out2 is None:
            return 0, 0, 0
        
        # Tính băng thông (bits per second to Mbps)
        try:
            net_in = (int(in2) - int(in1)) * 8 / 3 / 1_000_000
            net_out = (int(out2) - int(out1)) * 8 / 3 / 1_000_000
            
            # Xử lý counter rollover
            if net_in < 0:
                net_in = 0
            if net_out < 0:
                net_out = 0
                
        except (ValueError, TypeError):
            net_in = net_out = 0
        
        # Tốc độ liên kết (cached)
        link_speed = self.snmp_get_cached(oid_speed, f"link_speed_{self.interface_index}")
        try:
            link_speed_mbps = float(int(link_speed) / 1_000_000) if link_speed else 0
        except (ValueError, TypeError):
            link_speed_mbps = 0
        
        return net_in, net_out, link_speed_mbps

    def get_memory_metrics(self):
        """Lấy số liệu sử dụng bộ nhớ"""
        if not self.memory_index:
            return 0, 0
            
        oid_total = f'1.3.6.1.2.1.25.2.3.1.5.{self.memory_index}'
        oid_used = f'1.3.6.1.2.1.25.2.3.1.6.{self.memory_index}'
        oid_alloc = f'1.3.6.1.2.1.25.2.3.1.4.{self.memory_index}'
        
        total_blocks = self.snmp_get(oid_total)
        used_blocks = self.snmp_get(oid_used)
        alloc_unit = self.snmp_get_cached(oid_alloc, f"alloc_unit_{self.memory_index}")
        
        try:
            if total_blocks and alloc_unit:
                total_mb = int(total_blocks) * int(alloc_unit) / 1024 / 1024
            else:
                total_mb = 0
                
            if used_blocks and alloc_unit:
                used_mb = int(used_blocks) * int(alloc_unit) / 1024 / 1024
            else:
                used_mb = 0
                
        except (ValueError, TypeError):
            total_mb = used_mb = 0
        
        return total_mb, used_mb

    def get_system_metrics(self):
        """Lấy số liệu hệ thống (CPU, uptime, disk)"""
        # CPU
        cpu_list = self.get_all_cpu_loads()
        avg_cpu = round(sum(cpu_list) / len(cpu_list), 2) if cpu_list else 0
        
        # Uptime
        uptime = self.snmp_get('1.3.6.1.2.1.1.3.0')
        try:
            uptime_sec = float(int(uptime) / 100) if uptime else 0
        except (ValueError, TypeError):
            uptime_sec = 0
        
        # Disk (hệ thống file gốc)
        disk_used = self.snmp_get('1.3.6.1.2.1.25.2.3.1.6.1')
        disk_total = self.snmp_get('1.3.6.1.2.1.25.2.3.1.5.1')
        
        try:
            # Giả định đơn vị phân bổ 4KB (phổ biến cho hệ thống file)
            disk_used_mb = int(disk_used) * 4096 / 1024 / 1024 if disk_used else 0
            disk_total_mb = int(disk_total) * 4096 / 1024 / 1024 if disk_total else 0
        except (ValueError, TypeError):
            disk_used_mb = disk_total_mb = 0
        
        return avg_cpu, uptime_sec, disk_used_mb, disk_total_mb

    def _get_offline_data(self, timestamp):
        """Trả về cấu trúc dữ liệu thiết bị offline"""
        return {
            'timestamp': timestamp,
            'state': 'off',
            'ip_address': self.ip,
            'mac_address': 'Unknown',
            'total_ram_mb': 0,
            'used_ram_mb': 0,
            'link_speed': 0,
            'network_in_mbps': 0,
            'network_out_mbps': 0,
            'cpu_load_percent': 0,
            'uptime_seconds': 0,
            'disk_used_mb': 0,
            'disk_total_mb': 0
        }

    def _process_alerts(self, avg_cpu, used_mb, total_mb, disk_used_mb, disk_total_mb,
                       uptime_sec, net_in, net_out, link_speed_mbps, mac_addr, now_str):
        """Xử lý tất cả các loại cảnh báo"""
        
        # Cảnh báo CPU
        if ALERT_CONFIG['cpu']['enabled'] and avg_cpu > ALERT_CONFIG['cpu']['threshold']:
            msg = (f"🔥 *CẢNH BÁO CPU*\n"
                   f"Thiết bị `{self.ip}` vượt ngưỡng CPU: *{avg_cpu}%*\n"
                   f"Ngưỡng: {ALERT_CONFIG['cpu']['threshold']}%\n"
                   f"⏰ {now_str}")
            AlertManager.send_alert(msg, alert_key=f"{self.ip}_cpu_high",
                                  cooldown_sec=ALERT_CONFIG['cpu']['cooldown_sec'], value=avg_cpu)
        else:
            AlertManager.clear_alert(f"{self.ip}_cpu_high")

        # Cảnh báo RAM
        ram_percent = (used_mb / total_mb * 100) if total_mb else 0
        if ALERT_CONFIG['ram']['enabled'] and ram_percent > ALERT_CONFIG['ram']['threshold']:
            msg = (f"📊 *CẢNH BÁO RAM*\n"
                   f"Thiết bị `{self.ip}` vượt ngưỡng RAM: *{ram_percent:.1f}%*\n"
                   f"Đang sử dụng: {used_mb:.1f} MB / {total_mb:.1f} MB\n"
                   f"Ngưỡng: {ALERT_CONFIG['ram']['threshold']}%\n"
                   f"⏰ {now_str}")
            AlertManager.send_alert(msg, alert_key=f"{self.ip}_ram_high",
                                  cooldown_sec=ALERT_CONFIG['ram']['cooldown_sec'], value=ram_percent)
        else:
            AlertManager.clear_alert(f"{self.ip}_ram_high")

        # Cảnh báo Disk
        disk_percent = (disk_used_mb / disk_total_mb * 100) if disk_total_mb else 0
        if ALERT_CONFIG['disk']['enabled'] and disk_percent > ALERT_CONFIG['disk']['threshold']:
            msg = (f"💾 *CẢNH BÁO Ổ CỨNG*\n"
                   f"Thiết bị `{self.ip}` gần đầy ổ cứng!\n"
                   f"Đã sử dụng: {disk_used_mb:.1f} MB / {disk_total_mb:.1f} MB ({disk_percent:.1f}%)\n"
                   f"Vượt ngưỡng: {ALERT_CONFIG['disk']['threshold']}%\n"
                   f"⏰ {now_str}")
            AlertManager.send_alert(msg, alert_key=f"{self.ip}_disk_high",
                                  cooldown_sec=ALERT_CONFIG['disk']['cooldown_sec'], value=disk_percent)
        else:
            AlertManager.clear_alert(f"{self.ip}_disk_high")

        # Cảnh báo Uptime (thiết bị vừa khởi động lại)
        if ALERT_CONFIG['uptime']['enabled'] and 0 < uptime_sec < ALERT_CONFIG['uptime']['threshold_sec']:
            msg = (f"🔄 *CẢNH BÁO KHỞI ĐỘNG LẠI*\n"
                   f"Thiết bị `{self.ip}` vừa khởi động lại!\n"
                   f"Thời gian hoạt động: {uptime_sec:.0f} giây ({uptime_sec/60:.1f} phút)\n"
                   f"Ngưỡng: < {ALERT_CONFIG['uptime']['threshold_sec']} giây\n"
                   f"⏰ {now_str}")
            AlertManager.send_alert(msg, alert_key=f"{self.ip}_uptime_low",
                                  cooldown_sec=ALERT_CONFIG['uptime']['cooldown_sec'], value=uptime_sec)
        else:
            AlertManager.clear_alert(f"{self.ip}_uptime_low")

        # Cảnh báo lưu lượng mạng
        if ALERT_CONFIG['network']['enabled'] and link_speed_mbps > 0:
            net_threshold = ALERT_CONFIG['network']['threshold_percent'] / 100.0 * link_speed_mbps
            net_spike = (net_in > net_threshold) or (net_out > net_threshold)
            
            if net_spike:
                msg = (f"🌐 *CẢNH BÁO LƯU LƯỢNG MẠNG*\n"
                       f"Thiết bị `{self.ip}` có lưu lượng mạng cao bất thường!\n"
                       f"Vào: {net_in:.2f} Mbps | Ra: {net_out:.2f} Mbps\n"
                       f"Ngưỡng: {ALERT_CONFIG['network']['threshold_percent']}% của {link_speed_mbps:.2f} Mbps\n"
                       f"⏰ {now_str}")
                AlertManager.send_alert(msg, alert_key=f"{self.ip}_net_spike",
                                      cooldown_sec=ALERT_CONFIG['network']['cooldown_sec'],
                                      value=(net_in, net_out))
            else:
                AlertManager.clear_alert(f"{self.ip}_net_spike")

        # Cảnh báo địa chỉ MAC không xác định
        if mac_addr and mac_addr != "Unknown":
            mac_str = str(mac_addr).lower()
            if mac_str not in TRUSTED_MACS:
                msg = (f"🚨 *CẢNH BÁO THIẾT BỊ LẠ*\n"
                       f"Thiết bị SNMP IP `{self.ip}` có địa chỉ MAC *không thuộc danh sách an toàn!*\n"
                       f"MAC phát hiện: `{mac_addr}`\n"
                       f"Vui lòng kiểm tra và thêm vào Trust_Devices.txt nếu đây là thiết bị hợp lệ.\n"
                       f"⏰ {now_str}")
                AlertManager.send_alert(
                    msg,
                    alert_key=f"{self.ip}_unknown_mac",
                    cooldown_sec=600,
                    send_gmail=True,
                    gmail_subject=f"CẢNH BÁO THIẾT BỊ LẠ IP {self.ip}"
                )

    def collect_all_metrics(self):
        """Phương thức chính để thu thập tất cả số liệu"""
        now = datetime.datetime.now()
        now_str = now.strftime('%Y-%m-%d %H:%M:%S')
        
        print(f"[THÔNG TIN] Đang thu thập số liệu từ {self.ip}...")
        
        # Bước 1: Kiểm tra thiết bị có trực tuyến không
        if not self.is_host_up():
            print(f"[CẢNH BÁO] Thiết bị {self.ip} đang offline")
            
            if ALERT_CONFIG['offline']['enabled']:
                msg = (f"❌ *CẢNH BÁO SNMP*\n"
                       f"Thiết bị `{self.ip}` *mất kết nối* hoặc *tắt nguồn*.\n"
                       f"⏰ Thời điểm: {now_str}")
                AlertManager.send_alert(
                    msg,
                    alert_key=f"{self.ip}_offline",
                    cooldown_sec=ALERT_CONFIG['offline']['cooldown_sec'],
                    send_gmail=True,
                    gmail_subject=f"Thiết bị mất kết nối SNMP: {self.ip}"
                )
            
            return self._get_offline_data(now_str)
        
        # Xóa cảnh báo offline nếu thiết bị đã trực tuyến trở lại
        AlertManager.clear_alert(f"{self.ip}_offline")
        print(f"[OK] Thiết bị {self.ip} đang trực tuyến")
        
        # Bước 2: Thu thập số liệu song song
        try:
            with ThreadPoolExecutor(max_workers=3) as executor:
                # Gửi các tác vụ song song
                network_future = executor.submit(self.get_network_metrics_optimized)
                memory_future = executor.submit(self.get_memory_metrics)
                system_future = executor.submit(self.get_system_metrics)
                
                # Thu thập kết quả với timeout
                net_in, net_out, link_speed_mbps = network_future.result(timeout=15)
                total_mb, used_mb = memory_future.result(timeout=10)
                avg_cpu, uptime_sec, disk_used_mb, disk_total_mb = system_future.result(timeout=10)
                
        except Exception as e:
            print(f"[LỖI] Thu thập số liệu song song thất bại cho {self.ip}: {e}")
            return self._get_offline_data(now_str)
        
        # Bước 3: Lấy địa chỉ MAC
        mac_addr = self.get_mac_address()
        
        # Bước 4: Xử lý cảnh báo
        self._process_alerts(avg_cpu, used_mb, total_mb, disk_used_mb, disk_total_mb,
                           uptime_sec, net_in, net_out, link_speed_mbps, mac_addr, now_str)
        
        # Bước 5: Trả về dữ liệu đã thu thập
        data = {
            'timestamp': now_str,
            'state': 'on',
            'ip_address': self.ip,
            'mac_address': mac_addr,
            'total_ram_mb': float(round(total_mb, 2)),
            'used_ram_mb': float(round(used_mb, 2)),
            'ram_usage_percent': float(round((used_mb / total_mb * 100) if total_mb else 0, 2)),
            'link_speed': float(round(link_speed_mbps, 2)),
            'network_in_mbps': float(round(net_in, 2)),
            'network_out_mbps': float(round(net_out, 2)),
            'cpu_load_percent': float(avg_cpu),
            'uptime_seconds': float(round(uptime_sec, 2)),
            'uptime_hours': float(round(uptime_sec / 3600, 2)),
            'disk_used_mb': float(round(disk_used_mb, 2)),
            'disk_total_mb': float(round(disk_total_mb, 2)),
            'disk_usage_percent': float(round((disk_used_mb / disk_total_mb * 100) if disk_total_mb else 0, 2))
        }
        
        print(f"[OK] Đã thu thập số liệu cho {self.ip}: CPU={avg_cpu}%, RAM={data['ram_usage_percent']:.1f}%, Ổ cứng={data['disk_usage_percent']:.1f}%")
        return data

    def export_to_gsheets(self, data, creds_file, sheet_name, tab_name="SNMPData"):
        """Xuất dữ liệu vào Google Sheets với xử lý lỗi"""
        try:
            writer = GoogleSheetsWriter(creds_file, sheet_name)
            success = writer.write_logs(tab_name, [data])
            
            if success:
                print(f"[OK] Đã ghi dữ liệu {self.ip} vào Google Sheet tab '{tab_name}'")
            else:
                print(f"[LỖI] Ghi Google Sheets thất bại cho {self.ip}")
                
            return success
            
        except Exception as e:
            print(f"[LỖI] Xuất dữ liệu vào Google Sheets thất bại cho {self.ip}: {e}")
            return False

def discover_snmp_hosts(subnet=None, community=None, timeout=1.0):
    """Quét các thiết bị SNMP trong mạng"""
    if subnet is None:
        subnet = Config.SNMP_SUBNET
    if community is None:
        community = Config.SNMP_COMMUNITY
    
    print(f"[THÔNG TIN] Đang quét subnet {subnet} tìm thiết bị SNMP...")
    reachable_hosts = []
    
    try:
        network = ipaddress.IPv4Network(subnet)
        total_ips = network.num_addresses
        
        if total_ips > 256:
            print(f"[CẢNH BÁO] Phát hiện subnet lớn ({total_ips} IP). Quá trình này có thể mất thời gian...")
        
        scanned = 0
        for ip in network:
            ip_str = str(ip)
            scanned += 1
            
            # Hiển thị tiến độ cho subnet lớn
            if total_ips > 50 and scanned % 50 == 0:
                print(f"[TIẾN ĐỘ] Đã quét {scanned}/{total_ips} IP...")
            
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
                    print(f"[TÌM THẤY] Thiết bị SNMP: {ip_str}")
                    
            except Exception:
                continue
    
    except Exception as e:
        print(f"[LỖI] Khám phá mạng thất bại: {e}")
        return []

    # Cảnh báo nếu không tìm thấy thiết bị nào
    if ALERT_CONFIG['nohost']['enabled']:
        alert_key = f"subnet_{subnet}_nohost"
        
        if not reachable_hosts:
            msg = (f"🚨 *CẢNH BÁO HỆ THỐNG GIÁM SÁT SNMP*\n"
                   f"KHÔNG PHÁT HIỆN ĐƯỢC THIẾT BỊ SNMP NÀO TRÊN DẢI `{subnet}`!\n"
                   f"Tất cả thiết bị SNMP đều offline hoặc không phản hồi.\n"
                   f"Kiểm tra:\n"
                   f"• Kết nối mạng\n"
                   f"• Chuỗi community SNMP\n"
                   f"• Cài đặt tường lửa\n"
                   f"⏰ {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            AlertManager.send_alert(
                msg,
                alert_key=alert_key,
                cooldown_sec=ALERT_CONFIG['nohost']['cooldown_sec'],
                send_gmail=True,
                gmail_subject=f"KHÔNG PHÁT HIỆN THIẾT BỊ SNMP ({subnet})"
            )
        else:
            AlertManager.clear_alert(alert_key)

    print(f"[OK] Hoàn tất quá trình quét. Tìm thấy {len(reachable_hosts)} thiết bị SNMP.")
    return reachable_hosts
