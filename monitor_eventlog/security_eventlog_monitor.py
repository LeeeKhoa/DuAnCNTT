import win32evtlog
import csv
import datetime
import requests
import smtplib
import wmi
from email.mime.text import MIMEText
from collections import defaultdict
from config import Config

# Định nghĩa các Event ID cần giám sát cho bảo mật (đã loại bỏ 4648)
ALERT_EVENT_IDS = {
    4625: {"type": "login_failed", "user_idx": 5, "ip_idx": 18},  # Đăng nhập thất bại
    4634: {"type": "logoff", "user_idx": 5},                     # Đăng xuất
    4720: {"type": "add_user", "user_idx": 5},                   # Tạo tài khoản mới
    4722: {"type": "enable_user", "user_idx": 5},                # Kích hoạt tài khoản
    4723: {"type": "user_pw_change", "user_idx": 5},             # Đổi mật khẩu
    4724: {"type": "admin_pw_reset", "user_idx": 5},             # Admin reset mật khẩu
    4726: {"type": "del_user", "user_idx": 5},                   # Xóa tài khoản
    4732: {"type": "add_to_group", "user_idx": 5, "group_idx": 8},    # Thêm vào nhóm
    4733: {"type": "remove_from_group", "user_idx": 5, "group_idx": 8}, # Xóa khỏi nhóm
}


def get_mac_address():
    """Lấy địa chỉ MAC của interface mạng đầu tiên được kích hoạt."""
    try:
        c = wmi.WMI()
        for interface in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            mac = interface.MACAddress
            if mac:
                return mac
    except Exception as e:
        print(f"[CẢNH BÁO] Không lấy được MAC: {e}")
    return "Unknown"


class SecurityEventLogMonitor:
    """Giám sát Windows Security Event Log."""
    
    def __init__(self, server='localhost'):
        """
        Khởi tạo Security Event Log Monitor.
        
        Args:
            server: Tên server cần giám sát (mặc định: localhost)
        """
        # Xác thực cấu hình trước
        Config.validate()
        
        self.log_type = 'Security'
        self.server = server
        
        # Tải cấu hình từ biến môi trường
        self.telegram_token = Config.TELEGRAM_TOKEN
        self.telegram_chat_id = Config.TELEGRAM_CHAT_ID
        self.telegram_proxy = Config.TELEGRAM_PROXY
        self.gmail_user = Config.GMAIL_USER
        self.gmail_pass = Config.GMAIL_PASS
        
        # Lấy MAC khi khởi tạo để tái sử dụng
        self.mac_address = get_mac_address()

    def send_telegram_alert(self, message):
        """Gửi cảnh báo qua Telegram."""
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {'chat_id': self.telegram_chat_id, 'text': message}
        try:
            requests.post(url, data=payload, timeout=10, proxies=self.telegram_proxy, verify=False)
            print("[THÀNH CÔNG] Đã gửi cảnh báo Telegram")
        except Exception as e:
            print(f"[LỖI] Gửi Telegram thất bại: {e}")

    def send_mail_gmail(self, subject, body, to_email=None):
        """Gửi cảnh báo qua Gmail."""
        if not self.gmail_user or not self.gmail_pass:
            print("[LỖI] Chưa cấu hình gmail_user và gmail_pass!")
            return
        if not to_email:
            to_email = self.gmail_user

        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = self.gmail_user
        msg['To'] = to_email

        try:
            with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                smtp.starttls()
                smtp.login(self.gmail_user, self.gmail_pass)
                smtp.sendmail(self.gmail_user, [to_email], msg.as_string())
            print("[THÀNH CÔNG] Đã gửi mail Gmail")
        except Exception as e:
            print(f"[LỖI] Gửi mail Gmail thất bại: {e}")

    def extract_field(self, parts, idx):
        """Trích xuất trường từ thông điệp event với xử lý lỗi."""
        try:
            return parts[idx].strip()
        except Exception:
            return "Không rõ"

    def process_events_batch_alert(self, entries):
        """Xử lý các sự kiện bảo mật và gửi cảnh báo."""
        # Khởi tạo các biến để theo dõi cảnh báo
        alerts_this_scan = defaultdict(set)
        brute_force_candidates = defaultdict(list)

        # Duyệt qua từng entry để phân tích
        for entry in entries:
            event_id = entry['event_id']
            message = entry['message']
            timestamp = entry['timestamp']
            parts = message.split('|')

            # Xử lý phát hiện tấn công brute force
            if event_id == 4625:
                user = self.extract_field(parts, 5)
                ip = self.extract_field(parts, 18)
                key = (user, ip)
                brute_force_candidates[key].append(timestamp)
                continue

            # Xử lý các sự kiện bảo mật khác (đã loại bỏ 4648)
            if event_id in ALERT_EVENT_IDS:
                info = ALERT_EVENT_IDS[event_id]
                alert_type = info["type"]
                user = self.extract_field(parts, info.get("user_idx", 5))
                group = self.extract_field(parts, info.get("group_idx", -1)) if "group_idx" in info else None

                if group:
                    alerts_this_scan[alert_type].add(f"{user}→{group}")
                else:
                    alerts_this_scan[alert_type].add(user)

        # Gửi cảnh báo tấn công brute force (Telegram + Gmail)
        for (user, ip), times in brute_force_candidates.items():
            if len(times) >= 5:
                try:
                    t0 = datetime.datetime.strptime(times[0], "%Y-%m-%d %H:%M:%S")
                    t4 = datetime.datetime.strptime(times[4], "%Y-%m-%d %H:%M:%S")
                    if (t4 - t0).total_seconds() <= 600:  # 5 lần trong 10 phút
                        msg = (
                            f"🚨 CẢNH BÁO NGHIÊM TRỌNG: Phát hiện tấn công brute force\n"
                            f"👤 Tài khoản bị tấn công: {user}\n"
                            f"🌐 Địa chỉ IP nguồn: {ip}\n"
                            f"⏰ Thời gian gần nhất: {times[4]}\n"
                            f"📊 Tổng số lần thử: {len(times)} lần trong 10 phút\n"
                            f"⚡ Khuyến nghị: Khóa tài khoản và chặn IP ngay lập tức"
                        )
                        self.send_telegram_alert(msg)
                        self.send_mail_gmail("🚨 KHẨN CẤP: Phát hiện tấn công brute force", msg)
                except Exception:
                    msg = (
                        f"🚨 CẢNH BÁO NGHIÊM TRỌNG: Phát hiện tấn công brute force\n"
                        f"👤 Tài khoản bị tấn công: {user}\n"
                        f"🌐 Địa chỉ IP nguồn: {ip}\n"
                        f"⏰ Thời gian gần nhất: {times[4]}\n"
                        f"📊 Tổng số lần thử: {len(times)} lần\n"
                        f"⚡ Khuyến nghị: Khóa tài khoản và chặn IP ngay lập tức"
                    )
                    self.send_telegram_alert(msg)
                    self.send_mail_gmail("🚨 KHẨN CẤP: Phát hiện tấn công brute force", msg)

        # Gửi các cảnh báo bảo mật khác (chỉ Telegram)
        for alert_type, userlist in alerts_this_scan.items():
            if not userlist:
                continue

            userstr = ', '.join(userlist)
            
            if alert_type == "logoff":
                msg = f"🚪 Thông báo: Nhiều người dùng đã đăng xuất khỏi hệ thống\n👥 Danh sách: {userstr}"
            elif alert_type == "add_user":
                msg = f"➕ CẢNH BÁO: Tài khoản người dùng mới được tạo\n👤 Tài khoản: {userstr}\n⚠️ Vui lòng xác minh tính hợp lệ"
            elif alert_type == "del_user":
                msg = f"❌ CẢNH BÁO: Tài khoản người dùng đã bị xóa\n👤 Tài khoản: {userstr}\n⚠️ Vui lòng kiểm tra quyền thực hiện"
            elif alert_type == "add_to_group":
                msg = f"👥 CẢNH BÁO: Người dùng được thêm vào nhóm quyền\n📋 Chi tiết: {userstr}\n⚠️ Vui lòng xác minh quyền hạn"
            elif alert_type == "remove_from_group":
                msg = f"👤 THÔNG BÁO: Người dùng bị loại khỏi nhóm quyền\n📋 Chi tiết: {userstr}"
            elif alert_type == "user_pw_change":
                msg = f"🔑 THÔNG BÁO: Người dùng đã thay đổi mật khẩu\n👤 Tài khoản: {userstr}"
            elif alert_type == "admin_pw_reset":
                msg = f"🔐 CẢNH BÁO: Quản trị viên đã đặt lại mật khẩu\n👤 Tài khoản: {userstr}\n⚠️ Vui lòng xác minh tính hợp lệ"
            elif alert_type == "enable_user":
                msg = f"✅ THÔNG BÁO: Tài khoản người dùng đã được kích hoạt\n👤 Tài khoản: {userstr}"
            else:
                msg = f"🔔 THÔNG BÁO BẢO MẬT: Sự kiện {alert_type}\n📋 Chi tiết: {userstr}"

            self.send_telegram_alert(msg)

    def collect_logs(self, max_entries=20):
        """Thu thập logs từ Windows Security Event Log."""
        log_entries = []
        try:
            # Mở handle đến Security Event Log
            handle = win32evtlog.OpenEventLog(self.server, self.log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            count = 0
            while count < max_entries:
                # Đọc các event từ log
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events: 
                    break

                for event in events:
                    # Định dạng timestamp
                    ts = event.TimeGenerated.Format()
                    try:
                        datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        ts = str(event.TimeGenerated)

                    # Tạo entry log
                    entry = {
                        'timestamp': ts,
                        'source': event.SourceName,
                        'event_id': event.EventID & 0xFFFF,
                        'type': event.EventType,
                        'category': event.EventCategory,
                        'log_type': self.log_type,
                        'message': ' | '.join(event.StringInserts) if event.StringInserts else '',
                        'mac_address': self.mac_address  # Thêm MAC vào log
                    }

                    log_entries.append(entry)
                    count += 1
                    if count >= max_entries:
                        break

            # Đóng handle
            win32evtlog.CloseEventLog(handle)

        except Exception as e:
            print(f"[LỖI] Không thể đọc log Security: {e}")

        # Xử lý cảnh báo nếu có entries
        if log_entries:
            self.process_events_batch_alert(log_entries)

        return log_entries

    def export_to_csv(self, logs, filename='security_logs.csv'):
        """Xuất logs ra file CSV."""
        fieldnames = ['timestamp', 'log_type', 'source', 'event_id', 'type', 'category', 'message', 'mac_address']
        with open(filename, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if f.tell() == 0:
                writer.writeheader()
            for log in logs:
                writer.writerow(log)