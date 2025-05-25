import win32evtlog
import csv
import datetime
import requests
import smtplib
from email.mime.text import MIMEText
from collections import defaultdict

ALERT_EVENT_IDS = {
    4634: {"type": "logoff", "user_idx": 5},
    4720: {"type": "add_user", "user_idx": 5},
    4722: {"type": "enable_user", "user_idx": 5},
    4723: {"type": "user_pw_change", "user_idx": 5},
    4724: {"type": "admin_pw_reset", "user_idx": 5},
    4726: {"type": "del_user", "user_idx": 5},
    4732: {"type": "add_to_group", "user_idx": 5, "group_idx": 8},
    4733: {"type": "remove_from_group", "user_idx": 5, "group_idx": 8},
}

class SecurityEventLogMonitor:
    def __init__(self, server='localhost'):
        self.log_type = 'Security'
        self.server = server
        # Telegram (có sẵn token & chat_id)
        self.telegram_token = "7724834226:AAHv2sQoR4_UPrEuxc2qIA7MgSZaYEo7E6U"
        self.telegram_chat_id = "1910835997"
        # Gmail (bạn điền Gmail và App Password)
        self.gmail_user = "tancang1704@gmail.com"
        self.gmail_pass = "zrrg qbil itfc vlzg"  # App Password Gmail 16 ký tự

    def send_telegram_alert(self, message):
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {'chat_id': self.telegram_chat_id, 'text': message}
        try:
            requests.post(url, data=payload, timeout=5)
        except Exception as e:
            print(f"[ERROR] Gửi Telegram thất bại: {e}")

    def send_mail_gmail(self, subject, body, to_email=None):
        if not self.gmail_user or not self.gmail_pass:
            print("[ERROR] Chưa cấu hình gmail_user và gmail_pass!")
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
            print("[OK] Đã gửi mail Gmail.")
        except Exception as e:
            print(f"[ERROR] Gửi mail Gmail thất bại: {e}")

    def extract_field(self, parts, idx):
        try:
            return parts[idx].strip()
        except Exception:
            return "Không rõ"

    def process_events_batch_alert(self, entries):
        alerts_this_scan = defaultdict(set)
        brute_force_candidates = defaultdict(list)
        rdp_logons = []

        for entry in entries:
            event_id = entry['event_id']
            message = entry['message']
            timestamp = entry['timestamp']
            parts = message.split('|')

            # Brute-force login fail
            if event_id == 4625:
                user = self.extract_field(parts, 5)
                ip = self.extract_field(parts, 18)
                key = (user, ip)
                brute_force_candidates[key].append(timestamp)
                continue

            # Đăng nhập RDP qua 4648
            if event_id == 4648:
                user = self.extract_field(parts, 5)
                ip = self.extract_field(parts, 18)
                rdp_logons.append((user, ip, timestamp))
                continue

            # Các event khác (logoff, add_user, ...)
            if event_id in ALERT_EVENT_IDS:
                info = ALERT_EVENT_IDS[event_id]
                alert_type = info["type"]
                user = self.extract_field(parts, info.get("user_idx", 5))
                group = self.extract_field(parts, info.get("group_idx", -1)) if "group_idx" in info else None
                if group:
                    alerts_this_scan[alert_type].add(f"{user}→{group}")
                else:
                    alerts_this_scan[alert_type].add(user)

        # Gửi brute-force alert (Telegram + Gmail)
        for (user, ip), times in brute_force_candidates.items():
            if len(times) >= 5:
                try:
                    t0 = datetime.datetime.strptime(times[0], "%Y-%m-%d %H:%M:%S")
                    t4 = datetime.datetime.strptime(times[4], "%Y-%m-%d %H:%M:%S")
                    if (t4 - t0).total_seconds() <= 600:
                        msg = (f"⚠️ BRUTE FORCE: 5 lần login sai liên tiếp\n"
                               f"Tài khoản: {user}\nIP: {ip}\nThời gian: {times[4]}")
                        self.send_telegram_alert(msg)
                        self.send_mail_gmail("Cảnh báo BRUTE FORCE", msg)
                except Exception:
                    msg = (f"⚠️ BRUTE FORCE: 5 lần login sai liên tiếp\n"
                           f"Tài khoản: {user}\nIP: {ip}\nThời gian: {times[4]}")
                    self.send_telegram_alert(msg)
                    self.send_mail_gmail("Cảnh báo BRUTE FORCE", msg)

        # Gửi cảnh báo RDP qua 4648 (Telegram + Gmail)
        if rdp_logons:
            users = set([user for user, ip, _ in rdp_logons])
            ips = set([ip for user, ip, _ in rdp_logons])
            latest_time = max([ts for _, _, ts in rdp_logons])
            msg = (f"🖥️ PHÁT HIỆN ĐĂNG NHẬP RDP (4648) TRONG LẦN QUÉT\n"
                   f"User: {', '.join(users)}\n"
                   f"IP: {', '.join(ips)}\n"
                   f"Thời gian mới nhất: {latest_time}")
            self.send_telegram_alert(msg)
            self.send_mail_gmail("Cảnh báo RDP", msg)

        # Các loại alert khác chỉ gửi Telegram
        for alert_type, userlist in alerts_this_scan.items():
            if not userlist:
                continue
            userstr = ', '.join(userlist)
            if alert_type == "logoff":
                msg = f"🚪 Có nhiều user đăng xuất: {userstr}"
            elif alert_type == "add_user":
                msg = f"➕ User mới được tạo: {userstr}"
            elif alert_type == "del_user":
                msg = f"❌ User bị xóa: {userstr}"
            elif alert_type == "add_to_group":
                msg = f"👥 Thêm user vào group: {userstr}"
            elif alert_type == "remove_from_group":
                msg = f"👤 Xóa user khỏi group: {userstr}"
            else:
                msg = f"🔔 Event {alert_type}: {userstr}"
            self.send_telegram_alert(msg)

    def collect_logs(self, max_entries=20):
        log_entries = []
        try:
            handle = win32evtlog.OpenEventLog(self.server, self.log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            count = 0
            while count < max_entries:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events: break
                for event in events:
                    ts = event.TimeGenerated.Format()
                    try:
                        datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        ts = str(event.TimeGenerated)
                    entry = {
                        'timestamp': ts,
                        'source': event.SourceName,
                        'event_id': event.EventID & 0xFFFF,
                        'type': event.EventType,
                        'category': event.EventCategory,
                        'log_type': self.log_type,
                        'message': ' | '.join(event.StringInserts) if event.StringInserts else ''
                    }
                    log_entries.append(entry)
                    count += 1
                    if count >= max_entries:
                        break
            win32evtlog.CloseEventLog(handle)
        except Exception as e:
            print(f"[ERROR] Không thể đọc log Security: {e}")

        if log_entries:
            self.process_events_batch_alert(log_entries)
        return log_entries

    def export_to_csv(self, logs, filename='security_logs.csv'):
        fieldnames = ['timestamp', 'log_type', 'source', 'event_id', 'type', 'category', 'message']
        with open(filename, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if f.tell() == 0:
                writer.writeheader()
            for log in logs:
                writer.writerow(log)
