import win32evtlog
import csv
import datetime
import requests
import smtplib
from email.mime.text import MIMEText
from collections import defaultdict

ALERT_EVENT_IDS = {
    6005: "system_start",         # Hệ thống bật lại (Event Log service start)
    6006: "system_shutdown",      # Hệ thống shutdown (Event Log service stop)
    6008: "unexpected_shutdown",  # Hệ thống bị tắt đột ngột
    41:   "power_loss",           # Power lost (Kernel-Power)
    7000: "service_failed",       # Dịch vụ failed khởi động
    7036: "service_status_change" # Dịch vụ thay đổi trạng thái
}

class SystemEventLogMonitor:
    def __init__(self, server='localhost'):
        self.log_type = 'System'
        self.server = server
        # Telegram - ĐÃ có sẵn token & chat_id
        self.telegram_token = "7724834226:AAHv2sQoR4_UPrEuxc2qIA7MgSZaYEo7E6U"
        self.telegram_chat_id = "1910835997"
        # Gmail - bạn tự điền Gmail và App Password
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

    def process_events_batch_alert(self, entries):
        alerts_this_scan = defaultdict(list)
        power_loss_events = []

        for entry in entries:
            event_id = entry['event_id']
            message = entry['message']
            timestamp = entry['timestamp']

            if event_id == 41:
                power_loss_events.append((message, timestamp))
            if event_id in ALERT_EVENT_IDS:
                alert_type = ALERT_EVENT_IDS[event_id]
                alerts_this_scan[alert_type].append((message, timestamp))

        # Gửi cảnh báo cho event 41 (Telegram + Gmail)
        if power_loss_events:
            times = ', '.join([ts for msg, ts in power_loss_events])
            msg = f"⚡ MẤT ĐIỆN/RESET NGUỒN (Kernel-Power):\n{times}"
            self.send_telegram_alert(msg)
            self.send_mail_gmail("CẢNH BÁO: Power Loss (ID 41)", msg)

        # Gửi các cảnh báo khác chỉ qua Telegram
        for alert_type, events in alerts_this_scan.items():
            if not events or alert_type == "power_loss":
                continue  # Đã xử lý power_loss ở trên
            if alert_type == "system_start":
                times = ', '.join([ts for msg, ts in events])
                msg = f"🟢 HỆ THỐNG BẬT LẠI:\n{times}"
            elif alert_type == "system_shutdown":
                times = ', '.join([ts for msg, ts in events])
                msg = f"🔴 HỆ THỐNG TẮT:\n{times}"
            elif alert_type == "unexpected_shutdown":
                times = ', '.join([ts for msg, ts in events])
                msg = f"⚠️ TẮT ĐỘT NGỘT (Unexpected shutdown):\n{times}"
            elif alert_type == "service_failed":
                service_list = [f"{msg} ({ts})" for msg, ts in events]
                msg = "🚫 DỊCH VỤ KHÔNG KHỞI ĐỘNG ĐƯỢC:\n" + "\n".join(service_list)
            elif alert_type == "service_status_change":
                service_list = [f"{msg} ({ts})" for msg, ts in events]
                msg = "🔄 TRẠNG THÁI DỊCH VỤ THAY ĐỔI:\n" + "\n".join(service_list)
            else:
                detail_list = [f"{msg} ({ts})" for msg, ts in events]
                msg = f"🔔 SYSTEM EVENT {alert_type}:\n" + "\n".join(detail_list)
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
            print(f"[ERROR] Không thể đọc log System: {e}")

        if log_entries:
            self.process_events_batch_alert(log_entries)
        return log_entries

    def export_to_csv(self, logs, filename='system_logs.csv'):
        fieldnames = ['timestamp', 'log_type', 'source', 'event_id', 'type', 'category', 'message']
        with open(filename, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if f.tell() == 0:
                writer.writeheader()
            for log in logs:
                writer.writerow(log)