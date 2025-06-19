"""
Giám sát Event Log Hệ thống.
Giám sát Windows System event log cho các sự kiện liên quan đến hệ thống.
"""

import win32evtlog
import csv
import datetime
import requests
import smtplib
import wmi
from email.mime.text import MIMEText
from collections import defaultdict
from config import Config

# Định nghĩa các Event ID cần giám sát cho hệ thống
ALERT_EVENT_IDS = {
    6005: "system_start",        # Hệ thống khởi động (Event Log service start)
    6006: "system_shutdown",     # Hệ thống tắt (Event Log service stop)
    6008: "unexpected_shutdown", # Hệ thống tắt đột ngột
    41: "power_loss",           # Mất điện (Kernel-Power)
    7000: "service_failed",     # Dịch vụ khởi động thất bại
    7036: "service_status_change" # Dịch vụ thay đổi trạng thái
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


class SystemEventLogMonitor:
    """Giám sát Windows System Event Log."""
    
    def __init__(self, server='localhost'):
        """
        Khởi tạo System Event Log Monitor.
        
        Args:
            server: Tên server cần giám sát (mặc định: localhost)
        """
        # Xác thực cấu hình trước
        Config.validate()
        
        self.log_type = 'System'
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

    def process_events_batch_alert(self, entries):
        """Xử lý các sự kiện hệ thống và gửi cảnh báo."""
        # Khởi tạo các biến để theo dõi cảnh báo
        alerts_this_scan = defaultdict(list)
        power_loss_events = []

        # Duyệt qua từng entry để phân tích
        for entry in entries:
            event_id = entry['event_id']
            message = entry['message']
            timestamp = entry['timestamp']

            # Xử lý riêng sự kiện mất điện (Event ID 41)
            if event_id == 41:
                power_loss_events.append((message, timestamp))

            # Phân loại các sự kiện hệ thống
            if event_id in ALERT_EVENT_IDS:
                alert_type = ALERT_EVENT_IDS[event_id]
                alerts_this_scan[alert_type].append((message, timestamp))

        # Gửi cảnh báo mất điện (Telegram + Gmail vì nghiêm trọng)
        if power_loss_events:
            times = ', '.join([ts for msg, ts in power_loss_events])
            msg = (
                f"⚡ CẢNH BÁO NGHIÊM TRỌNG: Hệ thống mất điện hoặc khởi động lại bất thường\n"
                f"🕒 Thời gian xảy ra: {times}\n"
                f"💾 Khuyến nghị: Kiểm tra tính toàn vẹn dữ liệu và trạng thái hệ thống\n"
                f"🔧 Hành động: Xem xét kiểm tra phần cứng và nguồn điện"
            )
            self.send_telegram_alert(msg)
            self.send_mail_gmail("🚨 KHẨN CẤP: Hệ thống mất điện (Event ID 41)", msg)

        # Gửi các cảnh báo hệ thống khác (chỉ Telegram)
        for alert_type, events in alerts_this_scan.items():
            if not events or alert_type == "power_loss":
                continue  # Đã xử lý power_loss ở trên

            if alert_type == "system_start":
                times = ', '.join([ts for msg, ts in events])
                msg = (
                    f"🟢 THÔNG BÁO: Hệ thống đã khởi động thành công\n"
                    f"🕒 Thời gian khởi động: {times}\n"
                    f"✅ Trạng thái: Hệ thống đang hoạt động bình thường"
                )
            elif alert_type == "system_shutdown":
                times = ', '.join([ts for msg, ts in events])
                msg = (
                    f"🔴 THÔNG BÁO: Hệ thống đã được tắt\n"
                    f"🕒 Thời gian tắt máy: {times}\n"
                    f"📝 Ghi chú: Quá trình tắt máy được thực hiện theo đúng quy trình"
                )
            elif alert_type == "unexpected_shutdown":
                times = ', '.join([ts for msg, ts in events])
                msg = (
                    f"⚠️ CẢNH BÁO: Hệ thống tắt đột ngột không theo quy trình\n"
                    f"🕒 Thời gian xảy ra: {times}\n"
                    f"🔧 Khuyến nghị: Kiểm tra nguyên nhân và tình trạng phần cứng"
                )
            elif alert_type == "service_failed":
                service_list = [f"• {msg} (Thời gian: {ts})" for msg, ts in events]
                msg = (
                    f"🚫 CẢNH BÁO: Dịch vụ hệ thống không thể khởi động\n"
                    f"📋 Danh sách dịch vụ gặp sự cố:\n" + "\n".join(service_list) +
                    f"\n🔧 Khuyến nghị: Kiểm tra và khởi động lại các dịch vụ bị lỗi"
                )
            elif alert_type == "service_status_change":
                service_list = [f"• {msg} (Thời gian: {ts})" for msg, ts in events]
                msg = (
                    f"🔄 THÔNG BÁO: Trạng thái dịch vụ hệ thống đã thay đổi\n"
                    f"📋 Chi tiết thay đổi:\n" + "\n".join(service_list)
                )
            else:
                detail_list = [f"• {msg} (Thời gian: {ts})" for msg, ts in events]
                msg = (
                    f"🔔 THÔNG BÁO HỆ THỐNG: Sự kiện {alert_type}\n"
                    f"📋 Chi tiết:\n" + "\n".join(detail_list)
                )

            self.send_telegram_alert(msg)

    def collect_logs(self, max_entries=20):
        """Thu thập logs từ Windows System Event Log."""
        log_entries = []
        
        try:
            # Mở handle đến System Event Log
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
            print(f"[LỖI] Không thể đọc log System: {e}")

        # Xử lý cảnh báo nếu có entries
        if log_entries:
            self.process_events_batch_alert(log_entries)

        return log_entries

    def export_to_csv(self, logs, filename='system_logs.csv'):
        """Xuất logs ra file CSV."""
        fieldnames = ['timestamp', 'log_type', 'source', 'event_id', 'type', 'category', 'message', 'mac_address']
        
        try:
            with open(filename, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                if f.tell() == 0:
                    writer.writeheader()
                for log in logs:
                    writer.writerow(log)
            print(f"[THÀNH CÔNG] Đã xuất {len(logs)} bản ghi ra {filename}")
        except Exception as e:
            print(f"[LỖI] Không thể xuất CSV: {e}")