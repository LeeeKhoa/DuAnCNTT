"""
Ứng dụng chính cho Hệ thống Giám sát Event Log.
Điều phối tất cả các thành phần giám sát và xử lý luồng thực thi.
"""

from system_eventlog_monitor import SystemEventLogMonitor
from security_eventlog_monitor import SecurityEventLogMonitor
from rdp_eventlog_monitor import RDPPowerShellMonitor as RDPEventLogMonitor
from sheets_writer import GoogleSheetsWriter
from config import Config


def main():
    """Hàm chính để chạy giám sát."""
    try:
        # Xác thực cấu hình
        Config.validate()
        print("[THÀNH CÔNG] Đã xác thực cấu hình hệ thống")
        
        # Khởi tạo Google Sheets writer
        writer = GoogleSheetsWriter(Config.GOOGLE_CREDS_FILE, Config.GOOGLE_SHEET_NAME)
        print("[THÀNH CÔNG] Đã khởi tạo Google Sheets writer")
        
        # Giám sát System log
        print("[THÔNG TIN] Bắt đầu giám sát System log...")
        system_monitor = SystemEventLogMonitor()
        system_logs = system_monitor.collect_logs(max_entries=20)
        writer.write_logs("SystemLog", system_logs)
        print(f"[THÀNH CÔNG] Đã xử lý {len(system_logs)} bản ghi system log")

        # Giám sát Security log (không bao gồm RDP Event 4648)
        print("[THÔNG TIN] Bắt đầu giám sát Security log...")
        security_monitor = SecurityEventLogMonitor()
        security_logs = security_monitor.collect_logs(max_entries=20)
        writer.write_logs("SecurityLog", security_logs)
        print(f"[THÀNH CÔNG] Đã xử lý {len(security_logs)} bản ghi security log")
        
        # Giám sát RDP log (Event ID 1149) - THÊM MỚI
        print("[THÔNG TIN] Bắt đầu giám sát RDP log...")
        rdp_monitor = RDPEventLogMonitor()
        rdp_logs = rdp_monitor.collect_logs(max_entries=20)
        writer.write_logs("RDPLog", rdp_logs)
        print(f"[THÀNH CÔNG] Đã xử lý {len(rdp_logs)} bản ghi RDP log")
        
        print("\n[THÀNH CÔNG] Tất cả các tác vụ giám sát đã hoàn thành")
        
    except ValueError as e:
        print(f"[LỖI CẤU HÌNH] {e}")
    except Exception as e:
        print(f"[LỖI] Giám sát thất bại: {e}")


if __name__ == "__main__":
    main()