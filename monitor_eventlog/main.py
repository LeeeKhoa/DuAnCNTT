from system_eventlog_monitor import SystemEventLogMonitor
from security_eventlog_monitor import SecurityEventLogMonitor
from sheets_writer import GoogleSheetsWriter

if __name__ == "__main__":
    SHEET_NAME = "EventLogData"  # Tên Google Sheet bạn đã tạo
    CREDS_FILE = "credentials.json"  # Đường dẫn tới file JSON credentials
    writer = GoogleSheetsWriter(CREDS_FILE, SHEET_NAME)

    # System log monitoring
    system_monitor = SystemEventLogMonitor()
    system_logs = system_monitor.collect_logs(max_entries=20)
    writer.write_logs("SystemLog", system_logs)

    # Security log monitoring
    security_monitor = SecurityEventLogMonitor()
    security_logs = security_monitor.collect_logs(max_entries=20)
    writer.write_logs("SecurityLog", security_logs)