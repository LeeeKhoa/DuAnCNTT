from snmp_monitor import SNMPMonitor, discover_snmp_hosts

if __name__ == "__main__":
    SHEET_NAME = "EventLogData"
    CREDS_FILE = "credentials.json"

    available_hosts = discover_snmp_hosts("192.168.1.0/24", community="monitor")
    print("[INFO] Các máy SNMP phát hiện được:", available_hosts)

    for ip in available_hosts:
        monitor = SNMPMonitor(ip, community="monitor")
        data = monitor.collect_all_metrics()
        monitor.export_to_gsheets(data, CREDS_FILE, SHEET_NAME, tab_name="SNMPData")
        print(f"[OK] Ghi dữ liệu từ {ip} vào Google Sheet tab SNMPData")
