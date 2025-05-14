import gspread
from google.oauth2.service_account import Credentials

# Thiết lập kết nối Google Sheets
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
try:
    creds = Credentials.from_service_account_file('credentials.json', scopes=scope)
    client = gspread.authorize(creds)
    spreadsheet = client.open("EventLogData")
except Exception as e:
    print(f"[ERROR] Không thể kết nối Google Sheets: {e}")
    raise

# Hàm lấy dữ liệu từ sheet (chỉ lấy số lượng bản ghi tối đa)
def get_data_from_sheet(sheet_name, max_rows=50):
    try:
        sheet = spreadsheet.worksheet(sheet_name)
        data = sheet.get_all_records()
        # Chuẩn hóa dữ liệu
        standardized_data = []
        for item in data:
            standardized_item = {
                'timestamp': item.get('timestamp', ''),
                'state': item.get('state', 'off'),  # Chỉ dùng cho SNMPData
                'ip_address': item.get('ip_address', ''),  # Chỉ dùng cho SNMPData
                'mac_address': item.get('mac_address', ''),  # Chỉ dùng cho SNMPData
                'network_in_mbps': float(item.get('network_in_mbps', 0)),  # Chỉ dùng cho SNMPData
                'network_out_mbps': float(item.get('network_out_mbps', 0)),  # Chỉ dùng cho SNMPData
                'link_speed': float(item.get('link_speed', 0)),  # Chỉ dùng cho SNMPData
                'cpu_load_percent': float(item.get('cpu_load_percent', 0)),  # Chỉ dùng cho SNMPData
                'total_ram_mb': float(item.get('total_ram_mb', 0)),  # Chỉ dùng cho SNMPData
                'used_ram_mb': float(item.get('used_ram_mb', 0)),  # Chỉ dùng cho SNMPData
                'disk_used_mb': float(item.get('disk_used_mb', 0)),  # Chỉ dùng cho SNMPData
                'disk_total_mb': float(item.get('disk_total_mb', 0)),  # Chỉ dùng cho SNMPData
                'log_type': item.get('log_type', ''),  # Dùng cho SecurityLog/SystemLog
                'source': item.get('source', ''),  # Dùng cho SecurityLog/SystemLog
                'event_id': int(item.get('event_id', 0)),  # Dùng cho SecurityLog/SystemLog
                'type': item.get('type', ''),  # Dùng cho SecurityLog/SystemLog
                'category': item.get('category', ''),  # Dùng cho SecurityLog/SystemLog
                'message': item.get('message', '')  # Dùng cho SecurityLog/SystemLog
            }
            standardized_data.append(standardized_item)
        # Lấy max_rows bản ghi gần nhất
        return sorted(standardized_data, key=lambda x: x['timestamp'], reverse=True)[:max_rows]
    except Exception as e:
        print(f"[ERROR] Không thể đọc dữ liệu từ sheet {sheet_name}: {e}")
        return []

# Hàm lấy danh sách thiết bị (từ tab SNMPData)
def get_devices():
    return get_data_from_sheet("SNMPData")

# Hàm lấy thông số mạng (từ tab SNMPData)
def get_network_stats():
    return get_data_from_sheet("SNMPData")

# Hàm phát hiện thiết bị lạ (từ tab SNMPData)
def get_unauthorized_devices(allowed_devices):
    data = get_data_from_sheet("SNMPData")
    unauthorized = []
    for device in data:
        if (device['ip_address'], device['mac_address']) not in allowed_devices:
            unauthorized.append({
                'ip_address': device['ip_address'],
                'mac_address': device['mac_address'],
                'detected_at': device['timestamp']
            })
    return sorted(unauthorized, key=lambda x: x['detected_at'], reverse=True)

# Hàm lấy SecurityLog
def get_security_logs():
    return get_data_from_sheet("SecurityLog")

# Hàm lấy SystemLog
def get_system_logs():
    return get_data_from_sheet("SystemLog")