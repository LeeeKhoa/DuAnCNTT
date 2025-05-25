import gspread
from google.oauth2.service_account import Credentials
from datetime import datetime, timezone, timedelta

# Thiết lập kết nối Google Sheets
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
try:
    creds = Credentials.from_service_account_file('credentials.json', scopes=scope)
    client = gspread.authorize(creds)
    spreadsheet = client.open("EventLogData")
except Exception as e:
    print(f"[ERROR] Không thể kết nối Google Sheets: {e}")
    raise

# Hàm lấy dữ liệu từ sheet
def get_data_from_sheet(sheet_name, max_rows=50):
    try:
        sheet = spreadsheet.worksheet(sheet_name)
        data = sheet.get_all_records()
        # Chuẩn hóa dữ liệu
        standardized_data = []
        for item in data:
            standardized_item = {
                'timestamp': item.get('timestamp', ''),
                'state': item.get('state', 'off'),
                'ip_address': item.get('ip_address', ''),
                'mac_address': item.get('mac_address', ''),
                'network_in_mbps': float(item.get('network_in_mbps', 0)),
                'network_out_mbps': float(item.get('network_out_mbps', 0)),
                'link_speed': float(item.get('link_speed', 0)),
                'cpu_load_percent': float(item.get('cpu_load_percent', 0)),
                'total_ram_mb': float(item.get('total_ram_mb', 0)),
                'used_ram_mb': float(item.get('used_ram_mb', 0)),
                'disk_used_mb': float(item.get('disk_used_mb', 0)),
                'disk_total_mb': float(item.get('disk_total_mb', 0)),
                'log_type': item.get('log_type', ''),
                'source': item.get('source', ''),
                'event_id': int(item.get('event_id', 0)),
                'type': item.get('type', ''),
                'category': item.get('category', ''),
                'message': item.get('message', '')
            }
            standardized_data.append(standardized_item)
        return standardized_data
    except Exception as e:
        print(f"[ERROR] Không thể đọc dữ liệu từ sheet {sheet_name}: {e}")
        return []

# Hàm lấy danh sách thiết bị (đã lọc IP trùng lặp và tính trạng thái online/offline)
def get_devices():
    data = get_data_from_sheet("SNMPData")
    # Sắp xếp theo timestamp để bản ghi mới nhất lên đầu
    sorted_data = sorted(data, key=lambda x: x['timestamp'], reverse=True)
    # Lọc để chỉ giữ bản ghi mới nhất cho mỗi IP
    seen_ips = set()
    filtered_data = []
    # Định nghĩa múi giờ +07:00 (Việt Nam)
    vn_timezone = timezone(timedelta(hours=7))
    for item in sorted_data:
        ip = item['ip_address']
        if ip not in seen_ips:
            seen_ips.add(ip)
            # Tính trạng thái online/offline dựa trên timestamp
            try:
                # Chuyển timestamp thành datetime offset-aware (múi giờ +07:00)
                timestamp = datetime.strptime(item['timestamp'], '%Y-%m-%d %H:%M:%S')
                timestamp = timestamp.replace(tzinfo=vn_timezone)
                # Lấy thời gian hiện tại ở múi giờ +07:00
                current_time = datetime.now(vn_timezone)
                # Tính khoảng cách thời gian
                time_diff = (current_time - timestamp).total_seconds()
                # Nếu bản ghi mới nhất cách hiện tại ≤ 60 giây, coi là online
                item['is_online'] = time_diff <= 60
            except ValueError:
                # Nếu timestamp không hợp lệ, coi là offline
                item['is_online'] = False
            filtered_data.append(item)
    return filtered_data

# Hàm lấy thông số mạng
def get_network_stats(max_rows=50):
    data = get_data_from_sheet("SNMPData", max_rows)
    return sorted(data, key=lambda x: x['timestamp'], reverse=True)

# Hàm phát hiện thiết bị lạ (đã lọc IP trùng lặp)
def get_unauthorized_devices(allowed_devices):
    data = get_data_from_sheet("SNMPData")
    unauthorized = []
    # Sắp xếp theo timestamp để bản ghi mới nhất lên đầu
    sorted_data = sorted(data, key=lambda x: x['timestamp'], reverse=True)
    # Lọc để chỉ giữ bản ghi mới nhất cho mỗi IP
    seen_ips = set()
    filtered_data = []
    for device in sorted_data:
        ip = device['ip_address']
        if ip not in seen_ips:
            seen_ips.add(ip)
            if (device['ip_address'], device['mac_address']) not in allowed_devices:
                filtered_data.append({
                    'ip_address': device['ip_address'],
                    'mac_address': device['mac_address'],
                    'detected_at': device['timestamp']
                })
    return filtered_data

# Hàm lấy SecurityLog
def get_security_logs(max_rows=50):
    return get_data_from_sheet("SecurityLog", max_rows)

# Hàm lấy SystemLog
def get_system_logs(max_rows=50):
    return get_data_from_sheet("SystemLog", max_rows)