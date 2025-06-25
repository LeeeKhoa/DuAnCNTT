import gspread
from google.oauth2.service_account import Credentials
from datetime import datetime, timezone, timedelta

# Thiết lập kết nối Google Sheets
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
try:
    creds = Credentials.from_service_account_file('credentials.json', scopes=scope)
    client = gspread.authorize(creds)
    spreadsheet = client.open("EventLogData")
    users_sheet = spreadsheet.worksheet("Users")  # Sheet lưu tài khoản
    trust_devices_sheet = spreadsheet.worksheet("TrustDevices")  # Sheet lưu thiết bị tin cậy
    blocked_devices_sheet = spreadsheet.worksheet("BlockedDevices")  # Sheet lưu thiết bị bị chặn
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
                'message': item.get('message', ''),
                'rdp_user': item.get('rdp_user', ''),
                'rdp_domain': item.get('rdp_domain', ''),
                'rdp_source_ip': item.get('rdp_source_ip', '')
            }
            standardized_data.append(standardized_item)
        return standardized_data
    except Exception as e:
        print(f"[ERROR] Không thể đọc dữ liệu từ sheet {sheet_name}: {e}")
        return []

# Hàm đọc danh sách MAC address từ tab TrustDevices
def get_trusted_devices():
    try:
        data = trust_devices_sheet.get_all_records()
        trusted_devices = {item['mac_address'].strip().upper(): item.get('device_name', '') for item in data if 'mac_address' in item and item['mac_address']}
        return trusted_devices  # Trả về dict với mac và device_name
    except Exception as e:
        print(f"[ERROR] Không thể đọc dữ liệu từ tab TrustDevices: {e}")
        return {}

# Hàm đọc danh sách MAC address từ tab BlockedDevices
def get_blocked_devices():
    try:
        data = get_data_from_sheet("BlockedDevices")
        blocked_macs = [item['mac_address'].strip().upper() for item in data if 'mac_address' in item and item['mac_address']]
        return set(blocked_macs)
    except Exception as e:
        print(f"[ERROR] Không thể đọc dữ liệu từ tab BlockedDevices: {e}")
        return set()

# Hàm thêm một mac_address vào tab TrustDevices
def add_to_trusted_devices(mac_address, device_name=''):
    try:
        # Lấy tất cả dữ liệu hiện có
        data = trust_devices_sheet.get_all_values()
        # Nếu sheet trống, thêm tiêu đề
        if not data or (len(data) == 1 and not data[0]):
            trust_devices_sheet.append_row(['mac_address', 'device_name'])
        # Thêm mac_address và device_name mới
        mac_address = mac_address.strip().upper()
        if not any(row[0].strip().upper() == mac_address for row in data if row):
            trust_devices_sheet.append_row([mac_address, device_name])
            print(f"[OK] Đã thêm {mac_address} với tên {device_name} vào tab TrustDevices")
        else:
            print(f"[WARNING] {mac_address} đã tồn tại trong tab TrustDevices")
    except gspread.exceptions.APIError as e:
        print(f"[ERROR] Lỗi API khi thêm {mac_address}: {e}")
        raise
    except Exception as e:
        print(f"[ERROR] Không thể thêm {mac_address} vào tab TrustDevices: {e}")
        raise

# Hàm xóa một mac_address khỏi tab TrustDevices
def remove_from_trusted_devices(mac_address):
    try:
        # Lấy tất cả dữ liệu
        data = trust_devices_sheet.get_all_values()
        if not data or (len(data) == 1 and not data[0]):
            print(f"[WARNING] Tab TrustDevices trống, không có gì để xóa.")
            return
        # Tìm hàng chứa mac_address
        mac_address = mac_address.strip().upper()
        row_to_delete = None
        for idx, row in enumerate(data, start=1):
            if row and len(row) > 0 and row[0].strip().upper() == mac_address:
                row_to_delete = idx
                break
        # Xóa hàng nếu tìm thấy
        if row_to_delete:
            trust_devices_sheet.delete_rows(row_to_delete)
            print(f"[OK] Đã xóa {mac_address} khỏi tab TrustDevices")
        else:
            print(f"[WARNING] Không tìm thấy {mac_address} trong tab TrustDevices để xóa.")
    except gspread.exceptions.APIError as e:
        print(f"[ERROR] Lỗi API khi xóa {mac_address}: {e}")
        raise
    except Exception as e:
        print(f"[ERROR] Không thể xóa {mac_address} khỏi tab TrustDevices: {e}")
        raise

# Hàm thêm một mac_address vào tab BlockedDevices
def add_to_blocked_devices(mac_address):
    try:
        # Kiểm tra nếu tab BlockedDevices chưa tồn tại, thì tạo mới
        try:
            sheet = blocked_devices_sheet
        except gspread.exceptions.WorksheetNotFound:
            sheet = spreadsheet.add_worksheet(title="BlockedDevices", rows="100", cols="1")
            sheet.append_row(['mac_address'])
        # Lấy tất cả dữ liệu hiện có
        data = sheet.get_all_values()
        # Thêm mac_address mới
        mac_address = mac_address.strip().upper()
        # Kiểm tra xem mac_address đã tồn tại chưa
        if not any(row[0].strip().upper() == mac_address for row in data if row):
            sheet.append_row([mac_address])
            print(f"[OK] Đã thêm {mac_address} vào tab BlockedDevices")
        else:
            print(f"[WARNING] {mac_address} đã tồn tại trong tab BlockedDevices")
    except gspread.exceptions.APIError as e:
        print(f"[ERROR] Lỗi API khi thêm {mac_address}: {e}")
        raise
    except Exception as e:
        print(f"[ERROR] Không thể thêm {mac_address} vào tab BlockedDevices: {e}")
        raise

# Hàm lấy danh sách thiết bị (đã lọc trùng lặp dựa trên mac_address)
def get_devices():
    data = get_data_from_sheet("SNMPData")
    # Sắp xếp theo timestamp để bản ghi mới nhất lên đầu
    sorted_data = sorted(data, key=lambda x: x['timestamp'], reverse=True)
    # Lọc để chỉ giữ bản ghi mới nhất cho mỗi mac_address
    seen_macs = set()
    filtered_data = []
    # Định nghĩa múi giờ +07:00 (Việt Nam)
    vn_timezone = timezone(timedelta(hours=7))
    # Lấy danh sách thiết bị tin cậy và bị chặn
    trusted_devices = get_trusted_devices()  # Lấy dict mac -> device_name
    blocked_macs = get_blocked_devices()
    for item in sorted_data:
        mac = item['mac_address'].strip().upper()
        if mac not in seen_macs:
            seen_macs.add(mac)
            # Bỏ qua thiết bị nếu bị chặn
            if mac in blocked_macs:
                continue
            # Thêm thông tin trạng thái đăng ký và tên thiết bị
            item['is_trusted'] = mac in trusted_devices
            item['device_name'] = trusted_devices.get(mac, '')  # Lấy device_name từ trusted_devices
            # Tính trạng thái online/offline dựa trên timestamp
            try:
                timestamp = datetime.strptime(item['timestamp'], '%Y-%m-%d %H:%M:%S')
                timestamp = timestamp.replace(tzinfo=vn_timezone)
                current_time = datetime.now(vn_timezone)
                time_diff = (current_time - timestamp).total_seconds()
                item['is_online'] = time_diff <= 180
            except ValueError:
                item['is_online'] = False
            filtered_data.append(item)
    return filtered_data

# Hàm phát hiện thiết bị lạ (đã lọc trùng lặp dựa trên mac_address)
def get_unauthorized_devices():
    data = get_data_from_sheet("SNMPData")
    # Lấy danh sách MAC address từ tab TrustDevices và BlockedDevices
    trusted_macs = get_trusted_devices().keys()  # Lấy các mac từ dict
    blocked_macs = get_blocked_devices()
    unauthorized = []
    # Sắp xếp theo timestamp để bản ghi mới nhất lên đầu
    sorted_data = sorted(data, key=lambda x: x['timestamp'], reverse=True)
    # Lọc để chỉ giữ bản ghi mới nhất cho mỗi mac_address
    seen_macs = set()
    filtered_data = []
    for device in sorted_data:
        mac = device['mac_address'].strip().upper()
        if mac not in seen_macs:
            seen_macs.add(mac)
            # Bỏ qua thiết bị nếu bị chặn
            if mac in blocked_macs:
                continue
            # Kiểm tra nếu mac_address không nằm trong danh sách tin cậy
            if mac not in trusted_macs:
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

# Hàm lấy RDPLog
def get_rdp_logs(max_rows=50):
    return get_data_from_sheet("RDPLog", max_rows)

# Hàm kiểm tra vai trò admin
def check_admin_role(username):
    users = users_sheet.get_all_records()
    for user in users:
        if user['username'] == username and user['role'] == 'admin':
            return True
    return False