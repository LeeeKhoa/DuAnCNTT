# Hệ thống Giám sát Thiết bị Mạng và Sự kiện Windows - Hướng dẫn Triển khai

## Mô tả
Hệ thống này bao gồm ba thành phần chính để giám sát thiết bị mạng, sự kiện Windows, và cung cấp giao diện quản lý:
1. **snmp_monitor_clean**: Giám sát các thiết bị mạng qua giao thức SNMP, thu thập số liệu như CPU, RAM, disk, network, và uptime. Gửi cảnh báo qua Telegram và Gmail khi phát hiện thiết bị offline, vượt ngưỡng (CPU, RAM, disk, network), hoặc địa chỉ MAC không tin cậy. Lưu dữ liệu vào Google Sheets (tab `SNMPData`).
2. **monitor_eventlog**: Giám sát các sự kiện Windows (System, Security, RDP) và phát hiện tấn công DoS. Gửi cảnh báo qua Telegram và Gmail khi phát hiện sự kiện quan trọng (ví dụ: mất điện, đăng nhập thất bại, tấn công DoS) và lưu dữ liệu vào Google Sheets (các tab `SystemLog`, `SecurityLog`, `RDPLog`, `DoSLog`).
3. **network_monitor**: Cung cấp giao diện web (Flask) để hiển thị dữ liệu từ Google Sheets, quản lý thiết bị (đăng ký/chặn/xóa MAC), và hỗ trợ đăng nhập/đăng ký với phân quyền admin/user. Dữ liệu được hiển thị trên các trang dashboard, danh sách thiết bị, thiết bị lạ, và lịch sử log.

Cả ba thành phần sử dụng Google Sheets (`EventLogData`) để lưu trữ dữ liệu, với các tab: `SNMPData`, `SystemLog`, `SecurityLog`, `RDPLog`, `DoSLog`, `Users`, `TrustDevices`, `BlockedDevices`. Cảnh báo được gửi qua Telegram và Gmail.

## Cấu trúc thư mục
### snmp_monitor_clean
- `.env`: Cấu hình biến môi trường (Telegram, Gmail, Proxy, SNMP, Google Sheets).
- `config.py`: Quản lý cấu hình SNMP và xác thực.
- `credentials.json`: Chứng chỉ Google Sheets API.
- `sheets_writer.py`: Ghi dữ liệu vào Google Sheets (tab `SNMPData`).
- `main.py`: Điều phối quét và giám sát SNMP.
- `snmp_monitor.py`: Logic giám sát SNMP, quét mạng, và gửi cảnh báo.
- `Trust_Devices.txt`: Danh sách địa chỉ MAC tin cậy.

### monitor_eventlog
- `.env`: Cấu hình biến môi trường (Telegram, Gmail, Google Sheets).
- `config.py`: Quản lý cấu hình cho giám sát sự kiện.
- `credentials.json`: Chứng chỉ Google Sheets API (có thể dùng chung với `snmp_monitor_clean`).
- `sheets_writer.py`: Ghi dữ liệu vào Google Sheets (các tab `SystemLog`, `SecurityLog`, `RDPLog`, `DoSLog`).
- `main.py`: Điều phối giám sát System, Security, RDP, và DoS.
- `dos_detector.py`: Phát hiện tấn công DoS dựa trên CPU, RAM, và kết nối mạng.
- `dos_detector_state.json`: Lưu trạng thái DoS detector.
- `rdp_eventlog_monitor.py`: Giám sát RDP qua PowerShell.
- `processed_rdp_events.json`: Theo dõi các sự kiện RDP đã xử lý.
- `system_eventlog_monitor.py`: Giám sát System Event Log.
- `security_eventlog_monitor.py`: Giám sát Security Event Log.

### network_monitor
- `.env`: Cấu hình `SECRET_KEY` cho Flask và Google Sheets.
- `sheets.py`: Truy xuất và quản lý dữ liệu từ Google Sheets (`SNMPData`, `SystemLog`, `SecurityLog`, `RDPLog`, `Users`, `TrustDevices`, `BlockedDevices`).
- `app.py`: Ứng dụng Flask với các route cho giao diện và quản lý thiết bị.
- `credentials.json`: Chứng chỉ Google Sheets API (khác với hai thư mục kia).
- **Thư mục `templates`**:
  - `base.html`: Template cơ sở với thanh điều hướng.
  - `index.html`: Dashboard hiển thị số liệu thiết bị (online, offline, thiết bị lạ).
  - `devices.html`: Danh sách thiết bị với thông tin chi tiết.
  - `history_logRDP.html`: Lịch sử log RDP.
  - `unauthorized.html`: Danh sách thiết bị lạ.
  - `security_logs.html`: Hiển thị Security Log.
  - `system_logs.html`: Hiển thị System Log.
  - `device_history.html`: Lịch sử hoạt động của một MAC.
  - `login.html`: Trang đăng nhập.
  - `register.html`: Trang đăng ký tài khoản.

## Yêu cầu
- **Hệ điều hành**: Windows (cho `monitor_eventlog` do sử dụng `win32evtlog` và PowerShell).
- **Python**: 3.8 hoặc mới hơn.
- **Thư viện Python**:
  ```
  pip install pysnmp gspread oauth2client python-dotenv requests urllib3 psutil wmi pywin32 flask
  ```
- **Quyền truy cập**:
  - Quyền admin trên Windows để truy cập Event Log (System, Security) và PowerShell.
  - Quyền truy cập mạng tới các thiết bị SNMP (port 161/UDP).
  - Quyền truy cập internet cho Telegram, Gmail, và Google Sheets.
- **Tệp cấu hình**:
  - Tệp `.env` cho mỗi thư mục (hoặc dùng chung nếu triển khai trong cùng thư mục gốc).
  - Tệp `credentials.json` từ Google Cloud Console (cho Google Sheets API và Drive API).
- **Kết nối mạng**:
  - Proxy (nếu được cấu hình trong `.env`).
  - Port 5000 (hoặc tùy chỉnh) cho Flask server.

## Các bước cài đặt và chạy

### 1. Cài đặt môi trường
- Cài đặt Python 3.8 hoặc mới hơn.
- Cài đặt các thư viện cần thiết:
  ```
  pip install -r requirements.txt
  ```
  Tạo tệp `requirements.txt` với nội dung:
  ```
  pysnmp
  gspread
  oauth2client
  python-dotenv
  requests
  urllib3
  psutil
  wmi
  pywin32
  flask
  ```
- Đảm bảo PowerShell được cài đặt (mặc định trên Windows).

### 2. Cấu hình
- **Tệp `.env`**:
  - Tạo tệp `.env` trong mỗi thư mục (`snmp_monitor_clean`, `monitor_eventlog`, `network_monitor`) hoặc dùng chung nếu triển khai trong cùng thư mục gốc.
  - Nội dung mẫu cho `snmp_monitor_clean` và `monitor_eventlog`:
    ```
    TELEGRAM_TOKEN=your_telegram_bot_token
    TELEGRAM_CHAT_ID=your_chat_id
    TELEGRAM_PROXY_HTTP=socks5h://your_proxy
    TELEGRAM_PROXY_HTTPS=socks5h://your_proxy
    GMAIL_USER=your_email@gmail.com
    GMAIL_PASS=your_app_password
    GOOGLE_SHEET_NAME=EventLogData
    GOOGLE_CREDS_FILE=credentials.json
    SNMP_SUBNET=172.20.10.0/24
    SNMP_COMMUNITY=monitor
    ```
  - Nội dung mẫu cho `network_monitor`:
    ```
    SECRET_KEY=your_flask_secret_key
    GOOGLE_SHEET_NAME=EventLogData
    GOOGLE_CREDS_FILE=credentials.json
    ```
  - Lưu ý: Sử dụng [mật khẩu ứng dụng](https://support.google.com/accounts/answer/185833) cho `GMAIL_PASS`.
- **Tệp `credentials.json`**:
  - Tải từ Google Cloud Console (dự án với Google Sheets API và Drive API được bật).
  - Đặt vào mỗi thư mục hoặc thư mục gốc chung.
  - Lưu ý: `network_monitor` sử dụng `credentials.json` với `project_id: networkmonitor-459712`, khác với `monitor-tools` của hai thư mục kia.
- **Tệp `Trust_Devices.txt`** (cho `snmp_monitor_clean`):
  - Chỉnh sửa để thêm địa chỉ MAC tin cậy, mỗi dòng một địa chỉ (ví dụ: `00:0c:29:a5:90:8b`).
- **Google Sheets** (`EventLogData`):
  - Tạo Google Sheet với tên `EventLogData`.
  - Tạo các tab: `SNMPData`, `SystemLog`, `SecurityLog`, `RDPLog`, `DoSLog`, `Users`, `TrustDevices`, `BlockedDevices`.
  - Chia sẻ Sheet với `client_email` từ `credentials.json` của cả ba thư mục.

### 3. Chạy chương trình
#### a. Chạy `snmp_monitor_clean`
- Di chuyển vào thư mục `snmp_monitor_clean`:
  ```
  cd snmp_monitor_clean
  ```
- Chạy tệp chính:
  ```
  python main.py
  ```
- Quy trình:
  - Quét thiết bị SNMP trong dải mạng (`SNMP_SUBNET`).
  - Thu thập số liệu (CPU, RAM, disk, network, uptime, MAC).
  - Gửi cảnh báo qua Telegram/Gmail nếu vượt ngưỡng hoặc phát hiện thiết bị lạ.
  - Lưu dữ liệu vào Google Sheets (tab `SNMPData`).
- Kết quả:
  - Log console hiển thị tiến độ quét và ghi dữ liệu.
  - Dữ liệu được lưu vào tab `SNMPData`.
  - Cảnh báo được gửi qua Telegram và Gmail.

#### b. Chạy `monitor_eventlog`
- Di chuyển vào thư mục `monitor_eventlog`:
  ```
  cd monitor_eventlog
  ```
- Chạy tệp chính:
  ```
  python main.py
  ```
- Quy trình:
  - Giám sát System Event Log (khởi động, tắt máy, mất điện, dịch vụ).
  - Giám sát Security Event Log (đăng nhập thất bại, tạo/xóa tài khoản, thay đổi quyền).
  - Giám sát RDP qua PowerShell (đăng nhập từ xa).
  - Phát hiện tấn công DoS dựa trên CPU, RAM, và kết nối mạng.
  - Gửi cảnh báo qua Telegram/Gmail.
  - Lưu dữ liệu vào Google Sheets (các tab `SystemLog`, `SecurityLog`, `RDPLog`, `DoSLog`).
- Kết quả:
  - Log console hiển thị tiến độ và thống kê.
  - Dữ liệu được lưu vào các tab tương ứng.
  - Tệp log (`system_monitor.log`, `security_monitor.log`) ghi lại chi tiết hoạt động.

#### c. Chạy `network_monitor`
- Di chuyển vào thư mục `network_monitor`:
  ```
  cd network_monitor
  ```
- Chạy ứng dụng Flask:
  ```
  python app.py
  ```
- Quy trình:
  - Khởi động server Flask (mặc định: `http://127.0.0.1:5000`).
  - Truy cập giao diện web qua trình duyệt:
    - **Dashboard** (`/`): Hiển thị số lượng thiết bị online, offline, và thiết bị lạ.
    - **Danh sách thiết bị** (`/devices`): Hiển thị thông tin thiết bị (MAC, IP, trạng thái, CPU, RAM, disk).
    - **Lịch sử log RDP** (`/history_logRDP`): Hiển thị log RDP.
    - **Thiết bị lạ** (`/unauthorized`): Hiển thị thiết bị không trong danh sách tin cậy.
    - **Security Logs** (`/security_logs`): Hiển thị log bảo mật.
    - **System Logs** (`/system_logs`): Hiển thị log hệ thống.
    - **Lịch sử thiết bị** (`/device_history/<mac>`): Hiển thị lịch sử hoạt động của một MAC.
    - **Đăng nhập** (`/login`): Yêu cầu đăng nhập để truy cập.
    - **Đăng ký** (`/register`): Đăng ký tài khoản (lưu vào tab `Users`).
  - Admin có thể:
    - Đăng ký thiết bị vào `TrustDevices` với tên thiết bị.
    - Xóa thiết bị khỏi `TrustDevices`.
    - Chặn thiết bị (thêm vào `BlockedDevices`).
- Kết quả:
  - Giao diện web hiển thị dữ liệu từ Google Sheets.
  - Các hành động quản lý được lưu vào tab `TrustDevices` hoặc `BlockedDevices`.

### 4. Kiểm tra kết quả
- **Google Sheets** (`EventLogData`):
  - **Tab `SNMPData`**: Dữ liệu từ `snmp_monitor_clean`.
  - **Tab `SystemLog`, `SecurityLog`, `RDPLog`, `DoSLog`**: Dữ liệu từ `monitor_eventlog`.
  - **Tab `Users`**: Tài khoản người dùng (username, hashed password, role).
  - **Tab `TrustDevices`**: Danh sách MAC tin cậy và tên thiết bị.
  - **Tab `BlockedDevices`**: Danh sách MAC bị chặn.
- **Cảnh báo**:
  - Kiểm tra Telegram (nhóm chat) và Gmail để xem thông báo từ `snmp_monitor_clean` và `monitor_eventlog`.
- **Log files**:
  - `system_monitor.log` và `security_monitor.log` trong `monitor_eventlog`.
  - Console output trong cả ba thư mục.
- **Trạng thái**:
  - `dos_detector_state.json`: Lưu trạng thái DoS detector.
  - `processed_rdp_events.json`: Theo dõi sự kiện RDP đã xử lý.
- **Web Interface**:
  - Truy cập `http://127.0.0.1:5000` (hoặc địa chỉ server Flask) để xem giao diện.
  - Đăng nhập với tài khoản từ tab `Users` (admin hoặc user).

### 5. Chạy toàn bộ hệ thống
- **Triển khai riêng lẻ**:
  - Chạy `snmp_monitor_clean/main.py` trong một terminal.
  - Chạy `monitor_eventlog/main.py` trong terminal thứ hai.
  - Chạy `network_monitor/app.py` trong terminal thứ ba.
- **Triển khai chung** (khuyến nghị):
  - Đặt cả ba thư mục trong một thư mục gốc (ví dụ: `network_monitoring_system`).
  - Dùng chung tệp `.env` và `credentials.json` (đảm bảo chia sẻ Google Sheet với cả hai `client_email`).
  - Chạy từng thành phần như trên.
- **Script điều phối** (tùy chọn):
  - Tạo `run_all.py` trong thư mục gốc để chạy cả ba thành phần:
    ```
    import subprocess
    import os
    def run_component(folder, script):
        print(f"Starting {script} in {folder}...")
        return subprocess.Popen(["python", script], cwd=folder)
    if __name__ == "__main__":
        processes = [
            run_component("snmp_monitor_clean", "main.py"),
            run_component("monitor_eventlog", "main.py"),
            run_component("network_monitor", "app.py")
        ]
        for p in processes:
            p.wait()
    ```
  - Chạy: `python run_all.py`

## Lưu ý
- **Hệ điều hành**: `monitor_eventlog` yêu cầu Windows do sử dụng `win32evtlog` và PowerShell.
- **Firewall**: Đảm bảo port 161/UDP mở cho SNMP (`snmp_monitor_clean`) và port 5000 (hoặc tùy chỉnh) cho Flask.
- **Quota API**: Google Sheets API có giới hạn; cơ chế batch trong `sheets_writer.py` và `sheets.py` giúp giảm lỗi.
- **Bảo mật**:
  - Mật khẩu trong tab `Users` được mã hóa bằng MD5 (khuyến nghị nâng cấp lên bcrypt hoặc Argon2).
  - Kiểm tra quyền admin trước khi thực hiện hành động quản lý thiết bị.
- **Cảnh báo trùng lặp**:
  - `snmp_monitor_clean` sử dụng `Trust_Devices.txt` và tab `TrustDevices` để kiểm tra MAC.
  - `monitor_eventlog` sử dụng `processed_rdp_events.json` để tránh gửi cảnh báo RDP trùng.
- **DoS Detection**: Ngưỡng trong `dos_detector.py` (CPU > 70%, RAM > 80%, connections > 500) có thể cần điều chỉnh.
- **Giao diện web**:
  - Đảm bảo thư mục `templates` tồn tại trong `network_monitor`.
  - Biểu đồ trong `system_logs.html` và `security_logs.html` yêu cầu script JavaScript trong `static` (nếu có).

## Xử lý sự cố
- **Lỗi SNMP** (`snmp_monitor_clean`):
  - Kiểm tra `SNMP_SUBNET`, `SNMP_COMMUNITY`, và firewall (port 161/UDP).
  - Đảm bảo thiết bị mục tiêu hỗ trợ SNMP.
- **Lỗi Windows Event Log** (`monitor_eventlog`):
  - Đảm bảo quyền admin để truy cập System/Security Event Log.
  - Kiểm tra PowerShell được cài đặt và có quyền chạy script.
- **Lỗi Google Sheets**:
  - Xác minh `credentials.json`, `GOOGLE_SHEET_NAME`, và quyền chia sẻ Sheet.
  - Kiểm tra kết nối internet và quota Google Sheets API.
- **Lỗi Telegram**:
  - Kiểm tra `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`, và proxy.
- **Lỗi Gmail**:
  - Sử dụng [mật khẩu ứng dụng](https://support.google.com/accounts/answer/185833) cho `GMAIL_PASS`.
  - Kiểm tra kết nối SMTP (`smtp.gmail.com:587`).
- **Lỗi Flask** (`network_monitor`):
  - Kiểm tra `SECRET_KEY` trong `.env`.
  - Đảm bảo các template HTML tồn tại trong `network_monitor/templates`.
  - Kiểm tra quyền truy cập vào tab `Users` trong Google Sheets.
- **Lỗi giao diện web**:
  - Nếu biểu đồ không hiển thị (`system_logs.html`, `security_logs.html`), kiểm tra script JavaScript trong `static` (nếu có).
  - Đảm bảo trình duyệt hỗ trợ HTML5 và JavaScript.

## Liên hệ
- **Email hỗ trợ**: tancang1704@gmail.com
- **Nhóm Telegram**: Liên hệ admin để được thêm vào nhóm.
- **Dự án**: Network Monitoring System - Khoa & Cang