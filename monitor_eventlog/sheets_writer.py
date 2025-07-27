"""
Google Sheets Writer
Xử lý ghi dữ liệu log vào Google Sheets.
"""

import gspread
from oauth2client.service_account import ServiceAccountCredentials
import time

class GoogleSheetsWriter:
    """Xử lý ghi dữ liệu log vào Google Sheets."""

    def __init__(self, creds_file, sheet_name):
        """
        Khởi tạo Google Sheets writer.
   
        """
        try:
            # Định nghĩa scope cho Google Sheets và Drive API
            scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
            creds = ServiceAccountCredentials.from_json_keyfile_name(creds_file, scope)
            client = gspread.authorize(creds)
            self.sheet = client.open(sheet_name)
            print(f"[THÀNH CÔNG] Đã kết nối đến Google Sheet: {sheet_name}")
        except Exception as e:
            print(f"[LỖI NGHIÊM TRỌNG] Không thể kết nối Google Sheets: {e}")
            raise

    def _check_worksheet_has_data(self, worksheet):
        """
        Kiểm tra worksheet có dữ liệu hay không.
 
        """
        try:
            # Kiểm tra cell A1 có giá trị không
            first_cell = worksheet.cell(1, 1).value
            return bool(first_cell and first_cell.strip())
        except Exception:
            return False

    def _get_worksheet_data_rows(self, worksheet):
        """
        Lấy số dòng có dữ liệu thực tế trong worksheet.
 
        """
        try:
            all_values = worksheet.get_all_values()
            # Đếm từ cuối lên để tìm dòng cuối cùng có dữ liệu
            for i in range(len(all_values) - 1, -1, -1):
                if any(cell.strip() for cell in all_values[i]):
                    return i + 1
            return 0
        except Exception:
            return 0

    def write_logs(self, sheet_tab, logs):
        """
        Ghi logs vào tab worksheet được chỉ định.
       
        """
        if not logs:
            print(f"[CẢNH BÁO] Không có logs để ghi vào {sheet_tab}")
            return

        try:
            worksheet = None
            
            # Bước 1: Lấy hoặc tạo worksheet
            try:
                worksheet = self.sheet.worksheet(sheet_tab)
                print(f"[THÔNG TIN] Đã tìm thấy worksheet: {sheet_tab}")
            except gspread.exceptions.WorksheetNotFound:
                print(f"[THÔNG TIN] Tạo worksheet mới: {sheet_tab}")
                worksheet = self.sheet.add_worksheet(title=sheet_tab, rows=1000, cols=25)
                time.sleep(1)  # Đợi Google tạo worksheet

            # Bước 2: Định nghĩa headers dựa trên loại log
            if sheet_tab == "DoSLog": 
                headers = [
                    'timestamp', 'log_type', 'source', 'event_id', 'type', 'category', 'message', 'mac_address',
                    'threat_level', 'severity_score', 'is_attack', 'cpu_percent', 
                    'memory_percent', 'network_connections', 'indicators_count',
                    'network_bandwidth_mbps', 'unique_ips'
                ]
            elif sheet_tab == "RDPLog":
                headers = [
                    'timestamp', 'log_type', 'source', 'event_id', 'type', 'category', 'message', 'mac_address',
                    'rdp_user', 'rdp_domain', 'rdp_source_ip', 'rdp_full_user', 'detection_method'
                ]
            else:
                # SecurityLog, SystemLog
                headers = ['timestamp', 'log_type', 'source', 'event_id', 'type', 'category', 'message', 'mac_address']

            # Bước 3: Kiểm tra và ghi header 
            has_data = self._check_worksheet_has_data(worksheet)
            if not has_data:
                print(f"[THÔNG TIN] Ghi header cho worksheet trống: {sheet_tab}")
                worksheet.append_row(headers)
                time.sleep(1)  

            # Bước 4: Chuẩn bị dữ liệu để ghi
            rows_to_write = []
            
            for log in logs:
                try:
                    if sheet_tab == "DoSLog":
                        # Xử lý DoS logs - SỬA LỖI
                        dos_info = log.get('dos_info', {})  # SỬA: ddos_info -> dos_info
                        metrics = dos_info.get('metrics', {})
                        
                        row = [
                            log.get('timestamp', ''),
                            log.get('log_type', ''),
                            log.get('source', ''),
                            log.get('event_id', ''),
                            log.get('type', ''),
                            log.get('category', ''),
                            log.get('message', ''),
                            log.get('mac_address', ''),
                            dos_info.get('threat_level', ''),
                            dos_info.get('severity_score', 0),
                            dos_info.get('is_attack', False),
                            metrics.get('cpu_percent', 0),
                            metrics.get('memory_percent', 0),
                            metrics.get('network_connections', 0),
                            len(dos_info.get('indicators', [])),
                            round((metrics.get('network_bytes_in_per_sec', 0) + metrics.get('network_bytes_out_per_sec', 0)) / 1024 / 1024, 2),
                            len(dos_info.get('ip_stats', {}))
                        ]
                        
                    elif sheet_tab == "RDPLog":
                        # Xử lý RDP logs
                        rdp_info = log.get('rdp_info', {})
                        row = [
                            log.get('timestamp', ''),
                            log.get('log_type', ''),
                            log.get('source', ''),
                            log.get('event_id', ''),
                            log.get('type', ''),
                            log.get('category', ''),
                            log.get('message', ''),
                            log.get('mac_address', ''),
                            rdp_info.get('user', ''),
                            rdp_info.get('domain', ''),
                            rdp_info.get('source_ip', ''),
                            rdp_info.get('full_user', ''),
                            rdp_info.get('detection_method', '')
                        ]
                        
                    else:
                        # Xử lý Security, System logs
                        row = [
                            log.get('timestamp', ''),
                            log.get('log_type', ''),
                            log.get('source', ''),
                            log.get('event_id', ''),
                            log.get('type', ''),
                            log.get('category', ''),
                            log.get('message', ''),
                            log.get('mac_address', '')
                        ]
                    
                    # Đảm bảo tất cả values là string
                    row = [str(cell) if cell is not None else '' for cell in row]
                    rows_to_write.append(row)
                    
                except Exception as e:
                    print(f"[LỖI] Xử lý log entry thất bại: {e}")
                    continue

            # Bước 5: Ghi dữ liệu 
            if rows_to_write:
                try:
                    # Ghi tất cả rows cùng lúc thay vì từng dòng
                    worksheet.append_rows(rows_to_write)
                    print(f"[THÀNH CÔNG] Đã ghi {len(rows_to_write)} dòng vào tab '{sheet_tab}'")
                    
                    # Verify bằng cách đếm dòng sau khi ghi
                    time.sleep(2)  # Đợi Google xử lý
                    final_rows = self._get_worksheet_data_rows(worksheet)
                    print(f"[VERIFY] Worksheet '{sheet_tab}' hiện có {final_rows} dòng dữ liệu")
                    
                except Exception as e:
                    print(f"[LỖI] Ghi batch thất bại, thử ghi từng dòng: {e}")
                    # Fallback: ghi từng dòng
                    success_count = 0
                    for row in rows_to_write:
                        try:
                            worksheet.append_row(row)
                            success_count += 1
                            time.sleep(0.5)  # Rate limiting
                        except Exception as row_error:
                            print(f"[LỖI] Ghi dòng thất bại: {row_error}")
                            continue
                    
                    print(f"[THÀNH CÔNG] Đã ghi {success_count}/{len(rows_to_write)} dòng vào tab '{sheet_tab}'")
            else:
                print(f"[CẢNH BÁO] Không có dòng nào hợp lệ để ghi vào {sheet_tab}")

        except Exception as e:
            print(f"[LỖI NGHIÊM TRỌNG] Ghi dữ liệu Google Sheets thất bại: {e}")
            print(f"[CHI TIẾT] Sheet: {sheet_tab}, Logs count: {len(logs)}")

    def test_connection(self):
        """Test kết nối đến Google Sheets."""
        try:
            worksheets = self.sheet.worksheets()
            print(f"[TEST] Kết nối thành công. Tìm thấy {len(worksheets)} worksheets:")
            for ws in worksheets:
                print(f"  - {ws.title}")
            return True
        except Exception as e:
            print(f"[TEST FAILED] Lỗi kết nối: {e}")
            return False
