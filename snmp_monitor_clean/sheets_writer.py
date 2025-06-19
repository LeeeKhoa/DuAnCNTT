import gspread
from oauth2client.service_account import ServiceAccountCredentials
import time
from datetime import datetime

class GoogleSheetsWriter:
    def __init__(self, creds_file, sheet_name):
        """Initialize Google Sheets connection với error handling"""
        try:
            scope = [
                "https://www.googleapis.com/auth/spreadsheets",
                "https://www.googleapis.com/auth/drive"
            ]
            
            creds = ServiceAccountCredentials.from_json_keyfile_name(creds_file, scope)
            client = gspread.authorize(creds)
            self.sheet = client.open(sheet_name)
            print(f"[OK] Kết nối Google Sheets '{sheet_name}' thành công")
            
        except FileNotFoundError:
            raise Exception(f"Không tìm thấy file credentials: {creds_file}")
        except gspread.exceptions.SpreadsheetNotFound:
            raise Exception(f"Không tìm thấy Google Sheet: {sheet_name}")
        except Exception as e:
            raise Exception(f"Lỗi kết nối Google Sheets: {e}")

    def write_logs_batch(self, sheet_tab, logs_list):
        """Batch write - ghi nhiều dòng cùng lúc"""
        try:
            if not logs_list:
                print("[WARN] Không có dữ liệu để ghi")
                return False
            
            # Tạo hoặc lấy worksheet
            try:
                worksheet = self.sheet.worksheet(sheet_tab)
            except gspread.exceptions.WorksheetNotFound:
                print(f"[INFO] Tạo worksheet mới: {sheet_tab}")
                worksheet = self.sheet.add_worksheet(title=sheet_tab, rows="1000", cols="20")

            # Lấy headers từ record đầu tiên
            headers = list(logs_list[0].keys())
            
            # Kiểm tra và thêm headers nếu cần
            try:
                existing_headers = worksheet.row_values(1)
                if not existing_headers or existing_headers != headers:
                    worksheet.clear()
                    worksheet.append_row(headers)
                    print(f"[INFO] Đã thêm headers: {headers}")
            except Exception:
                worksheet.append_row(headers)
                print(f"[INFO] Đã thêm headers: {headers}")

            # Chuẩn bị dữ liệu batch
            batch_data = []
            for log in logs_list:
                row = []
                for header in headers:
                    value = log.get(header, '')
                    # Convert các kiểu dữ liệu đặc biệt
                    if isinstance(value, (int, float)):
                        row.append(str(value))
                    elif value is None:
                        row.append('')
                    else:
                        row.append(str(value))
                batch_data.append(row)

            # Batch update
            if batch_data:
                start_row = worksheet.row_count + 1
                end_row = start_row + len(batch_data) - 1
                
                # Tính toán range
                end_col_letter = chr(ord('A') + len(headers) - 1)
                cell_range = f'A{start_row}:{end_col_letter}{end_row}'
                
                # Thực hiện batch update
                worksheet.batch_update([{
                    'range': cell_range,
                    'values': batch_data
                }])
                
                print(f"[OK] Batch write {len(batch_data)} dòng vào tab '{sheet_tab}'")
                return True
                
        except Exception as e:
            print(f"[ERROR] Batch write thất bại: {e}")
            # Fallback to individual writes
            return self.write_logs_fallback(sheet_tab, logs_list)

    def write_logs_fallback(self, sheet_tab, logs_list):
        """Fallback method - ghi từng dòng nếu batch thất bại"""
        print("[INFO] Chuyển sang fallback mode - ghi từng dòng...")
        success_count = 0
        
        for i, log in enumerate(logs_list):
            try:
                if self.write_logs(sheet_tab, [log]):
                    success_count += 1
                time.sleep(0.2)  # Rate limiting
                
                if (i + 1) % 10 == 0:
                    print(f"[PROGRESS] Đã ghi {i + 1}/{len(logs_list)} dòng...")
                    
            except Exception as e:
                print(f"[ERROR] Ghi dòng {i+1} thất bại: {e}")
        
        print(f"[OK] Fallback write hoàn thành: {success_count}/{len(logs_list)} thành công")
        return success_count > 0

    def write_logs(self, sheet_tab, logs):
        """Method gốc - ghi single hoặc multiple logs"""
        try:
            if not logs:
                return False
                
            # Tạo hoặc lấy worksheet
            try:
                worksheet = self.sheet.worksheet(sheet_tab)
            except gspread.exceptions.WorksheetNotFound:
                worksheet = self.sheet.add_worksheet(title=sheet_tab, rows="1000", cols="20")

            # Process từng log
            for log in logs:
                if not isinstance(log, dict):
                    continue
                    
                # Thêm timestamp nếu chưa có
                if 'timestamp' not in log:
                    log['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                # Lấy headers
                headers = list(log.keys())
                
                # Kiểm tra và thêm headers nếu cần
                try:
                    existing_headers = worksheet.row_values(1)
                    if not existing_headers:
                        worksheet.append_row(headers)
                except Exception:
                    worksheet.append_row(headers)
                
                # Chuẩn bị row data
                row_data = []
                for header in headers:
                    value = log.get(header, '')
                    if isinstance(value, (int, float)):
                        row_data.append(str(value))
                    elif value is None:
                        row_data.append('')
                    else:
                        row_data.append(str(value))
                
                # Append row
                worksheet.append_row(row_data)
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Write logs thất bại: {e}")
            return False

    def get_worksheet_data(self, sheet_tab, limit=100):
        """Utility method để đọc dữ liệu từ worksheet"""
        try:
            worksheet = self.sheet.worksheet(sheet_tab)
            records = worksheet.get_all_records()
            return records[-limit:] if limit else records
        except Exception as e:
            print(f"[ERROR] Đọc dữ liệu thất bại: {e}")
            return []

    def clear_worksheet(self, sheet_tab):
        """Utility method để xóa toàn bộ dữ liệu worksheet"""
        try:
            worksheet = self.sheet.worksheet(sheet_tab)
            worksheet.clear()
            print(f"[OK] Đã xóa toàn bộ dữ liệu worksheet '{sheet_tab}'")
            return True
        except Exception as e:
            print(f"[ERROR] Xóa worksheet thất bại: {e}")
            return False
