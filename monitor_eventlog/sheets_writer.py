"""
Google Sheets Writer.
Xử lý ghi dữ liệu log vào Google Sheets với xử lý lỗi phù hợp.
"""

import gspread
from oauth2client.service_account import ServiceAccountCredentials


class GoogleSheetsWriter:
    """Xử lý ghi dữ liệu log vào Google Sheets."""
    
    def __init__(self, creds_file, sheet_name):
        """
        Khởi tạo Google Sheets writer.
        
        Args:
            creds_file: Đường dẫn đến file JSON credentials của Google service account
            sheet_name: Tên của Google Sheet
        """
        # Định nghĩa scope cho Google Sheets và Drive API
        scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
        creds = ServiceAccountCredentials.from_json_keyfile_name(creds_file, scope)
        client = gspread.authorize(creds)
        self.sheet = client.open(sheet_name)

    def write_logs(self, sheet_tab, logs):
        """
        Ghi logs vào tab worksheet được chỉ định.
        
        Args:
            sheet_tab: Tên của tab worksheet
            logs: Danh sách các entry log cần ghi
        """
        try:
            worksheet = None
            try:
                # Thử lấy worksheet hiện có
                worksheet = self.sheet.worksheet(sheet_tab)
            except gspread.exceptions.WorksheetNotFound:
                # Tạo worksheet mới nếu không tồn tại
                print(f"[THÔNG TIN] Tạo worksheet mới: {sheet_tab}")
                worksheet = self.sheet.add_worksheet(title=sheet_tab, rows="1000", cols="20")

            # Định nghĩa header chuẩn
            headers = ['timestamp', 'log_type', 'source', 'event_id', 'type', 'category', 'message', 'mac_address']
            
            # Thêm header dành riêng cho RDP nếu cần
            if sheet_tab == "RDPLog":
                headers.extend(['rdp_user', 'rdp_domain', 'rdp_source_ip'])

            # Ghi header nếu chưa có
            if worksheet.row_count == 0 or not worksheet.cell(1, 1).value:
                worksheet.append_row(headers)

            # Ghi từng log entry
            for log in logs:
                if sheet_tab == "RDPLog":
                    # Xử lý đặc biệt cho RDP logs
                    rdp_info = log.get('rdp_info', {})
                    row = [log.get(h, '') for h in headers[:8]]  # 8 trường chuẩn đầu tiên
                    row.extend([
                        rdp_info.get('user', '') if rdp_info else '',
                        rdp_info.get('domain', '') if rdp_info else '',
                        rdp_info.get('source_ip', '') if rdp_info else ''
                    ])
                else:
                    # Xử lý cho các logs khác
                    row = [log.get(h, '') for h in headers]
                
                worksheet.append_row(row)

            print(f"[THÀNH CÔNG] Đã ghi {len(logs)} dòng vào tab '{sheet_tab}'")

        except Exception as e:
            print(f"[LỖI] Ghi dữ liệu Google Sheets thất bại: {e}")