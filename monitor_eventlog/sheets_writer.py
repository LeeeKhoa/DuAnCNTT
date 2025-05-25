import gspread
from oauth2client.service_account import ServiceAccountCredentials

class GoogleSheetsWriter:
    def __init__(self, creds_file, sheet_name):
        scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
        creds = ServiceAccountCredentials.from_json_keyfile_name(creds_file, scope)
        client = gspread.authorize(creds)
        self.sheet = client.open(sheet_name)

    def write_logs(self, sheet_tab, logs):
        try:
            worksheet = None
            try:
                worksheet = self.sheet.worksheet(sheet_tab)
            except gspread.exceptions.WorksheetNotFound:
                worksheet = self.sheet.add_worksheet(title=sheet_tab, rows="1000", cols="20")

            headers = ['timestamp', 'log_type', 'source', 'event_id', 'type', 'category', 'message']
            if worksheet.row_count == 0 or not worksheet.cell(1, 1).value:
                worksheet.append_row(headers)

            for log in logs:
                row = [log.get(h, '') for h in headers]
                worksheet.append_row(row)

            print(f"[OK] Đã ghi {len(logs)} dòng vào tab '{sheet_tab}'")
        except Exception as e:
            print(f"[ERROR] Ghi dữ liệu Google Sheets thất bại: {e}")