"""
Module quản lý cấu hình cho Hệ thống Giám sát Event Log.
Xử lý các biến môi trường và cài đặt hệ thống.
"""
import os
from dotenv import load_dotenv

# Tải các biến môi trường từ file .env
load_dotenv()


class Config:
    """Lớp cấu hình để quản lý biến môi trường và cài đặt."""
    
    # Cài đặt Telegram
    TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN', '')
    TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID', '')
    TELEGRAM_PROXY = {
        'http': os.getenv('TELEGRAM_PROXY_HTTP', ''),
        'https': os.getenv('TELEGRAM_PROXY_HTTPS', '')
    }
    
    # Cài đặt Gmail
    GMAIL_USER = os.getenv('GMAIL_USER', '')
    GMAIL_PASS = os.getenv('GMAIL_PASS', '')
    
    # Cài đặt Google Sheets
    GOOGLE_SHEET_NAME = os.getenv('GOOGLE_SHEET_NAME', 'EventLogData')
    GOOGLE_CREDS_FILE = os.getenv('GOOGLE_CREDS_FILE', 'credentials.json')
    
    @classmethod
    def validate(cls):
        """Xác thực rằng tất cả các biến môi trường bắt buộc đều có mặt."""
        required_vars = [
            'TELEGRAM_TOKEN', 'TELEGRAM_CHAT_ID', 'GMAIL_USER', 
            'GMAIL_PASS', 'GOOGLE_SHEET_NAME', 'GOOGLE_CREDS_FILE'
        ]
        
        missing = []
        for var in required_vars:
            if not getattr(cls, var):
                missing.append(var)
        
        if missing:
            raise ValueError(f"Thiếu các biến môi trường bắt buộc: {', '.join(missing)}")
        
        return True