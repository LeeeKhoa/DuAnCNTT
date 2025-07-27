import os
from dotenv import load_dotenv

# Tải biến môi trường từ file .env
load_dotenv()

class Config:
    """Cấu hình tập trung cho hệ thống giám sát SNMP"""
    
    # Cấu hình Telegram
    TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')
    TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
    TELEGRAM_PROXY = {
        'http': os.getenv('PROXY_HTTP'),
        'https': os.getenv('PROXY_HTTPS')
    }
    
    # Cấu hình Gmail
    GMAIL_USER = os.getenv('GMAIL_USER')
    GMAIL_PASSWORD = os.getenv('GMAIL_PASSWORD')
    
    # Cấu hình mạng
    SNMP_SUBNET = os.getenv('SNMP_SUBNET', '172.20.10.0/24')
    SNMP_COMMUNITY = os.getenv('SNMP_COMMUNITY', 'monitor')
    
    # Cấu hình Google Sheets
    GOOGLE_SHEET_NAME = os.getenv('GOOGLE_SHEET_NAME', 'EventLogData')
    GOOGLE_CREDENTIALS_FILE = 'credentials.json'
    
    # Cài đặt ứng dụng
    MAX_WORKERS = 3
    SNMP_TIMEOUT = 2.0
    
    # Cấu hình cảnh báo 
    ALERT_CONFIG = {
        "cpu": {"enabled": True, "threshold": 90, "cooldown_sec": 600},
        "ram": {"enabled": True, "threshold": 90, "cooldown_sec": 600},
        "disk": {"enabled": True, "threshold": 80, "cooldown_sec": 900},
        "uptime": {"enabled": True, "threshold_sec": 600, "cooldown_sec": 1800},
        "network": {"enabled": True, "threshold_percent": 80, "cooldown_sec": 600},
        "offline": {"enabled": True, "cooldown_sec": 60},
        "nohost": {"enabled": True, "cooldown_sec": 600},
    }
    
    @classmethod
    def validate(cls):
        """Kiểm tra cấu hình có đầy đủ không"""
        required = ['TELEGRAM_TOKEN', 'TELEGRAM_CHAT_ID', 'GMAIL_USER', 'GMAIL_PASSWORD']
        missing = [var for var in required if not getattr(cls, var)]
        
        if missing:
            print(f"[LỖI] Thiếu cấu hình: {', '.join(missing)}")
            print("Vui lòng kiểm tra file .env")
            return False
        
        print("[OK] Cấu hình hợp lệ")
        return True

# Kiểm tra cấu hình khi import
if not Config.validate():
    print("Vui lòng cập nhật file .env trước khi chạy ứng dụng")
    exit(1)
