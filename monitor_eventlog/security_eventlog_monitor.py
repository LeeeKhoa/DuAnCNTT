import win32evtlog
import csv
import datetime
import requests
import smtplib
import wmi
import logging
import traceback
from email.mime.text import MIMEText
from collections import defaultdict
from typing import Dict, List, Optional, Any, Tuple
from config import Config

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_monitor.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Định nghĩa các Event ID cần giám sát cho bảo mật 
ALERT_EVENT_IDS = {
    4625: {
        "type": "login_failed", 
        "user_idx": 5, 
        "ip_idx": 18,
        "severity": "HIGH",
        "description": "Đăng nhập thất bại"
    },
    4634: {
        "type": "logoff", 
        "user_idx": 5,
        "severity": "LOW",
        "description": "Đăng xuất"
    },
    4720: {
        "type": "add_user", 
        "user_idx": 5,
        "severity": "CRITICAL",
        "description": "Tạo tài khoản mới"
    },
    4722: {
        "type": "enable_user", 
        "user_idx": 5,
        "severity": "MEDIUM",
        "description": "Kích hoạt tài khoản"
    },
    4723: {
        "type": "user_pw_change", 
        "user_idx": 5,
        "severity": "LOW",
        "description": "Đổi mật khẩu người dùng"
    },
    4724: {
        "type": "admin_pw_reset", 
        "user_idx": 5,
        "severity": "HIGH",
        "description": "Admin reset mật khẩu"
    },
    4726: {
        "type": "del_user", 
        "user_idx": 5,
        "severity": "CRITICAL",
        "description": "Xóa tài khoản"
    },
    4732: {
        "type": "add_to_group", 
        "user_idx": 5, 
        "group_idx": 8,
        "severity": "HIGH",
        "description": "Thêm vào nhóm quyền"
    },
    4733: {
        "type": "remove_from_group", 
        "user_idx": 5, 
        "group_idx": 8,
        "severity": "MEDIUM",
        "description": "Xóa khỏi nhóm quyền"
    },
}

# Cấu hình Brute Force Detection
BRUTE_FORCE_CONFIG = {
    "max_attempts": 5,
    "time_window": 600,  # 10 phút
    "event_id": 4625
}


def get_mac_address() -> str:
    """
    Lấy địa chỉ MAC của interface mạng đầu tiên được kích hoạt.
    
    Returns:
        str: Địa chỉ MAC hoặc "Unknown" nếu không lấy được
    """
    try:
        c = wmi.WMI()
        for interface in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            mac = interface.MACAddress
            if mac:
                logger.info(f"Detected MAC address: {mac}")
                return mac
    except Exception as e:
        logger.warning(f"Không lấy được MAC address: {e}")
    return "Unknown"


class SecurityEventLogMonitor:
    def __init__(self, server: str = 'localhost'):
        """
        Khởi tạo Security Event Log Monitor.
        
        Args:
            server: Tên server cần giám sát (mặc định: localhost)
        """
        logger.info("Initializing Security Event Log Monitor...")
        
        # Xác thực cấu hình trước
        try:
            Config.validate()
            logger.info("Configuration validated successfully")
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            raise
        
        self.log_type = 'Security'
        self.server = server
        
        # Tải cấu hình từ biến môi trường
        self.telegram_token = Config.TELEGRAM_TOKEN
        self.telegram_chat_id = Config.TELEGRAM_CHAT_ID
        self.telegram_proxy = Config.TELEGRAM_PROXY
        self.gmail_user = Config.GMAIL_USER
        self.gmail_pass = Config.GMAIL_PASS
        
        # Lấy MAC khi khởi tạo để tái sử dụng
        self.mac_address = get_mac_address()
        
        # Performance tracking
        self.stats = {
            'total_events_processed': 0,
            'alerts_sent': 0,
            'brute_force_detected': 0,
            'errors_encountered': 0,
            'last_scan_time': None
        }
        
        logger.info(f"Security Monitor initialized for server: {server}")

    def send_telegram_alert(self, message: str) -> bool:
        """
        "Gửi cảnh báo qua Telegram 
        
        """
        if not self.telegram_token or not self.telegram_chat_id:
            logger.error("Telegram configuration missing")
            return False
            
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {
            'chat_id': self.telegram_chat_id, 
            'text': message,
            'parse_mode': 'HTML',
            'disable_web_page_preview': True
        }
        
        try:
            response = requests.post(
                url, 
                data=payload, 
                timeout=10, 
                proxies=self.telegram_proxy, 
                verify=False
            )
            
            if response.status_code == 200:
                logger.info("Telegram alert sent successfully")
                self.stats['alerts_sent'] += 1
                return True
            else:
                logger.error(f"Telegram API error: {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.Timeout:
            logger.error("Telegram request timeout")
            return False
        except requests.exceptions.ConnectionError:
            logger.error("Telegram connection error")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending Telegram: {e}")
            return False

    def send_mail_gmail(self, subject: str, body: str, to_email: Optional[str] = None) -> bool:
        """
        Gửi cảnh báo qua Gmail 
        
        """
        if not self.gmail_user or not self.gmail_pass:
            logger.error("Gmail configuration missing")
            return False
            
        if not to_email:
            to_email = self.gmail_user

        try:
            msg = MIMEText(body, 'plain', 'utf-8')
            msg['Subject'] = subject
            msg['From'] = self.gmail_user
            msg['To'] = to_email

            with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                smtp.starttls()
                smtp.login(self.gmail_user, self.gmail_pass)
                smtp.sendmail(self.gmail_user, [to_email], msg.as_string())
                
            logger.info(f"Gmail sent successfully to {to_email}")
            self.stats['alerts_sent'] += 1
            return True
            
        except smtplib.SMTPAuthenticationError:
            logger.error("Gmail authentication failed - check credentials")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending Gmail: {e}")
            return False

    def extract_field(self, parts: List[str], idx: int) -> str:
        """
        Trích xuất trường từ event viewer 
        
        """
        try:
            if 0 <= idx < len(parts):
                result = parts[idx].strip()
                return result if result else "Trống"
            else:
                logger.warning(f"Index {idx} out of range for parts length {len(parts)}")
                return "Index không hợp lệ"
        except Exception as e:
            logger.warning(f"Error extracting field at index {idx}: {e}")
            return "Không rõ"

    def detect_brute_force_attack(self, brute_force_candidates: Dict[Tuple[str, str], List[str]]) -> None:
        """
        Phát hiện tấn công brute force 
        
        """
        for (user, ip), timestamps in brute_force_candidates.items():
            if len(timestamps) < BRUTE_FORCE_CONFIG["max_attempts"]:
                continue
                
            try:
                # Sắp xếp timestamps để đảm bảo thứ tự
                timestamps.sort()
                
                # Kiểm tra 5 lần đầu tiên
                first_attempt = datetime.datetime.strptime(timestamps[0], "%Y-%m-%d %H:%M:%S")
                fifth_attempt = datetime.datetime.strptime(
                    timestamps[BRUTE_FORCE_CONFIG["max_attempts"] - 1], 
                    "%Y-%m-%d %H:%M:%S"
                )
                
                time_diff = (fifth_attempt - first_attempt).total_seconds()
                
                if time_diff <= BRUTE_FORCE_CONFIG["time_window"]:
                    self._send_brute_force_alert(user, ip, timestamps, time_diff)
                    self.stats['brute_force_detected'] += 1
                    
            except ValueError as e:
                logger.error(f"Error parsing timestamps for brute force detection: {e}")
                # Fallback: gửi cảnh báo với thông tin có sẵn
                self._send_brute_force_alert_fallback(user, ip, timestamps)
            except Exception as e:
                logger.error(f"Unexpected error in brute force detection: {e}")

    def _send_brute_force_alert(self, user: str, ip: str, timestamps: List[str], time_diff: float) -> None:
        """Gửi cảnh báo brute force với thông tin chi tiết."""
        msg = (
            f"🚨 <b>CẢNH BÁO: Phát hiện nhiều lần đăng nhập thất bại</b>\n\n"
            f"👤 <b>Tài khoản bị tấn công:</b> {user}\n"
            f"🌐 <b>Địa chỉ IP nguồn:</b> {ip}\n"
            f"⏰ <b>Thời gian bắt đầu:</b> {timestamps[0]}\n"
            f"⏰ <b>Thời gian gần nhất:</b> {timestamps[-1]}\n"
            f"📊 <b>Tổng số lần thử:</b> {len(timestamps)} lần trong {time_diff:.0f} giây\n"
            f"🔗 <b>MAC Address:</b> {self.mac_address}\n\n"
            f"⚡ <b>KHUYẾN NGHỊ KHẨN CẤP:</b>\n"
            f"• Khóa tài khoản {user} ngay lập tức\n"
            f"• Chặn IP {ip} tại firewall\n"
            f"• Kiểm tra log chi tiết\n"
            f"• Thông báo cho team bảo mật"
        )
        
        self.send_telegram_alert(msg)
        self.send_mail_gmail("🚨 KHẨN CẤP: Phát hiện nhiều lần đăng nhập thất bại", msg.replace('<b>', '').replace('</b>', ''))
        
        logger.critical(f"Brute force attack detected: {user} from {ip} - {len(timestamps)} attempts")

    def _send_brute_force_alert_fallback(self, user: str, ip: str, timestamps: List[str]) -> None:
        """Gửi cảnh báo brute force fallback khi có lỗi parse timestamp."""
        msg = (
            f"🚨 <b>CẢNH BÁO: Phát hiện nhiều lần đăng nhập thất bại</b>\n\n"
            f"👤 <b>Tài khoản bị tấn công:</b> {user}\n"
            f"🌐 <b>Địa chỉ IP nguồn:</b> {ip}\n"
            f"⏰ <b>Thời gian gần nhất:</b> {timestamps[-1]}\n"
            f"📊 <b>Tổng số lần thử:</b> {len(timestamps)} lần\n"
            f"🔗 <b>MAC Address:</b> {self.mac_address}\n\n"
            f"⚡ <b>KHUYẾN NGHỊ:</b> Khóa tài khoản và chặn IP ngay lập tức"
        )
        
        self.send_telegram_alert(msg)
        self.send_mail_gmail("🚨 KHẨN CẤP: Phát hiện tấn công brute force", msg.replace('<b>', '').replace('</b>', ''))

    def process_security_events(self, event_details: List[Dict[str, Any]]) -> None:
        """
        Xử lý các sự kiện bảo mật và gửi cảnh báo chi tiết.
        
        """
        # Nhóm events theo loại
        events_by_type = defaultdict(list)
        
        for event in event_details:
            alert_type = event['alert_type']
            events_by_type[alert_type].append(event)
        
        # Xử lý từng loại event
        for alert_type, events in events_by_type.items():
            try:
                self._process_alert_type(alert_type, events)
            except Exception as e:
                logger.error(f"Error processing alert type {alert_type}: {e}")
                self.stats['errors_encountered'] += 1

    def _process_alert_type(self, alert_type: str, events: List[Dict[str, Any]]) -> None:
        """Xử lý từng loại cảnh báo với thông tin chi tiết."""
        
        for event in events:
            user = event['user']
            group = event.get('group', '')
            timestamp = event['timestamp']
            event_id = event['event_id']
            source = event['source']
            severity = event['severity']
            description = event['description']
            
            # Tạo thông báo chi tiết dựa trên loại sự kiện
            if alert_type == "logoff":
                msg = (
                    f"🚪 <b>THÔNG BÁO: Người dùng đã đăng xuất</b>\n\n"
                    f"👤 <b>Tài khoản:</b> {user}\n"
                    f"⏰ <b>Thời gian:</b> {timestamp}\n"
                    f"💻 <b>Máy tính:</b> {source}\n"
                    f"🔗 <b>MAC Address:</b> {self.mac_address}\n"
                    f"🆔 <b>Event ID:</b> {event_id}\n\n"
                    f"ℹ️ Đây là hoạt động bình thường của hệ thống"
                )
                self.send_telegram_alert(msg)
                
            elif alert_type == "add_user":
                msg = (
                    f"➕ <b>CẢNH BÁO QUAN TRỌNG: Tài khoản người dùng mới được tạo</b>\n\n"
                    f"👤 <b>Tài khoản mới:</b> {user}\n"
                    f"⏰ <b>Thời gian tạo:</b> {timestamp}\n"
                    f"💻 <b>Máy tính thực hiện:</b> {source}\n"
                    f"🔗 <b>MAC Address:</b> {self.mac_address}\n"
                    f"🆔 <b>Event ID:</b> {event_id}\n"
                    f"🔥 <b>Mức độ:</b> {severity}\n\n"
                    f"⚠️ <b>KHUYẾN NGHỊ:</b>\n"
                    f"• Xác minh tính hợp lệ của việc tạo tài khoản\n"
                    f"• Kiểm tra quyền hạn của người thực hiện\n"
                    f"• Đảm bảo tuân thủ chính sách bảo mật\n"
                    f"• Ghi nhận vào hệ thống quản lý tài khoản"
                )
                self.send_telegram_alert(msg)
                # Gửi email cho sự kiện quan trọng
                self.send_mail_gmail("➕ CẢNH BÁO: Tài khoản mới được tạo", msg.replace('<b>', '').replace('</b>', ''))
                
            elif alert_type == "del_user":
                msg = (
                    f"❌ <b>CẢNH BÁO NGHIÊM TRỌNG: Tài khoản người dùng đã bị xóa</b>\n\n"
                    f"👤 <b>Tài khoản bị xóa:</b> {user}\n"
                    f"⏰ <b>Thời gian xóa:</b> {timestamp}\n"
                    f"💻 <b>Máy tính thực hiện:</b> {source}\n"
                    f"🔗 <b>MAC Address:</b> {self.mac_address}\n"
                    f"🆔 <b>Event ID:</b> {event_id}\n"
                    f"🔥 <b>Mức độ:</b> {severity}\n\n"
                    f"🚨 <b>HÀNH ĐỘNG CẦN THIẾT:</b>\n"
                    f"• Kiểm tra ngay quyền thực hiện\n"
                    f"• Xác minh tính hợp lệ của việc xóa\n"
                    f"• Backup dữ liệu nếu cần thiết\n"
                    f"• Báo cáo cho quản trị viên cấp cao\n"
                    f"• Ghi nhận vào log bảo mật"
                )
                self.send_telegram_alert(msg)
                self.send_mail_gmail("❌ CẢNH BÁO NGHIÊM TRỌNG: Tài khoản bị xóa", msg.replace('<b>', '').replace('</b>', ''))
                
            elif alert_type == "admin_pw_reset":
                msg = (
                    f"🔐 <b>CẢNH BÁO BẢO MẬT: Quản trị viên đã đặt lại mật khẩu</b>\n\n"
                    f"👤 <b>Tài khoản được reset:</b> {user}\n"
                    f"⏰ <b>Thời gian thực hiện:</b> {timestamp}\n"
                    f"💻 <b>Máy tính thực hiện:</b> {source}\n"
                    f"🔗 <b>MAC Address:</b> {self.mac_address}\n"
                    f"🆔 <b>Event ID:</b> {event_id}\n"
                    f"🔥 <b>Mức độ:</b> {severity}\n\n"
                    f"⚠️ <b>KIỂM TRA CẦN THIẾT:</b>\n"
                    f"• Xác minh danh tính người thực hiện\n"
                    f"• Đảm bảo có quyền hạn hợp lệ\n"
                    f"• Thông báo cho chủ tài khoản\n"
                    f"• Ghi nhận vào log bảo mật\n"
                    f"• Yêu cầu đổi mật khẩu ngay"
                )
                self.send_telegram_alert(msg)
                self.send_mail_gmail("🔐 CẢNH BÁO: Admin reset mật khẩu", msg.replace('<b>', '').replace('</b>', ''))
                
            elif alert_type == "enable_user":
                msg = (
                    f"✅ <b>THÔNG BÁO BẢO MẬT: Tài khoản người dùng được kích hoạt</b>\n\n"
                    f"👤 <b>Tài khoản:</b> {user}\n"
                    f"⏰ <b>Thời gian kích hoạt:</b> {timestamp}\n"
                    f"💻 <b>Máy tính thực hiện:</b> {source}\n"
                    f"🔗 <b>MAC Address:</b> {self.mac_address}\n"
                    f"🆔 <b>Event ID:</b> {event_id}\n"
                    f"🔥 <b>Mức độ:</b> {severity}\n\n"
                    f"ℹ️ Vui lòng xác minh tính hợp lệ của việc kích hoạt"
                )
                self.send_telegram_alert(msg)
                
            elif alert_type == "user_pw_change":
                msg = (
                    f"🔑 <b>THÔNG BÁO: Người dùng đã thay đổi mật khẩu</b>\n\n"
                    f"👤 <b>Tài khoản:</b> {user}\n"
                    f"⏰ <b>Thời gian thay đổi:</b> {timestamp}\n"
                    f"💻 <b>Máy tính:</b> {source}\n"
                    f"🔗 <b>MAC Address:</b> {self.mac_address}\n"
                    f"🆔 <b>Event ID:</b> {event_id}\n\n"
                    f"ℹ️ Đây là hoạt động bảo mật bình thường"
                )
                self.send_telegram_alert(msg)
                
            elif alert_type == "add_to_group":
                msg = (
                    f"👥 <b>CẢNH BÁO QUAN TRỌNG: Người dùng được thêm vào nhóm quyền</b>\n\n"
                    f"👤 <b>Người dùng:</b> {user}\n"
                    f"👥 <b>Nhóm:</b> {group}\n"
                    f"⏰ <b>Thời gian:</b> {timestamp}\n"
                    f"💻 <b>Máy tính:</b> {source}\n"
                    f"🔗 <b>MAC Address:</b> {self.mac_address}\n"
                    f"🆔 <b>Event ID:</b> {event_id}\n"
                    f"🔥 <b>Mức độ:</b> {severity}\n\n"
                    f"⚠️ <b>KIỂM TRA CẦN THIẾT:</b>\n"
                    f"• Xác minh quyền hạn được cấp\n"
                    f"• Đảm bảo tuân thủ chính sách\n"
                    f"• Ghi nhận vào hệ thống quản lý quyền"
                )
                self.send_telegram_alert(msg)
                
            elif alert_type == "remove_from_group":
                msg = (
                    f"👤 <b>THÔNG BÁO: Người dùng bị loại khỏi nhóm quyền</b>\n\n"
                    f"👤 <b>Người dùng:</b> {user}\n"
                    f"👥 <b>Nhóm:</b> {group}\n"
                    f"⏰ <b>Thời gian:</b> {timestamp}\n"
                    f"💻 <b>Máy tính:</b> {source}\n"
                    f"🔗 <b>MAC Address:</b> {self.mac_address}\n"
                    f"🆔 <b>Event ID:</b> {event_id}\n"
                    f"🔥 <b>Mức độ:</b> {severity}\n\n"
                    f"ℹ️ Vui lòng xác minh tính hợp lệ của thay đổi quyền"
                )
                self.send_telegram_alert(msg)
                
            else:
                # Generic alert cho các event không được định nghĩa cụ thể
                msg = (
                    f"🔔 <b>THÔNG BÁO BẢO MẬT: {description}</b>\n\n"
                    f"👤 <b>Người dùng:</b> {user}\n"
                    f"⏰ <b>Thời gian:</b> {timestamp}\n"
                    f"💻 <b>Máy tính:</b> {source}\n"
                    f"🔗 <b>MAC Address:</b> {self.mac_address}\n"
                    f"🆔 <b>Event ID:</b> {event_id}\n"
                    f"🔥 <b>Mức độ:</b> {severity}\n\n"
                    f"📋 <b>Chi tiết:</b> {alert_type}"
                )
                self.send_telegram_alert(msg)
            
            logger.info(f"Processed {alert_type} alert for user {user}")

    def process_events_batch_alert(self, entries: List[Dict[str, Any]]) -> None:
        """
        Xử lý batch các sự kiện bảo mật 
        
        """
        logger.info(f"Processing batch of {len(entries)} events...")
        
        # Khởi tạo tracking structures
        brute_force_candidates = defaultdict(list)
        security_events = []
        
        # Phân tích từng entry
        for entry in entries:
            try:
                event_id = entry['event_id']
                message = entry['message']
                timestamp = entry['timestamp']
                source = entry.get('source', 'Unknown')
                parts = message.split('|')
                
                self.stats['total_events_processed'] += 1
                
                # Xử lý tất cả events trong ALERT_EVENT_IDS
                if event_id in ALERT_EVENT_IDS:
                    info = ALERT_EVENT_IDS[event_id]
                    alert_type = info["type"]
                    user = self.extract_field(parts, info.get("user_idx", 5))
                    group = self.extract_field(parts, info.get("group_idx", -1)) if "group_idx" in info else None
                    
                    # Tạo event detail
                    event_detail = {
                        'alert_type': alert_type,
                        'user': user,
                        'group': group,
                        'timestamp': timestamp,
                        'event_id': event_id,
                        'source': source,
                        'severity': info.get('severity', 'MEDIUM'),
                        'description': info.get('description', alert_type)
                    }
                    
                    security_events.append(event_detail)
                    
                    # Nếu là event 4625, cũng thêm vào brute force candidates
                    if event_id == BRUTE_FORCE_CONFIG["event_id"]:
                        ip = self.extract_field(parts, info.get("ip_idx", 18))
                        key = (user, ip)
                        brute_force_candidates[key].append(timestamp)
                        
            except Exception as e:
                logger.error(f"Error processing entry: {e}")
                logger.debug(f"Problematic entry: {entry}")
                self.stats['errors_encountered'] += 1
                continue
        
        # Phát hiện brute force attacks
        if brute_force_candidates:
            logger.info(f"Analyzing {len(brute_force_candidates)} potential brute force patterns...")
            self.detect_brute_force_attack(brute_force_candidates)
        
        # Xử lý security events
        if security_events:
            logger.info(f"Processing {len(security_events)} security events...")
            self.process_security_events(security_events)
        
        # Cập nhật stats
        self.stats['last_scan_time'] = datetime.datetime.now()
        
        logger.info(f"Batch processing completed. Events: {len(entries)}, Alerts: {len(security_events)}")

    def collect_logs(self, max_entries: int = 20) -> List[Dict[str, Any]]:
        """
        Thu thập logs MỚI NHẤT từ Windows Security Event Log 
        
        """
        logger.info(f"Starting log collection (max_entries: {max_entries})...")
        log_entries = []
        
        try:
            # Mở handle đến Security Event Log
            handle = win32evtlog.OpenEventLog(self.server, self.log_type)
            
            # SỬA LỖI: Đọc BACKWARDS để lấy events mới nhất
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            count = 0
            while count < max_entries:
                try:
                    # Đọc các event từ log (backwards = mới nhất trước)
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not events: 
                        logger.info("No more events to read")
                        break

                    for event in events:
                        if count >= max_entries:
                            break
                            
                        try:
                            # Định dạng timestamp với error handling
                            ts = event.TimeGenerated.Format()
                            try:
                                datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                            except ValueError:
                                ts = str(event.TimeGenerated)

                            # Tạo entry log với validation
                            entry = {
                                'timestamp': ts,
                                'source': event.SourceName or 'Unknown',
                                'event_id': event.EventID & 0xFFFF,
                                'type': event.EventType,
                                'category': event.EventCategory,
                                'log_type': self.log_type,
                                'message': ' | '.join(event.StringInserts) if event.StringInserts else '',
                                'mac_address': self.mac_address
                            }

                            log_entries.append(entry)
                            count += 1
                            
                        except Exception as e:
                            logger.warning(f"Error processing individual event: {e}")
                            continue

                except Exception as e:
                    logger.error(f"Error reading event batch: {e}")
                    break

            # Đóng handle
            win32evtlog.CloseEventLog(handle)
            

            log_entries.sort(key=lambda x: x['timestamp'], reverse=True)
            
            logger.info(f"Successfully collected {len(log_entries)} LATEST log entries")

        except Exception as e:
            logger.error(f"Critical error in log collection: {e}")
            logger.debug(traceback.format_exc())
            self.stats['errors_encountered'] += 1

        # Xử lý cảnh báo nếu có entries
        if log_entries:
            try:
                self.process_events_batch_alert(log_entries)
            except Exception as e:
                logger.error(f"Error in batch alert processing: {e}")
                self.stats['errors_encountered'] += 1

        return log_entries

    def export_to_csv(self, logs: List[Dict[str, Any]], filename: str = 'security_logs.csv') -> bool:
        """
        Xuất logs ra file CSV 
 
        """
        if not logs:
            logger.warning("No logs to export")
            return False
            
        try:
            fieldnames = ['timestamp', 'log_type', 'source', 'event_id', 'type', 'category', 'message', 'mac_address']
            
            with open(filename, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                
                # Write header nếu file mới
                if f.tell() == 0:
                    writer.writeheader()
                    
                for log in logs:
                    try:
                        writer.writerow(log)
                    except Exception as e:
                        logger.warning(f"Error writing log entry to CSV: {e}")
                        continue
            
            logger.info(f"Successfully exported {len(logs)} logs to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """
        Lấy thống kê hoạt động của monitor.
        
        """
        return {
            'total_events_processed': self.stats['total_events_processed'],
            'alerts_sent': self.stats['alerts_sent'],
            'brute_force_detected': self.stats['brute_force_detected'],
            'errors_encountered': self.stats['errors_encountered'],
            'last_scan_time': self.stats['last_scan_time'].isoformat() if self.stats['last_scan_time'] else None,
            'mac_address': self.mac_address,
            'server': self.server,
            'log_type': self.log_type
        }

    def print_statistics(self) -> None:
        """In thống kê hoạt động."""
        stats = self.get_statistics()
        
        print("\n" + "="*60)
        print("📊 SECURITY MONITOR STATISTICS")
        print("="*60)
        print(f"🔍 Total Events Processed: {stats['total_events_processed']}")
        print(f"🚨 Alerts Sent: {stats['alerts_sent']}")
        print(f"⚡ Brute Force Detected: {stats['brute_force_detected']}")
        print(f"❌ Errors Encountered: {stats['errors_encountered']}")
        print(f"🕐 Last Scan: {stats['last_scan_time'] or 'Never'}")
        print(f"🔗 MAC Address: {stats['mac_address']}")
        print(f"💻 Server: {stats['server']}")
        print("="*60)


# Test function 
def main():
    """Test function cho Security Event Log Monitor."""
    try:
        monitor = SecurityEventLogMonitor()
        
        print("🔍 Starting Security Event Log Monitor Test...")
        logs = monitor.collect_logs(max_entries=10)
        
        if logs:
            print(f"✅ Collected {len(logs)} logs")
            monitor.export_to_csv(logs, 'test_security_logs.csv')
        else:
            print("⚠️ No logs collected")
        
        monitor.print_statistics()
        
    except Exception as e:
        logger.error(f"Error in main: {e}")
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
