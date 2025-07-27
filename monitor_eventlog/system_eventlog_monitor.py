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
        logging.FileHandler('system_monitor.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Định nghĩa các Event ID cần giám sát cho hệ thống 
ALERT_EVENT_IDS = {
    6005: {
        "type": "system_start",
        "severity": "LOW",
        "description": "Hệ thống khởi động"
    },
    6006: {
        "type": "system_shutdown",
        "severity": "LOW", 
        "description": "Hệ thống tắt"
    },
    6008: {
        "type": "unexpected_shutdown",
        "severity": "HIGH",
        "description": "Hệ thống tắt đột ngột"
    },
    41: {
        "type": "power_loss",
        "severity": "CRITICAL",
        "description": "Mất điện"
    },
    7000: {
        "type": "service_failed",
        "severity": "HIGH",
        "description": "Dịch vụ khởi động thất bại"
    },
    7036: {
        "type": "service_status_change",
        "severity": "MEDIUM",
        "description": "Dịch vụ thay đổi trạng thái"
    }
}


def get_mac_address() -> str:
    """
    Lấy địa chỉ MAC của interface mạng đầu tiên được kích hoạt.
    
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


class SystemEventLogMonitor:
    """
    System Event Log Monitor với khả năng phát hiện và cảnh báo.
    
    """
    
    def __init__(self, server: str = 'localhost'):
        """
        Khởi tạo System Event Log Monitor.
        
        """
        logger.info("Initializing System Event Log Monitor...")
        
        # Xác thực cấu hình trước
        try:
            Config.validate()
            logger.info("Configuration validated successfully")
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            raise
        
        self.log_type = 'System'
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
            'critical_events_detected': 0,
            'errors_encountered': 0,
            'last_scan_time': None
        }
        
        logger.info(f"System Monitor initialized for server: {server}")

    def send_telegram_alert(self, message: str) -> bool:
        """
        Gửi cảnh báo qua Telegram.
       
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
        Trích xuất trường từ thông điệp event viewer
     
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

    def process_system_events(self, event_details: List[Dict[str, Any]]) -> None:
        """
        Xử lý các sự kiện hệ thống và gửi cảnh báo chi tiết.
        
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
        """Xử lý từng loại cảnh báo hệ thống với thông tin chi tiết."""
        
        for event in events:
            message = event['message']
            timestamp = event['timestamp']
            event_id = event['event_id']
            source = event['source']
            severity = event['severity']
            description = event['description']
            
            # Tạo thông báo chi tiết dựa trên loại sự kiện
            if alert_type == "system_start":
                msg = (
                    f"🟢 <b>THÔNG BÁO: Hệ thống đã khởi động thành công</b>\n\n"
                    f"⏰ <b>Thời gian khởi động:</b> {timestamp}\n"
                    f"💻 <b>Máy tính:</b> {source}\n"
                    f"🔗 <b>MAC Address:</b> {self.mac_address}\n"
                    f"🆔 <b>Event ID:</b> {event_id}\n"
                    f"🔥 <b>Mức độ:</b> {severity}\n\n"
                    f"✅ <b>Trạng thái:</b> Hệ thống đang hoạt động bình thường\n"
                    f"📝 <b>Chi tiết:</b> {message}"
                )
                self.send_telegram_alert(msg)
                
            elif alert_type == "system_shutdown":
                msg = (
                    f"🔴 <b>THÔNG BÁO: Hệ thống đã được tắt</b>\n\n"
                    f"⏰ <b>Thời gian tắt máy:</b> {timestamp}\n"
                    f"💻 <b>Máy tính:</b> {source}\n"
                    f"🔗 <b>MAC Address:</b> {self.mac_address}\n"
                    f"🆔 <b>Event ID:</b> {event_id}\n"
                    f"🔥 <b>Mức độ:</b> {severity}\n\n"
                    f"📝 <b>Ghi chú:</b> Quá trình tắt máy được thực hiện theo đúng quy trình\n"
                    f"📋 <b>Chi tiết:</b> {message}"
                )
                self.send_telegram_alert(msg)
                
            elif alert_type == "unexpected_shutdown":
                msg = (
                    f"⚠️ <b>CẢNH BÁO: Hệ thống tắt đột ngột không theo quy trình</b>\n\n"
                    f"⏰ <b>Thời gian xảy ra:</b> {timestamp}\n"
                    f"💻 <b>Máy tính:</b> {source}\n"
                    f"🔗 <b>MAC Address:</b> {self.mac_address}\n"
                    f"🆔 <b>Event ID:</b> {event_id}\n"
                    f"🔥 <b>Mức độ:</b> {severity}\n\n"
                    f"🔧 <b>KHUYẾN NGHỊ:</b>\n"
                    f"• Kiểm tra nguyên nhân tắt đột ngột\n"
                    f"• Kiểm tra tình trạng phần cứng\n"
                    f"• Xem xét nguồn điện và UPS\n"
                    f"• Kiểm tra tính toàn vẹn dữ liệu\n\n"
                    f"📋 <b>Chi tiết:</b> {message}"
                )
                self.send_telegram_alert(msg)
                self.send_mail_gmail("⚠️ CẢNH BÁO: Hệ thống tắt đột ngột", msg.replace('<b>', '').replace('</b>', ''))
                
            elif alert_type == "power_loss":
                msg = (
                    f"⚡ <b>CẢNH BÁO NGHIÊM TRỌNG: Hệ thống mất điện hoặc khởi động lại bất thường</b>\n\n"
                    f"⏰ <b>Thời gian xảy ra:</b> {timestamp}\n"
                    f"💻 <b>Máy tính:</b> {source}\n"
                    f"🔗 <b>MAC Address:</b> {self.mac_address}\n"
                    f"🆔 <b>Event ID:</b> {event_id}\n"
                    f"🔥 <b>Mức độ:</b> {severity}\n\n"
                    f"🚨 <b>HÀNH ĐỘNG KHẨN CẤP:</b>\n"
                    f"• Kiểm tra tính toàn vẹn dữ liệu ngay lập tức\n"
                    f"• Kiểm tra trạng thái hệ thống và ứng dụng\n"
                    f"• Xem xét kiểm tra phần cứng và nguồn điện\n"
                    f"• Cân nhắc sử dụng UPS để tránh sự cố tương lai\n"
                    f"• Backup dữ liệu quan trọng\n\n"
                    f"📋 <b>Chi tiết:</b> {message}"
                )
                self.send_telegram_alert(msg)
                self.send_mail_gmail("🚨 KHẨN CẤP: Hệ thống mất điện (Event ID 41)", msg.replace('<b>', '').replace('</b>', ''))
                self.stats['critical_events_detected'] += 1
                
            elif alert_type == "service_failed":
                msg = (
                    f"🚫 <b>CẢNH BÁO: Dịch vụ hệ thống không thể khởi động</b>\n\n"
                    f"⏰ <b>Thời gian:</b> {timestamp}\n"
                    f"💻 <b>Máy tính:</b> {source}\n"
                    f"🔗 <b>MAC Address:</b> {self.mac_address}\n"
                    f"🆔 <b>Event ID:</b> {event_id}\n"
                    f"🔥 <b>Mức độ:</b> {severity}\n\n"
                    f"🔧 <b>KHUYẾN NGHỊ:</b>\n"
                    f"• Kiểm tra và khởi động lại dịch vụ bị lỗi\n"
                    f"• Xem log chi tiết để xác định nguyên nhân\n"
                    f"• Kiểm tra dependencies của dịch vụ\n"
                    f"• Xem xét cấu hình dịch vụ\n\n"
                    f"📋 <b>Chi tiết dịch vụ:</b> {message}"
                )
                self.send_telegram_alert(msg)
                
            elif alert_type == "service_status_change":
                msg = (
                    f"🔄 <b>THÔNG BÁO: Trạng thái dịch vụ hệ thống đã thay đổi</b>\n\n"
                    f"⏰ <b>Thời gian:</b> {timestamp}\n"
                    f"💻 <b>Máy tính:</b> {source}\n"
                    f"🔗 <b>MAC Address:</b> {self.mac_address}\n"
                    f"🆔 <b>Event ID:</b> {event_id}\n"
                    f"🔥 <b>Mức độ:</b> {severity}\n\n"
                    f"📋 <b>Chi tiết thay đổi:</b> {message}\n\n"
                    f"ℹ️ Vui lòng xác minh tính hợp lệ của thay đổi"
                )
                self.send_telegram_alert(msg)
                
            else:
                # Generic alert cho các event không được định nghĩa cụ thể
                msg = (
                    f"🔔 <b>THÔNG BÁO HỆ THỐNG: {description}</b>\n\n"
                    f"⏰ <b>Thời gian:</b> {timestamp}\n"
                    f"💻 <b>Máy tính:</b> {source}\n"
                    f"🔗 <b>MAC Address:</b> {self.mac_address}\n"
                    f"🆔 <b>Event ID:</b> {event_id}\n"
                    f"🔥 <b>Mức độ:</b> {severity}\n\n"
                    f"📋 <b>Chi tiết:</b> {message}"
                )
                self.send_telegram_alert(msg)
            
            logger.info(f"Processed {alert_type} alert for event {event_id}")

    def process_events_batch_alert(self, entries: List[Dict[str, Any]]) -> None:
        """
        Xử lý batch các sự kiện hệ thống và gửi cảnh báo 
        
        """
        logger.info(f"Processing batch of {len(entries)} events...")
        
        # Khởi tạo tracking structures
        system_events = []
        
        # Phân tích từng entry
        for entry in entries:
            try:
                event_id = entry['event_id']
                message = entry['message']
                timestamp = entry['timestamp']
                source = entry.get('source', 'Unknown')
                
                self.stats['total_events_processed'] += 1
                
                # Xử lý các sự kiện hệ thống
                if event_id in ALERT_EVENT_IDS:
                    info = ALERT_EVENT_IDS[event_id]
                    alert_type = info["type"]
                    
                    # Tạo event detail
                    event_detail = {
                        'alert_type': alert_type,
                        'message': message,
                        'timestamp': timestamp,
                        'event_id': event_id,
                        'source': source,
                        'severity': info.get('severity', 'MEDIUM'),
                        'description': info.get('description', alert_type)
                    }
                    
                    system_events.append(event_detail)
                    
            except Exception as e:
                logger.error(f"Error processing entry: {e}")
                logger.debug(f"Problematic entry: {entry}")
                self.stats['errors_encountered'] += 1
                continue
        
        # Xử lý system events
        if system_events:
            logger.info(f"Processing {len(system_events)} system events...")
            self.process_system_events(system_events)
        
        # Cập nhật stats
        self.stats['last_scan_time'] = datetime.datetime.now()
        
        logger.info(f"Batch processing completed. Events: {len(entries)}, Alerts: {len(system_events)}")

    def collect_logs(self, max_entries: int = 20) -> List[Dict[str, Any]]:
        """
        Thu thập logs MỚI NHẤT từ Windows System Event Log.
        
        """
        logger.info(f"Starting log collection (max_entries: {max_entries})...")
        log_entries = []
        
        try:
            # Mở handle đến System Event Log
            handle = win32evtlog.OpenEventLog(self.server, self.log_type)
            

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
            
            #Sắp xếp lại để có thứ tự từ mới nhất đến cũ nhất
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

    def export_to_csv(self, logs: List[Dict[str, Any]], filename: str = 'system_logs.csv') -> bool:
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
            
            logger.info(f"Successfully exported {len(log_entries)} logs to {filename}")
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
            'critical_events_detected': self.stats['critical_events_detected'],
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
        print("📊 SYSTEM MONITOR STATISTICS")
        print("="*60)
        print(f"🔍 Total Events Processed: {stats['total_events_processed']}")
        print(f"🚨 Alerts Sent: {stats['alerts_sent']}")
        print(f"⚡ Critical Events Detected: {stats['critical_events_detected']}")
        print(f"❌ Errors Encountered: {stats['errors_encountered']}")
        print(f"🕐 Last Scan: {stats['last_scan_time'] or 'Never'}")
        print(f"🔗 MAC Address: {stats['mac_address']}")
        print(f"💻 Server: {stats['server']}")
        print("="*60)


def main():
    """Test function cho System Event Log Monitor."""
    try:
        monitor = SystemEventLogMonitor()
        
        print("🔍 Starting System Event Log Monitor Test...")
        logs = monitor.collect_logs(max_entries=10)
        
        if logs:
            print(f"✅ Collected {len(logs)} logs")
            monitor.export_to_csv(logs, 'test_system_logs.csv')
        else:
            print("⚠️ No logs collected")
        
        monitor.print_statistics()
        
    except Exception as e:
        logger.error(f"Error in main: {e}")
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
