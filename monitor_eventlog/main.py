import sys
import traceback
from typing import Optional

# Import các module cần thiết 
try:
    from config import Config
except ImportError as e:
    print(f"[LỖI NGHIÊM TRỌNG] Không thể import config: {e}")
    sys.exit(1)

try:
    from system_eventlog_monitor import SystemEventLogMonitor
except ImportError as e:
    print(f"[CẢNH BÁO] Không thể import SystemEventLogMonitor: {e}")
    SystemEventLogMonitor = None

try:
    from security_eventlog_monitor import SecurityEventLogMonitor
except ImportError as e:
    print(f"[CẢNH BÁO] Không thể import SecurityEventLogMonitor: {e}")
    SecurityEventLogMonitor = None

try:
    from rdp_eventlog_monitor import RDPPowerShellMonitor as RDPEventLogMonitor
except ImportError as e:
    print(f"[CẢNH BÁO] Không thể import RDPEventLogMonitor: {e}")
    RDPEventLogMonitor = None

try:
    from dos_detector import DoSDetector
except ImportError as e:
    print(f"[CẢNH BÁO] Không thể import DoSDetector: {e}")
    DoSDetector = None

try:
    from sheets_writer import GoogleSheetsWriter
except ImportError as e:
    print(f"[LỖI NGHIÊM TRỌNG] Không thể import GoogleSheetsWriter: {e}")
    sys.exit(1)


class EventLogMonitorApp:
    """Ứng dụng chính cho hệ thống giám sát Event Log với DoS Detection."""
    
    def __init__(self):
        """Khởi tạo ứng dụng."""
        self.writer: Optional[GoogleSheetsWriter] = None
        self.dos_detector: Optional[DoSDetector] = None
        
        self.monitors_available = {
            'system': SystemEventLogMonitor is not None,
            'security': SecurityEventLogMonitor is not None,
            'rdp': RDPEventLogMonitor is not None,
            'dos': DoSDetector is not None
        }
    
    def _validate_config(self) -> bool:
        """Xác thực cấu hình hệ thống."""
        try:
            Config.validate()
            print("[THÀNH CÔNG] Đã xác thực cấu hình hệ thống")
            return True
        except ValueError as e:
            print(f"[LỖI CẤU HÌNH] {e}")
            print("[HƯỚNG DẪN] Vui lòng kiểm tra file .env và đảm bảo tất cả biến môi trường được cấu hình đúng")
            return False
        except Exception as e:
            print(f"[LỖI] Lỗi không xác định khi xác thực cấu hình: {e}")
            return False
    
    def _initialize_sheets_writer(self) -> bool:
        """Khởi tạo Google Sheets writer."""
        try:
            self.writer = GoogleSheetsWriter(Config.GOOGLE_CREDS_FILE, Config.GOOGLE_SHEET_NAME)
            print("[THÀNH CÔNG] Đã khởi tạo Google Sheets writer")
            return True
        except FileNotFoundError:
            print(f"[LỖI] Không tìm thấy file credentials: {Config.GOOGLE_CREDS_FILE}")
            print("[HƯỚNG DẪN] Vui lòng đảm bảo file credentials.json tồn tại trong thư mục dự án")
            return False
        except Exception as e:
            print(f"[LỖI] Không thể khởi tạo Google Sheets writer: {e}")
            print("[HƯỚNG DẪN] Kiểm tra kết nối internet và quyền truy cập Google Sheets")
            return False
    
    def _initialize_dos_detector(self) -> bool:
        """Khởi tạo DoS Detector."""
        if not self.monitors_available['dos']:
            print("[CẢNH BÁO] DoS Detector không khả dụng")
            return False
        
        try:
            self.dos_detector = DoSDetector()
            print("[THÀNH CÔNG] Đã khởi tạo DoS Detector")
            return True
        except Exception as e:
            print(f"[LỖI] Không thể khởi tạo DoS Detector: {e}")
            return False
    
    def _monitor_dos_threats(self) -> tuple:
        """Giám sát DoS threats - tích hợp vào Event Log workflow."""
        if not self.dos_detector:
            return [], None
        
        try:
            print("[THÔNG TIN] Đang kiểm tra DoS threats...")
            
            # Chạy DoS detection
            detection_result = self.dos_detector.check_dos_attack()
            
            if detection_result:
                # Tạo log entry cho DoS detection
                dos_log_entry = {
                    'timestamp': detection_result['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    'source': 'DoS-Detector',
                    'event_id': 9999,  # Custom event ID cho DoS
                    'type': 'Security',
                    'category': 'DoS Detection',
                    'log_type': 'DoS-Security',
                    'message': f"DoS Detection: {detection_result['threat_level']} - Score: {detection_result['severity_score']}",
                    'mac_address': self.dos_detector.mac_address,
                    'dos_info': {
                        'threat_level': detection_result['threat_level'],
                        'severity_score': detection_result['severity_score'],
                        'indicators': detection_result['indicators'],
                        'metrics': detection_result['metrics'],
                        'is_attack': detection_result['is_attack'],
                        'ip_stats': detection_result['ip_stats']
                    }
                }
                
                return [dos_log_entry], detection_result
            
            return [], None
            
        except Exception as e:
            print(f"[LỖI] DoS monitoring thất bại: {e}")
            return [], None
    
    def _monitor_system_log(self) -> int:
        """Giám sát System log."""
        if not self.monitors_available['system']:
            print("[BỎ QUA] SystemEventLogMonitor không khả dụng")
            return 0
        
        try:
            print("[THÔNG TIN] Bắt đầu giám sát System log...")
            system_monitor = SystemEventLogMonitor()
            system_logs = system_monitor.collect_logs(max_entries=20)
            
            if self.writer:
                self.writer.write_logs("SystemLog", system_logs)
            
            print(f"[THÀNH CÔNG] Đã xử lý {len(system_logs)} bản ghi system log")
            return len(system_logs)
            
        except Exception as e:
            print(f"[LỖI] Giám sát System log thất bại: {e}")
            print(f"[CHI TIẾT] {traceback.format_exc()}")
            return 0
    
    def _monitor_security_log(self) -> int:
        """Giám sát Security log."""
        if not self.monitors_available['security']:
            print("[BỎ QUA] SecurityEventLogMonitor không khả dụng")
            return 0
        
        try:
            print("[THÔNG TIN] Bắt đầu giám sát Security log...")
            security_monitor = SecurityEventLogMonitor()
            security_logs = security_monitor.collect_logs(max_entries=20)
            
            if self.writer:
                self.writer.write_logs("SecurityLog", security_logs)
            
            print(f"[THÀNH CÔNG] Đã xử lý {len(security_logs)} bản ghi security log")
            return len(security_logs)
            
        except Exception as e:
            print(f"[LỖI] Giám sát Security log thất bại: {e}")
            print(f"[CHI TIẾT] {traceback.format_exc()}")
            return 0
    
    def _monitor_rdp_log(self) -> int:
        """Giám sát RDP log."""
        if not self.monitors_available['rdp']:
            print("[BỎ QUA] RDPEventLogMonitor không khả dụng")
            return 0
        
        try:
            print("[THÔNG TIN] Bắt đầu giám sát RDP log...")
            rdp_monitor = RDPEventLogMonitor()
            rdp_logs = rdp_monitor.collect_logs(max_entries=20)
            
            if self.writer:
                self.writer.write_logs("RDPLog", rdp_logs)
            
            print(f"[THÀNH CÔNG] Đã xử lý {len(rdp_logs)} bản ghi RDP log")
            return len(rdp_logs)
            
        except Exception as e:
            print(f"[LỖI] Giám sát RDP log thất bại: {e}")
            print(f"[CHI TIẾT] {traceback.format_exc()}")
            return 0
    
    def _print_summary_with_dos(self, system_count: int, security_count: int, rdp_count: int, dos_count: int, dos_result):
        """In tóm tắt kèm DoS status."""
        total_logs = system_count + security_count + rdp_count + dos_count
        
        print("\n" + "="*70)
        print("📊 TÓM TẮT KẾT QUẢ GIÁM SÁT")
        print("="*70)
        print(f"System Log:      {system_count:>3} bản ghi")
        print(f"Security Log:    {security_count:>3} bản ghi")
        print(f"RDP Log:         {rdp_count:>3} bản ghi")
        print(f"DoS Detection:   {dos_count:>3} bản ghi")
        print("-"*70)
        print(f"Tổng cộng:       {total_logs:>3} bản ghi")
        
        # DoS Status Detail
        if dos_result:
            threat_emoji = {
                'CRITICAL': '🚨',
                'HIGH': '⚠️', 
                'MEDIUM': '⚡',
                'LOW': '✅'
            }
            emoji = threat_emoji.get(dos_result['threat_level'], 'ℹ️')
            print(f"\n🛡️  DoS Status: {emoji} {dos_result['threat_level']}")
            print(f"   Severity Score: {dos_result['severity_score']}/30")
            if dos_result['is_attack']:
                print(f"   ⚠️  ĐANG BỊ TẤN CÔNG!")
            else:
                print(f"   ✅ Hệ thống an toàn")
        else:
            print(f"\n🛡️  DoS Status: ✅ Hệ thống bình thường")
        
        # Hiển thị trạng thái modules
        print("\n📋 TRẠNG THÁI MODULES:")
        for module, available in self.monitors_available.items():
            status = "✅ Khả dụng" if available else "❌ Không khả dụng"
            print(f"   {module.capitalize()}: {status}")
        
        print("="*70)
    
    def run(self) -> int:
        """Chạy ứng dụng chính."""
        print("🚀 BẮT ĐẦU HỆ THỐNG GIÁM SÁT EVENT LOG + DOS DETECTION + RDP")
        print("="*70)
        
        # Bước 1: Xác thực cấu hình
        if not self._validate_config():
            return 1
        
        # Bước 2: Khởi tạo Google Sheets writer
        if not self._initialize_sheets_writer():
            return 1
        
        # Bước 3: Khởi tạo DoS Detector
        self._initialize_dos_detector()
        
        # Bước 4: Thực hiện giám sát
        try:
            # 1. DoS Detection TRƯỚC (ưu tiên cao nhất)
            dos_logs, dos_result = self._monitor_dos_threats()
            
            # 2. Event Log Monitoring
            system_count = self._monitor_system_log()
            security_count = self._monitor_security_log()
            rdp_count = self._monitor_rdp_log()
            
            # 3. Ghi DoS logs vào Google Sheets
            dos_count = 0
            if dos_logs and self.writer:
                self.writer.write_logs("DoSLog", dos_logs)
                dos_count = len(dos_logs)
                print(f"[THÀNH CÔNG] Đã ghi {dos_count} bản ghi DoS detection")
            
            # 4. Summary với DoS status
            self._print_summary_with_dos(system_count, security_count, rdp_count, dos_count, dos_result)
            
            if system_count + security_count + rdp_count + dos_count > 0:
                print("\n[THÀNH CÔNG] ✅ Tất cả các tác vụ giám sát đã hoàn thành")
                return 0
            else:
                print("\n[CẢNH BÁO] ⚠️  Không thu thập được dữ liệu nào")
                return 1
                
        except KeyboardInterrupt:
            print("\n[THÔNG TIN] Người dùng dừng chương trình")
            return 0
        except Exception as e:
            print(f"\n[LỖI NGHIÊM TRỌNG] {e}")
            print(f"[CHI TIẾT] {traceback.format_exc()}")
            return 1


def main():
    app = EventLogMonitorApp()
    exit_code = app.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
