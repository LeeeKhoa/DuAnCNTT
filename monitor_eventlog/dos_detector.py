"""
DoS Detection Module 
Giám sát system metrics để phát hiện tấn công DoS với độ chính xác cao.
"""

import psutil
import time
import requests
import smtplib
import wmi
import json
import os
import traceback
from collections import defaultdict, deque
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from config import Config


class DoSDetector:
    
    def __init__(self):
        """Khởi tạo DoS Detector."""
        Config.validate()
        
        # Cấu hình cảnh báo
        self.telegram_token = Config.TELEGRAM_TOKEN
        self.telegram_chat_id = Config.TELEGRAM_CHAT_ID
        self.telegram_proxy = Config.TELEGRAM_PROXY
        self.gmail_user = Config.GMAIL_USER
        self.gmail_pass = Config.GMAIL_PASS
        
        # Lấy MAC address
        self.mac_address = self._get_mac_address()
        
        # Ngưỡng phát hiện tối ưu
        self.thresholds = {
            'cpu_percent': 70.0,
            'memory_percent': 80.0,
            'network_connections': 500
        }
        
        # Lưu trữ metrics lịch sử
        self.metrics_history = {
            'cpu': deque(maxlen=100),
            'memory': deque(maxlen=100),
            'connections': deque(maxlen=100)
        }
        
        # File lưu trạng thái
        self.state_file = "dos_detector_state.json"
        
        # Trạng thái cảnh báo
        self.alert_sent = False
        self.attack_start_time = None
        
        # Load state
        self._initialize_state()
        
        # Network tracking
        self.last_network_check = time.time()
        self.last_bytes_recv = 0
        self.last_bytes_sent = 0
        
        print("[DOS DETECTOR] 🚀 Advanced DoS Detector initialized")

    def _initialize_state(self):
        """Khởi tạo state management."""
        try:
            self._load_state()
        except Exception as e:
            print(f"[STATE ERROR] Lỗi khởi tạo state: {e}")
            self.alert_sent = False
            self.attack_start_time = None
            self._create_initial_state()

    def _load_state(self):
        """Load trạng thái và metrics history."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                    
                    # Load alert state
                    self.alert_sent = state.get('alert_sent', False)
                    attack_start_str = state.get('attack_start_time')
                    if attack_start_str:
                        self.attack_start_time = datetime.fromisoformat(attack_start_str)
                    else:
                        self.attack_start_time = None
                    
                    # Load metrics history
                    if 'metrics_history_summary' in state:
                        summary = state['metrics_history_summary']
                        
                        # Khôi phục lịch sử metrics
                        for cpu_val in summary.get('last_10_cpu', []):
                            self.metrics_history['cpu'].append(cpu_val)
                        for mem_val in summary.get('last_10_memory', []):
                            self.metrics_history['memory'].append(mem_val)
                        for conn_val in summary.get('last_10_connections', []):
                            self.metrics_history['connections'].append(conn_val)
                        
                        print(f"[STATE] ✅ Restored metrics history:")
                        print(f"  - CPU samples: {len(self.metrics_history['cpu'])}")
                        print(f"  - Memory samples: {len(self.metrics_history['memory'])}")
                        print(f"  - Connections samples: {len(self.metrics_history['connections'])}")
                    
                    print(f"[STATE] ✅ Loaded state: alert_sent={self.alert_sent}")
                    
            except (json.JSONDecodeError, ValueError) as e:
                print(f"[STATE ERROR] File corrupted: {e}")
                self._create_initial_state()
        else:
            print("[STATE] 🆕 No state file found, creating new state...")
            self._create_initial_state()

    def _create_initial_state(self):
        """Tạo state file ban đầu."""
        self.alert_sent = False
        self.attack_start_time = None
        success = self._save_state()
        if success:
            print("[STATE] ✅ Created new state file successfully")
        else:
            print("[STATE] ❌ Failed to create state file")

    def _save_state(self):
        """Save trạng thái và metrics history."""
        try:
            print(f"[DEBUG] Saving state - CPU samples: {len(self.metrics_history['cpu'])}")
            
            state = {
                'alert_sent': self.alert_sent,
                'attack_start_time': self.attack_start_time.isoformat() if self.attack_start_time else None,
                'last_update': datetime.now().isoformat(),
                'version': '3.0-advanced',
                
                # Lưu metrics history
                'metrics_history_summary': {
                    'cpu_samples': len(self.metrics_history['cpu']),
                    'memory_samples': len(self.metrics_history['memory']),
                    'last_10_cpu': list(self.metrics_history['cpu'])[-10:] if self.metrics_history['cpu'] else [],
                    'last_10_memory': list(self.metrics_history['memory'])[-10:] if self.metrics_history['memory'] else [],
                    'last_10_connections': list(self.metrics_history['connections'])[-10:] if self.metrics_history['connections'] else []
                }
            }
            
            # Atomic write
            temp_file = self.state_file + '.tmp'
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(state, f, ensure_ascii=False, indent=2)
            
            if os.path.exists(self.state_file):
                os.remove(self.state_file)
            os.rename(temp_file, self.state_file)
            
            print(f"[STATE] 💾 Saved state successfully with {len(self.metrics_history['cpu'])} CPU samples")
            return True
            
        except Exception as e:
            print(f"[STATE ERROR] ❌ Save failed: {e}")
            print(f"[DEBUG] Traceback: {traceback.format_exc()}")
            return False

    def _get_mac_address(self):
        """Lấy địa chỉ MAC."""
        try:
            c = wmi.WMI()
            for interface in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                if interface.MACAddress:
                    return interface.MACAddress
        except Exception as e:
            print(f"[CẢNH BÁO] Không lấy được MAC: {e}")
        return "Unknown"

    def get_system_metrics(self):
        """Thu thập system metrics."""
        try:
            # CPU và Memory
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Network statistics
            network_io = psutil.net_io_counters()
            network_connections = len(psutil.net_connections())
            
            # Network bytes per second
            current_time = time.time()
            if hasattr(self, 'last_network_check') and self.last_bytes_recv > 0:
                time_diff = current_time - self.last_network_check
                if time_diff > 0:
                    bytes_in_per_sec = (network_io.bytes_recv - self.last_bytes_recv) / time_diff
                    bytes_out_per_sec = (network_io.bytes_sent - self.last_bytes_sent) / time_diff
                else:
                    bytes_in_per_sec = 0
                    bytes_out_per_sec = 0
            else:
                bytes_in_per_sec = 0
                bytes_out_per_sec = 0
            
            self.last_network_check = current_time
            self.last_bytes_recv = network_io.bytes_recv
            self.last_bytes_sent = network_io.bytes_sent
            
            metrics = {
                'timestamp': datetime.now(),
                'cpu_percent': cpu_percent,
                'memory_percent': memory_percent,
                'network_connections': network_connections,
                'network_bytes_in_per_sec': bytes_in_per_sec,
                'network_bytes_out_per_sec': bytes_out_per_sec
            }
            
            return metrics
            
        except Exception as e:
            print(f"[LỖI] Không thể thu thập system metrics: {e}")
            return None

    def update_metrics_history(self, metrics):
        """Cập nhật lịch sử metrics."""
        self.metrics_history['cpu'].append(metrics['cpu_percent'])
        self.metrics_history['memory'].append(metrics['memory_percent'])
        self.metrics_history['connections'].append(metrics['network_connections'])

    def _check_advanced_alert_logic(self, current_metrics):
        """
        Kiểm tra logic cảnh báo.
        
        Điều kiện:
        1. 5 lần liên tiếp CPU > 70% HOẶC Memory > 80% HOẶC Network > 500
        2. 2 lần liên tiếp cả 3 chỉ số cùng vượt ngưỡng  
        3. Cuối tuần sau 12h tối: 2 lần liên tiếp bất kỳ chỉ số nào vượt ngưỡng
  
        """
        # Lấy 10 lần quét gần nhất
        last_10_cpu = list(self.metrics_history['cpu'])[-10:] if len(self.metrics_history['cpu']) >= 10 else list(self.metrics_history['cpu'])
        last_10_memory = list(self.metrics_history['memory'])[-10:] if len(self.metrics_history['memory']) >= 10 else list(self.metrics_history['memory'])
        last_10_connections = list(self.metrics_history['connections'])[-10:] if len(self.metrics_history['connections']) >= 10 else list(self.metrics_history['connections'])
        
        # Thêm giá trị hiện tại
        current_cpu_values = last_10_cpu + [current_metrics['cpu_percent']]
        current_memory_values = last_10_memory + [current_metrics['memory_percent']]
        current_network_values = last_10_connections + [current_metrics['network_connections']]
        
        # Lấy 10 giá trị cuối cùng
        cpu_values = current_cpu_values[-10:]
        memory_values = current_memory_values[-10:]
        network_values = current_network_values[-10:]
        
        print(f"[ADVANCED LOGIC] Checking last values:")
        print(f"  - CPU: {[f'{x:.1f}' for x in cpu_values[-5:]]}")
        print(f"  - Memory: {[f'{x:.1f}' for x in memory_values[-5:]]}")
        print(f"  - Network: {network_values[-5:]}")
        
        # Hàm đếm số lần liên tiếp vượt ngưỡng
        def count_consecutive_over_threshold(values, threshold):
            max_count = 0
            current_count = 0
            for v in values:
                if v > threshold:
                    current_count += 1
                    max_count = max(max_count, current_count)
                else:
                    current_count = 0
            return max_count
        
        # Đếm số lần liên tiếp vượt ngưỡng
        cpu_consec = count_consecutive_over_threshold(cpu_values, self.thresholds['cpu_percent'])
        mem_consec = count_consecutive_over_threshold(memory_values, self.thresholds['memory_percent'])
        net_consec = count_consecutive_over_threshold(network_values, self.thresholds['network_connections'])
        
        print(f"[ADVANCED LOGIC] Consecutive over threshold:")
        print(f"  - CPU: {cpu_consec} times (threshold: {self.thresholds['cpu_percent']}%)")
        print(f"  - Memory: {mem_consec} times (threshold: {self.thresholds['memory_percent']}%)")
        print(f"  - Network: {net_consec} times (threshold: {self.thresholds['network_connections']})")
        
        # ĐIỀU KIỆN 1: 5 lần liên tiếp vượt ngưỡng cho bất kỳ chỉ số nào
        if cpu_consec >= 5 or mem_consec >= 5 or net_consec >= 5:
            print(f"[ADVANCED LOGIC] ✅ ALERT: 5+ consecutive threshold exceeded!")
            print(f"  - CPU consecutive: {cpu_consec}, Memory consecutive: {mem_consec}, Network consecutive: {net_consec}")
            return True
        
        # ĐIỀU KIỆN 2: Cả 3 cùng vượt ngưỡng thì 2 lần liên tiếp
        all_three_over = []
        for i in range(len(cpu_values)):
            if (cpu_values[i] > self.thresholds['cpu_percent'] and 
                memory_values[i] > self.thresholds['memory_percent'] and 
                network_values[i] > self.thresholds['network_connections']):
                all_three_over.append(True)
            else:
                all_three_over.append(False)
        
        # Đếm số lần liên tiếp cả 3 cùng vượt ngưỡng
        all_three_consec = 0
        current_consec = 0
        for over in all_three_over:
            if over:
                current_consec += 1
                all_three_consec = max(all_three_consec, current_consec)
            else:
                current_consec = 0
        
        print(f"[ADVANCED LOGIC] All three over threshold: {all_three_over}")
        print(f"[ADVANCED LOGIC] All three consecutive: {all_three_consec}")
        
        if all_three_consec >= 2:
            print(f"[ADVANCED LOGIC] ✅ ALERT: All 3 metrics over threshold for 2+ consecutive times!")
            return True
        
        # ĐIỀU KIỆN 3: Cuối tuần sau 12h tối thì 2 lần liên tiếp
        current_time = datetime.now()
        is_weekend = current_time.weekday() >= 5  # Thứ 7, Chủ nhật
        is_after_midnight = current_time.hour >= 0  # Sau 12h tối (0h trở đi)
        
        if is_weekend and is_after_midnight:
            print(f"[ADVANCED LOGIC] Weekend night detected: {current_time.strftime('%A %H:%M')}")
            
            # Kiểm tra 2 lần quét liên tiếp có vượt ngưỡng không
            if len(cpu_values) >= 2:
                last_2_cpu = cpu_values[-2:]
                last_2_memory = memory_values[-2:]
                last_2_network = network_values[-2:]
                
                weekend_night_count = 0
                for i in range(len(last_2_cpu)):
                    if (last_2_cpu[i] > self.thresholds['cpu_percent'] or 
                        last_2_memory[i] > self.thresholds['memory_percent'] or 
                        last_2_network[i] > self.thresholds['network_connections']):
                        weekend_night_count += 1
                
                print(f"[ADVANCED LOGIC] Weekend night check: {weekend_night_count}/2 times over threshold")
                print(f"  - Last 2 CPU: {[f'{x:.1f}' for x in last_2_cpu]}")
                print(f"  - Last 2 Memory: {[f'{x:.1f}' for x in last_2_memory]}")
                print(f"  - Last 2 Network: {last_2_network}")
                
                if weekend_night_count >= 2:
                    print(f"[ADVANCED LOGIC] ✅ ALERT: Weekend night - 2 consecutive times over threshold!")
                    return True
        
        print(f"[ADVANCED LOGIC] ❌ No alert conditions met")
        return False

    def _analyze_alert_reason(self, metrics):
        """Phân tích lý do cảnh báo chi tiết."""
        reasons = []
        
        # Kiểm tra từng điều kiện
        cpu_over = metrics['cpu_percent'] > self.thresholds['cpu_percent']
        mem_over = metrics['memory_percent'] > self.thresholds['memory_percent']
        net_over = metrics['network_connections'] > self.thresholds['network_connections']
        
        # Phân tích pattern từ lịch sử
        if len(self.metrics_history['cpu']) >= 5:
            last_5_cpu = list(self.metrics_history['cpu'])[-5:]
            cpu_trend = "tăng" if last_5_cpu[-1] > last_5_cpu[0] else "giảm"
            cpu_consec = sum(1 for x in last_5_cpu if x > self.thresholds['cpu_percent'])
            
            if cpu_consec >= 3:
                reasons.append(f"├─ 🖥️ CPU: {cpu_consec}/5 lần gần nhất vượt ngưỡng an toàn (xu hướng {cpu_trend})")
        
        if len(self.metrics_history['memory']) >= 5:
            last_5_mem = list(self.metrics_history['memory'])[-5:]
            mem_consec = sum(1 for x in last_5_mem if x > self.thresholds['memory_percent'])
            
            if mem_consec >= 3:
                reasons.append(f"├─ 🧠 RAM: {mem_consec}/5 lần gần nhất vượt ngưỡng an toàn")
        
        if len(self.metrics_history['connections']) >= 5:
            last_5_net = list(self.metrics_history['connections'])[-5:]
            net_consec = sum(1 for x in last_5_net if x > self.thresholds['network_connections'])
            
            if net_consec >= 3:
                reasons.append(f"├─ 🌐 Mạng: {net_consec}/5 lần gần nhất vượt ngưỡng an toàn")
        
        # Kiểm tra multiple metrics
        if cpu_over and mem_over and net_over:
            reasons.append("├─ ⚠️ Các thông số đang có dấu hiệu tăng mạnh")
        
        # Kiểm tra thời gian đặc biệt
        current_time = datetime.now()
        if current_time.weekday() >= 5 and current_time.hour >= 0:
            reasons.append("├─ 🌙 Phát hiện trong khung giờ nhạy cảm (cuối tuần, sau 12h đêm)")
        
        if not reasons:
            reasons.append("├─ 🎯 Điều kiện cảnh báo tổng hợp đã được kích hoạt")
        
        reasons.append("└─ 🤖 Đánh giá hệ thống: Có dấu hiệu bất thường cần theo dõi")
        
        return "\n".join(reasons)

    def check_dos_attack(self):
  
        print("[DOS DETECTOR] 🔍 Checking DoS threats with advanced logic...")
        
        # Thu thập metrics
        metrics = self.get_system_metrics()
        if not metrics:
            return None
        
        # Cập nhật lịch sử
        self.update_metrics_history(metrics)
        
        # Kiểm tra logic cảnh báo thông minh
        is_attack_advanced_logic = self._check_advanced_alert_logic(metrics)
        
        # Tạo result
        result = {
            'timestamp': metrics['timestamp'],
            'threat_level': "HIGH" if is_attack_advanced_logic else "LOW",
            'severity_score': 15.0 if is_attack_advanced_logic else 2.0,
            'indicators': [{'type': 'ADVANCED_LOGIC_ALERT', 'description': 'Pattern detected by advanced algorithm'}] if is_attack_advanced_logic else [],
            'metrics': metrics,
            'is_attack': is_attack_advanced_logic,
            'pattern_valid': is_attack_advanced_logic
        }
        
        # DEBUG THÔNG TIN
        print(f"[DEBUG] Advanced logic analysis:")
        print(f"  - advanced_logic_alert: {is_attack_advanced_logic}")
        print(f"  - threat_level: {result['threat_level']}")
        print(f"  - is_attack: {result['is_attack']}")
        print(f"  - alert_sent: {self.alert_sent}")
        
        
        state_changed = False
        
        if result['is_attack'] and not self.alert_sent:
            print("[ALERT] 🚨 ADVANCED LOGIC: Sending attack notification...")
            self.send_dos_alert(result)
            self.alert_sent = True
            self.attack_start_time = datetime.now()
            state_changed = True
            
        elif not result['is_attack'] and self.alert_sent:
            # Logic phục hồi tức thì: Báo cáo ngay khi bản ghi tiếp theo là false
            print("[RECOVERY] ✅ ADVANCED LOGIC: System recovered - sending stability notification...")
            self.send_recovery_alert()
            self.alert_sent = False
            self.attack_start_time = None
            state_changed = True
        
        # LUÔN SAVE STATE
        success = self._save_state()
        if success:
            print(f"[SUCCESS] ✅ State saved with {len(self.metrics_history['cpu'])} CPU samples")
        
        return result

    def send_dos_alert(self, detection_result):
        """Gửi cảnh báo DoS"""
        threat_level = detection_result['threat_level']
        metrics = detection_result['metrics']
        timestamp = detection_result['timestamp']
        
        # Phân tích chi tiết điều kiện kích hoạt
        alert_reason = self._analyze_alert_reason(metrics)
        
        message = (
            f"🚨 CẢNH BÁO BẢO MẬT HỆ THỐNG - NGHI VẤN HỆ THỐNG BỊ TẤN CÔNG\n"
            f"{'='*46}\n\n"
            f"📊 **THÔNG TIN CẢNH BÁO:**\n"
            f"🔥 Mức độ nguy hiểm: **{threat_level}**\n"
            f"⏰ Thời gian phát hiện: **{timestamp.strftime('%d/%m/%Y %H:%M:%S')}**\n"
            f"💻 Hệ thống: **{self.mac_address}**\n"
            f"🆔 Mã cảnh báo: **DOS-{timestamp.strftime('%Y%m%d%H%M%S')}**\n\n"
            
            f"📈 **CHỈ SỐ HỆ THỐNG HIỆN TẠI:**\n"
            f"├─ 🖥️ Sử dụng CPU: **{metrics['cpu_percent']:.1f}%** "
            f"{'🔴' if metrics['cpu_percent'] > self.thresholds['cpu_percent'] else '🟢'}\n"
            f"├─ 🧠 Sử dụng RAM: **{metrics['memory_percent']:.1f}%** "
            f"{'🔴' if metrics['memory_percent'] > self.thresholds['memory_percent'] else '🟢'}\n"
            f"├─ 🌐 Kết nối mạng: **{metrics['network_connections']}** "
            f"{'🔴' if metrics['network_connections'] > self.thresholds['network_connections'] else '🟢'}\n"
            f"├─ ⬇️ Network In: **{(metrics['network_bytes_in_per_sec']/1024/1024):.2f} MB/s**\n"
            f"└─ ⬆️ Network out: **{(metrics['network_bytes_out_per_sec']/1024/1024):.2f} MB/s**\n\n"
            
            f"🎯 **PHÂN TÍCH TRẠNG THÁI:**\n"
            f"{alert_reason}\n\n"
            
            
            f"⚡ **HÀNH ĐỘNG KHUYẾN NGHỊ:**\n"
            f"🔍 Kiểm tra ngay các tiến trình đang chạy\n"
            f"👀 Xem xét lưu lượng mạng bất thường\n"
            f"📝 Theo dõi nhật ký hệ thống chi tiết\n"
            f"🚫 Cân nhắc chặn IP đáng nghi nếu cần\n"
            

            f"🔔 **Hệ thống sẽ tự động thông báo khi tình hình ổn định**\n"
            f"📞 **Liên hệ:** Đội ngũ Bảo mật IT nếu cần hỗ trợ khẩn cấp\n"
        )
        
        # Gửi qua Telegram
        self._send_telegram(message)
        
        # Gửi email 
        email_subject = f"🚨 CẢNH BÁO BẢO MẬT - Nghi vấn hệ thống bị tấn công [{timestamp.strftime('%d/%m/%Y %H:%M')}]"
        email_body = self._create_vietnamese_email_body(detection_result, alert_reason)
        self._send_gmail(email_subject, email_body)

    def _create_vietnamese_email_body(self, detection_result, alert_reason):
    
        metrics = detection_result['metrics']
        timestamp = detection_result['timestamp']
        
        return f"""

=== 🚨TÓM TẮT CẢNH BÁO ===
Loại cảnh báo: Phát hiện nghi vấn tấn công từ chối dịch vụ (DoS)
Mức độ nghiêm trọng: {detection_result['threat_level']}
Thời gian phát hiện: {timestamp.strftime('%d/%m/%Y %H:%M:%S')}
MAC hệ thống: {self.mac_address}
Mã cảnh báo: DOS-{timestamp.strftime('%Y%m%d%H%M%S')}

=== 📊CHỈ SỐ HỆ THỐNG ===
Sử dụng CPU: {metrics['cpu_percent']:.1f}% (Ngưỡng: {self.thresholds['cpu_percent']}%)
Sử dụng RAM: {metrics['memory_percent']:.1f}% (Ngưỡng: {self.thresholds['memory_percent']}%)
Kết nối mạng: {metrics['network_connections']} (Ngưỡng: {self.thresholds['network_connections']})
Network In: {(metrics['network_bytes_in_per_sec']/1024/1024):.2f} MB/s
Network Out: {(metrics['network_bytes_out_per_sec']/1024/1024):.2f} MB/s

=== PHÂN TÍCH TRẠNG THÁI ===
{alert_reason.replace('├─', '-').replace('└─', '-').replace('⚠️', '').replace('🌙', '').replace('🖥️', '').replace('🧠', '').replace('🌐', '').replace('🎯', '').replace('🤖', '')}

=== YÊU CẦU ===
1. Khẩn cấp: Kiểm tra các tiến trình đang chạy và tải hệ thống
2. Mạng: Giám sát các lưu lượng bất thường
3. Bảo mật: Xem xét nhật ký hệ thống để tìm hoạt động đáng nghi
3. Giám sát: Tiếp tục theo dõi để xác định rõ nguyên nhân và phương thức tấn công


Đây là thông báo tự động từ hệ thống
Để được hỗ trợ ngay lập tức, liên hệ Đội ngũ Bảo mật IT.

----------------------------
Hệ thống Phát hiện DoS v3.0 
Tạo lúc: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
"""

    def send_recovery_alert(self):
        """Gửi thông báo phục hồi."""
        if self.attack_start_time:
            duration = datetime.now() - self.attack_start_time
            duration_str = str(duration).split('.')[0]
        else:
            duration_str = "Không xác định"
        
        recovery_time = datetime.now()
        
        message = (
            f"✅ BÁO CÁO HỆ THỐNG\n"
            f"{'='*55}\n\n"
            f"🟢 Trạng thái: **Hệ thống đã ổn định trở lại**\n"
            f"⏰ Thời gian phục hồi: **{recovery_time.strftime('%d/%m/%Y %H:%M:%S')}**\n"
            f"⌛ Thời gian cảnh báo: **{duration_str}**\n"
            f"🆔 Mã phục hồi: **REC-{recovery_time.strftime('%Y%m%d%H%M%S')}**\n\n"
            
            f"📊 **PHÂN TÍCH:**\n"
            f"⚡ Tốc độ phục hồi: **Ngay lập tức** (1 chu kỳ kiểm tra)\n"
            f"🔍 Đánh giá: **Có thể là cảnh báo tạm thời**\n"
            f"📈 Độ tin cậy: **Cần theo dõi thêm để xác nhận**\n"
            f"💡 Khuyến nghị: **Tiếp tục giám sát trong 30 phút tới**\n\n"
            
            f"🔍 **THÔNG TIN QUAN TRỌNG:**\n"
            f"📋 Bản ghi tiếp theo đã trở lại ngưỡng bình thường\n"
            f"💭 Điều này cho thấy có thể là tăng đột biến tạm thời\n"
            f"🤖 Hệ thống tiếp tục giám sát để phát hiện các dấu hiệu bất thường\n"
            
            
            f"🔗 **MAC hệ thống:** {self.mac_address}\n"
            f"📞 **Liên hệ:** Đội ngũ Bảo mật IT nếu có thắc mắc\n"
        )
        
        self._send_telegram(message)
        
        # Email phục hồi bằng tiếng Việt
        email_subject = f"✅ BÁO CÁO HỆ THỐNG [{recovery_time.strftime('%d/%m/%Y %H:%M')}]"
        email_body = f"""
✅THÔNG BÁO HỆ THỐNG ĐÃ PHỤC HỒI ỔN ĐỊNH

==================================================================
Trạng thái: Hệ thống đã ổn định
Thời gian phục hồi: {recovery_time.strftime('%d/%m/%Y %H:%M:%S')}
Thời gian cảnh báo: {duration_str}
Loại phục hồi: Ngay lập tức (Phát hiện chu kỳ tiếp theo)
Mã phục hồi: REC-{recovery_time.strftime('%Y%m%d%H%M%S')}

=== 📊PHÂN TÍCH ===
Tốc độ phục hồi: Ngay lập tức (1 chu kỳ phát hiện)
Đánh giá: Có thể là tăng đột biến tạm thời hoặc cảnh báo giả
Mức độ tin cậy: Cần tiếp tục giám sát để xác nhận
Khuyến nghị: Tiếp tục theo dõi trong 30 phút tới

=== TÓM TẮT SỰ CỐ ===
Hệ thống đã trở lại các thông số hoạt động bình thường trong chu kỳ quét tiếp theo.
Việc phục hồi nhanh chóng này cho thấy cảnh báo có thể được kích hoạt bởi:
- Tăng đột biến hệ thống tạm thời
- Tắc nghẽn mạng ngắn hạn
- Bảo trì hệ thống theo lịch trình
- Khởi động/tắt ứng dụng

=== YÊU CẦU ===
1. Tiếp tục các hoạt động giám sát bình thường
2. Ghi nhận sự cố để phân tích xu hướng
3. Cập nhật chỉ số phục hồi trong hệ thống
4. Báo cáo tình trạng cho đội ngũ quản lý


Việc phục hồi nhanh chóng này là tích cực và cho thấy khả năng phục hồi của hệ thống.
Việc tiếp tục giám sát sẽ giúp phân biệt giữa các mối đe dọa thực sự và các tăng đột biến tạm thời.

---
Hệ thống Phát hiện DoS v3.0 
Tạo lúc: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
"""
        
        self._send_gmail(email_subject, email_body)

    def _send_telegram(self, message):
        """Gửi thông báo qua Telegram."""
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {'chat_id': self.telegram_chat_id, 'text': message, 'parse_mode': 'Markdown'}
        
        try:
            response = requests.post(url, data=payload, timeout=10, proxies=self.telegram_proxy, verify=False)
            if response.status_code == 200:
                print("[THÀNH CÔNG] Đã gửi cảnh báo qua Telegram")
            else:
                print(f"[LỖI] Telegram API error: {response.status_code}")
        except Exception as e:
            print(f"[LỖI] Gửi Telegram thất bại: {e}")

    def _send_gmail(self, subject, body):
        """Gửi cảnh báo qua Gmail."""
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = self.gmail_user
        msg['To'] = self.gmail_user

        try:
            with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                smtp.starttls()
                smtp.login(self.gmail_user, self.gmail_pass)
                smtp.sendmail(self.gmail_user, [self.gmail_user], msg.as_string())
            print("[THÀNH CÔNG] Đã gửi cảnh báo qua Gmail")
        except Exception as e:
            print(f"[LỖI] Gửi Gmail thất bại: {e}")

    def get_detection_report(self):
        """Tạo báo cáo tổng hợp."""
        current_metrics = self.get_system_metrics()
        if not current_metrics:
            return None
        
        return {
            'current_metrics': current_metrics,
            'alert_status': self.alert_sent,
            'attack_duration': str(datetime.now() - self.attack_start_time).split('.')[0] if self.attack_start_time else None,
            'thresholds': self.thresholds,
            'history_size': len(self.metrics_history['cpu']),
            'advanced_features': {
                'intelligent_thresholds': True,
                'immediate_recovery_notification': True,
                'false_positive_detection': True,
                'weekend_night_sensitivity': True,
                'vietnamese_notifications': True
            }
        }


# Test function
if __name__ == "__main__":
    print("Testing DoS Detector with Vietnamese Notifications...")
    detector = DoSDetector()
    
    # Test với vài lần check
    for i in range(10):
        print(f"\n--- Vietnamese Notification Test {i+1} ---")
        result = detector.check_dos_attack()
        if result:
            print(f"Result: {result['threat_level']} - Attack: {result['is_attack']}")
        time.sleep(1)
    
    print("\nVietnamese Notification Test completed!")
