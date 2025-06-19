"""
RDP Event Log Monitor - Chỉ sử dụng PowerShell với time filter.
Tránh false alerts bằng cách chỉ lấy events trong khoảng thời gian gần đây.
ĐÃ SỬA LỖI TIMESTAMP VÀ IPv6 PARSING.
"""

import subprocess
import csv
import json
import os
import requests
import smtplib
import wmi
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from config import Config


class RDPPowerShellMonitor:
    """Monitor RDP chỉ qua PowerShell với time filtering."""
    
    def __init__(self, server='localhost'):
        """Khởi tạo RDP PowerShell Monitor."""
        Config.validate()
        
        self.server = server
        self.max_events = 20
        self.hours_lookback = 1  # Chỉ lấy events trong 1 giờ gần đây
        
        # Cấu hình từ biến môi trường
        self.telegram_token = Config.TELEGRAM_TOKEN
        self.telegram_chat_id = Config.TELEGRAM_CHAT_ID
        self.telegram_proxy = Config.TELEGRAM_PROXY
        self.gmail_user = Config.GMAIL_USER
        self.gmail_pass = Config.GMAIL_PASS
        self.mac_address = self._get_mac_address()
        
        # File để track processed events
        self.processed_events_file = 'processed_rdp_events.json'
        self.processed_events = self._load_processed_events()

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

    def _load_processed_events(self):
        """Load danh sách events đã xử lý."""
        try:
            if os.path.exists(self.processed_events_file):
                with open(self.processed_events_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Chỉ giữ events trong 24 giờ gần đây
                    cutoff_time = datetime.now() - timedelta(hours=24)
                    return {
                        k: v for k, v in data.items() 
                        if datetime.fromisoformat(v['processed_at']) > cutoff_time
                    }
            return {}
        except Exception as e:
            print(f"[CẢNH BÁO] Không thể load processed events: {e}")
            return {}

    def _save_processed_events(self):
        """Lưu danh sách events đã xử lý."""
        try:
            with open(self.processed_events_file, 'w', encoding='utf-8') as f:
                json.dump(self.processed_events, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[CẢNH BÁO] Không thể save processed events: {e}")

    def _parse_timestamp_safe(self, timestamp_str):
        """Parse timestamp với multiple formats để xử lý lỗi timestamp."""
        formats = [
            "%Y-%m-%d %H:%M:%S",        # 2025-06-19 12:27:47
            "%m/%d/%Y %H:%M:%S",        # 06/19/2025 12:27:47
            "%d/%m/%Y %H:%M:%S",        # 19/06/2025 12:27:47
            "%Y-%m-%dT%H:%M:%S",        # 2025-06-19T12:27:47
            "%Y-%m-%d %H:%M:%S.%f",     # 2025-06-19 12:27:47.123456
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                return dt.strftime("%Y-%m-%d %H:%M:%S")  # Chuẩn hóa format
            except ValueError:
                continue
        
        # Nếu không parse được, trả về timestamp hiện tại
        print(f"[CẢNH BÁO] Không parse được timestamp: {timestamp_str}")
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _clean_ip_address(self, ip_str):
        """Clean IP address, xử lý IPv6 với zone ID."""
        if not ip_str or ip_str == "Unknown":
            return "Unknown"
        
        # Xử lý IPv6 với zone ID (ví dụ: fe80::2b3a:f25a%584877503)
        if '%' in ip_str:
            ip_str = ip_str.split('%')[0]  # Bỏ zone ID
        
        # Xử lý IPv6 shortened form (0:0:fe80::...)
        if ip_str.startswith('0:0:'):
            ip_str = ip_str[4:]  # Bỏ leading 0:0:
        
        return ip_str

    def _is_event_processed(self, event_info):
        """Kiểm tra event đã được xử lý chưa."""
        # SỬA LỖI: Sử dụng 'timestamp' thay vì truy cập trực tiếp
        timestamp = event_info.get('timestamp', 'unknown')
        user = event_info.get('user', 'unknown')
        source_ip = event_info.get('source_ip', 'unknown')
        
        event_key = f"{timestamp}_{user}_{source_ip}"
        return event_key in self.processed_events

    def _mark_event_processed(self, event_info):
        """Đánh dấu event đã được xử lý."""
        # SỬA LỖI: Sử dụng 'timestamp' thay vì truy cập trực tiếp
        timestamp = event_info.get('timestamp', 'unknown')
        user = event_info.get('user', 'unknown')
        source_ip = event_info.get('source_ip', 'unknown')
        
        event_key = f"{timestamp}_{user}_{source_ip}"
        self.processed_events[event_key] = {
            'timestamp': timestamp,
            'user': user,
            'source_ip': source_ip,
            'processed_at': datetime.now().isoformat()
        }

    def _get_recent_rdp_events_powershell(self):
        """Lấy RDP events gần đây qua PowerShell với timestamp parsing cải tiến."""
        # Tính thời gian bắt đầu lọc
        time_threshold = datetime.now() - timedelta(hours=self.hours_lookback)
        time_filter = time_threshold.strftime("%Y-%m-%dT%H:%M:%S")
        
        print(f"[POWERSHELL] Tìm RDP events sau: {time_filter}")

        # PowerShell script với format timestamp chuẩn
        ps_script = f"""
        try {{
            $startTime = [DateTime]::Parse('{time_filter}')
            $events = Get-WinEvent -FilterHashtable @{{
                LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
                ID=1149
                StartTime=$startTime
            }} -MaxEvents {self.max_events} -ErrorAction SilentlyContinue
            
            if ($events.Count -eq 0) {{
                Write-Output "NO_RECENT_EVENTS"
                exit 0
            }}
            
            foreach ($event in $events) {{
                $props = $event.Properties
                $user = if ($props.Count -gt 0) {{ $props[0].Value }} else {{ "Unknown" }}
                $domain = if ($props.Count -gt 1) {{ $props[1].Value }} else {{ "Unknown" }}
                $ip = if ($props.Count -gt 2) {{ $props[2].Value }} else {{ "Unknown" }}
                
                # Format timestamp thành ISO format chuẩn
                $timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                
                Write-Output "$timestamp|$($event.Id)|$user|$domain|$ip|$($event.LevelDisplayName)"
            }}
        }} catch {{
            Write-Output "ERROR: $($_.Exception.Message)"
        }}
        """

        try:
            # Chạy PowerShell script
            result = subprocess.run(
                ['powershell', '-Command', ps_script],
                capture_output=True,
                text=True,
                timeout=30,
                encoding='utf-8'
            )

            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                
                # Kiểm tra xem có events gần đây không
                if lines and lines[0].strip() == "NO_RECENT_EVENTS":
                    print("[THÔNG TIN] Không có RDP events nào trong khoảng thời gian gần đây")
                    return []

                events = []
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('ERROR:'):
                        if line.startswith('ERROR:'):
                            print(f"[POWERSHELL ERROR] {line}")
                        continue
                    
                    parts = line.split('|')
                    if len(parts) >= 6:
                        try:
                            # Parse timestamp với safe parsing
                            timestamp_str = parts[0]
                            parsed_timestamp = self._parse_timestamp_safe(timestamp_str)
                            
                            # Clean IP address (xử lý IPv6 với zone ID)
                            source_ip = self._clean_ip_address(parts[4])
                            
                            event = {
                                'timestamp': parsed_timestamp,
                                'event_id': int(parts[1]),
                                'user': parts[2],
                                'domain': parts[3],
                                'source_ip': source_ip,
                                'level': parts[5]
                            }
                            events.append(event)
                            print(f"[PHÁT HIỆN] PowerShell: {event['user']} từ {event['source_ip']} lúc {event['timestamp']}")
                        except (ValueError, IndexError) as e:
                            print(f"[CẢNH BÁO] Lỗi parse line: {line} - {e}")
                            continue

                return events
            else:
                if result.stderr:
                    print(f"[LỖI] PowerShell stderr: {result.stderr}")
                if result.returncode != 0:
                    print(f"[LỖI] PowerShell exit code: {result.returncode}")
                return []

        except subprocess.TimeoutExpired:
            print("[LỖI] PowerShell timeout sau 30 giây")
            return []
        except FileNotFoundError:
            print("[LỖI] PowerShell không tìm thấy - có thể không phải Windows hoặc PowerShell chưa được cài đặt")
            return []
        except Exception as e:
            print(f"[LỖI] PowerShell execution failed: {e}")
            return []

    def collect_logs(self, max_entries=20):
        """Thu thập RDP logs chỉ qua PowerShell với error handling cải tiến."""
        print("="*60)
        print("🔍 BẮT ĐẦU RDP LOG COLLECTION VIA POWERSHELL")
        print("="*60)
        
        try:
            # Lấy events từ PowerShell
            powershell_events = self._get_recent_rdp_events_powershell()
            
            if not powershell_events:
                print("[KẾT QUẢ] Không có RDP events mới trong khoảng thời gian gần đây")
                return []

            # Chuyển đổi sang format chuẩn với error handling
            log_entries = []
            rdp_events = []
            
            for ps_event in powershell_events:
                try:
                    # Tạo rdp_info với safe access
                    rdp_info = {
                        'user': ps_event.get('user', 'Unknown'),
                        'domain': ps_event.get('domain', 'Unknown'),
                        'source_ip': ps_event.get('source_ip', 'Unknown'),
                        'full_user': f"{ps_event.get('domain', 'Unknown')}\\{ps_event.get('user', 'Unknown')}" if ps_event.get('domain') != "Unknown" else ps_event.get('user', 'Unknown'),
                        'detection_method': 'PowerShell Get-WinEvent (Recent Events Only)',
                        'timestamp': ps_event.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    }
                    
                    # Tạo log entry
                    entry = {
                        'timestamp': ps_event.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                        'source': 'TerminalServices-RemoteConnectionManager',
                        'event_id': ps_event.get('event_id', 1149),
                        'type': 'Information',
                        'category': 0,
                        'log_type': 'RDP-PowerShell',
                        'message': f"RDP Authentication: {ps_event.get('user', 'Unknown')} from {ps_event.get('source_ip', 'Unknown')}",
                        'mac_address': self.mac_address,
                        'rdp_info': rdp_info
                    }
                    
                    log_entries.append(entry)
                    rdp_events.append(rdp_info)
                    
                except Exception as e:
                    print(f"[CẢNH BÁO] Lỗi xử lý event: {ps_event} - {e}")
                    continue

            # Gửi cảnh báo chỉ cho events chưa xử lý
            if rdp_events:
                self._send_alerts_filtered(rdp_events)
                print(f"[THÀNH CÔNG] Đã thu thập {len(log_entries)} RDP events từ PowerShell")
            
            return log_entries
            
        except Exception as e:
            print(f"[LỖI] Collect logs failed: {e}")
            import traceback
            print(f"[CHI TIẾT] {traceback.format_exc()}")
            return []

    def _send_alerts_filtered(self, rdp_events):
        """Gửi cảnh báo chỉ cho events chưa xử lý."""
        if not rdp_events:
            return

        # Filter out events đã xử lý
        new_events = []
        for event in rdp_events:
            if not self._is_event_processed(event):
                new_events.append(event)
                self._mark_event_processed(event)

        if not new_events:
            print("[THÔNG TIN] Tất cả RDP events đã được xử lý trước đó - không gửi cảnh báo")
            return

        print(f"[CẢNH BÁO] Gửi cảnh báo cho {len(new_events)} events mới (bỏ qua {len(rdp_events) - len(new_events)} events đã xử lý)")

        # Tạo message chỉ cho events mới
        users = set(e.get('full_user', 'Unknown') for e in new_events)
        ips = set(e.get('source_ip', 'Unknown') for e in new_events if e.get('source_ip') != 'Unknown')
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        session_details = []
        for event in new_events[:10]:  # Giới hạn 10 entries
            detail = f"• {event.get('full_user', 'Unknown')}"
            if event.get('source_ip') != 'Unknown':
                detail += f" từ {event.get('source_ip')}"
            session_details.append(detail)

        message = (
            f"🖥️ CẢNH BÁO RDP: Phát hiện đăng nhập từ xa MỚI\n\n"
            f"👥 Người dùng: {', '.join(users)}\n"
            f"🌐 IP nguồn: {', '.join(ips) if ips else 'Unknown'}\n"
            f"🔍 Phương thức: PowerShell Get-WinEvent (Time Filtered)\n"
            f"📊 Events mới: {len(new_events)}\n"
            f"⏰ Thời gian phát hiện: {current_time}\n\n"
            f"📋 Chi tiết:\n" + "\n".join(session_details)
        )

        if len(new_events) > 10:
            message += f"\n... và {len(new_events) - 10} events mới khác"

        self._send_telegram(message)
        self._send_gmail("🔒 CẢNH BÁO: RDP Activity MỚI Detected", message)

        # Lưu processed events
        self._save_processed_events()

    def _send_telegram(self, message):
        """Gửi cảnh báo qua Telegram."""
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {'chat_id': self.telegram_chat_id, 'text': message}

        try:
            requests.post(url, data=payload, timeout=10, proxies=self.telegram_proxy, verify=False)
            print("[THÀNH CÔNG] Đã gửi cảnh báo Telegram")
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
            print("[THÀNH CÔNG] Đã gửi cảnh báo Gmail")
        except Exception as e:
            print(f"[LỖI] Gửi Gmail thất bại: {e}")

    def export_to_csv(self, logs, filename='rdp_powershell_logs.csv'):
        """Xuất logs RDP ra file CSV."""
        if not logs:
            return

        fieldnames = [
            'timestamp', 'log_type', 'source', 'event_id', 'type', 
            'category', 'message', 'mac_address', 
            'rdp_user', 'rdp_domain', 'rdp_source_ip', 'rdp_full_user', 'detection_method'
        ]

        try:
            with open(filename, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                if f.tell() == 0:
                    writer.writeheader()

                for log in logs:
                    rdp_info = log.get('rdp_info', {})
                    row = {
                        'timestamp': log.get('timestamp', ''),
                        'log_type': log.get('log_type', ''),
                        'source': log.get('source', ''),
                        'event_id': log.get('event_id', ''),
                        'type': log.get('type', ''),
                        'category': log.get('category', ''),
                        'message': log.get('message', ''),
                        'mac_address': log.get('mac_address', ''),
                        'rdp_user': rdp_info.get('user', '') if rdp_info else '',
                        'rdp_domain': rdp_info.get('domain', '') if rdp_info else '',
                        'rdp_source_ip': rdp_info.get('source_ip', '') if rdp_info else '',
                        'rdp_full_user': rdp_info.get('full_user', '') if rdp_info else '',
                        'detection_method': rdp_info.get('detection_method', '') if rdp_info else ''
                    }
                    writer.writerow(row)

            print(f"[THÀNH CÔNG] Đã xuất {len(logs)} bản ghi RDP")
        except Exception as e:
            print(f"[LỖI] Không thể xuất CSV: {e}")


# Alias để tương thích với code cũ
RDPEventLogMonitor = RDPPowerShellMonitor
