import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from snmp_monitor import SNMPMonitor, discover_snmp_hosts
from config import Config

def monitor_single_host(ip, community=None):
    
    if community is None:
        community = Config.SNMP_COMMUNITY
        
    try:
        monitor = SNMPMonitor(ip, community=community)
        data = monitor.collect_all_metrics()
        
        if data and data.get('state') == 'on':
            print(f"[OK] Thu thập dữ liệu từ {ip} thành công")
            return data
        else:
            print(f"[CẢNH BÁO] Thiết bị {ip} offline hoặc không phản hồi")
            return data  
            
    except Exception as e:
        print(f"[LỖI] Lỗi giám sát {ip}: {e}")
        return None

def batch_export_to_sheets(all_data, sheet_name=None, tab_name="SNMPData"):
    """Xuất tất cả dữ liệu với cơ chế fallback"""
    if sheet_name is None:
        sheet_name = Config.GOOGLE_SHEET_NAME
        
    try:
        from sheets_writer import GoogleSheetsWriter
        writer = GoogleSheetsWriter(Config.GOOGLE_CREDENTIALS_FILE, sheet_name)
        
        # Lọc bỏ dữ liệu None
        valid_data = [data for data in all_data if data is not None]
        
        if not valid_data:
            print("[CẢNH BÁO] Không có dữ liệu hợp lệ để ghi")
            return
        
        # Thử batch write trước
        try:
            if hasattr(writer, 'write_logs_batch'):
                writer.write_logs_batch(tab_name, valid_data)
                print(f"[OK] Ghi hàng loạt {len(valid_data)} thiết bị vào Google Sheet")
            else:
                # Fallback sang ghi từng cái
                for i, data in enumerate(valid_data):
                    writer.write_logs(tab_name, [data])
                    if i % 5 == 0:  # Hiển thị tiến độ
                        print(f"[THÔNG TIN] Đã ghi {i+1}/{len(valid_data)} thiết bị...")
                print(f"[OK] Đã ghi {len(valid_data)} thiết bị vào Google Sheet")
                
        except Exception as batch_error:
            print(f"[CẢNH BÁO] Ghi hàng loạt thất bại: {batch_error}")
            print("[THÔNG TIN] Chuyển sang chế độ ghi từng cái...")
            
            # Ghi từng cái fallback
            success_count = 0
            for i, data in enumerate(valid_data):
                try:
                    writer.write_logs(tab_name, [data])
                    success_count += 1
                    time.sleep(0.1)  # Giới hạn tốc độ
                except Exception as e:
                    print(f"[LỖI] Ghi dòng {i+1} thất bại: {e}")
            
            print(f"[OK] Ghi từng cái hoàn thành: {success_count}/{len(valid_data)} thành công")
            
    except ImportError:
        print("[LỖI] Không thể import GoogleSheetsWriter. Kiểm tra file sheets_writer.py")
    except Exception as e:
        print(f"[LỖI] Xuất dữ liệu thất bại: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("HỆ THỐNG GIÁM SÁT SNMP - VERSION 1.0.0")
    print("=" * 60)
    
    start_time = time.time()
    
    # Bước 1: Quét thiết bị (sử dụng cấu hình mặc định từ Config)
    print(f"[THÔNG TIN] Bắt đầu khám phá thiết bị SNMP trên {Config.SNMP_SUBNET}...")
    available_hosts = discover_snmp_hosts()  # Không cần truyền tham số
    print(f"[THÔNG TIN] Phát hiện {len(available_hosts)} thiết bị SNMP: {available_hosts}")
    
    if not available_hosts:
        print("[CẢNH BÁO] Không tìm thấy thiết bị SNMP nào!")
        print("[THÔNG TIN] Kiểm tra:")
        print("  - Kết nối mạng")
        print("  - Chuỗi community SNMP")
        print("  - Cài đặt tường lửa")
        exit(1)
    
    # Bước 2: Giám sát đồng thời
    print(f"[THÔNG TIN] Bắt đầu giám sát {len(available_hosts)} thiết bị với {Config.MAX_WORKERS} luồng...")
    all_data = []
    
    with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
        # Gửi tất cả tác vụ
        future_to_ip = {
            executor.submit(monitor_single_host, ip): ip 
            for ip in available_hosts
        }
        
        # Thu thập kết quả với theo dõi tiến độ
        completed = 0
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            completed += 1
            
            try:
                result = future.result(timeout=60)  # Tăng timeout lên 60s
                if result:
                    all_data.append(result)
                    
                print(f"[TIẾN ĐỘ] {completed}/{len(available_hosts)} thiết bị hoàn thành")
                
            except Exception as e:
                print(f"[LỖI] Luồng giám sát {ip} thất bại: {e}")
    
    # Bước 3: Xuất dữ liệu vào Google Sheets
    if all_data:
        print(f"[THÔNG TIN] Bắt đầu xuất {len(all_data)} bản ghi vào Google Sheets...")
        batch_export_to_sheets(all_data)  # Sử dụng cấu hình mặc định
    else:
        print("[CẢNH BÁO] Không có dữ liệu để xuất!")
    
    # Bước 4: Tóm tắt
    end_time = time.time()
    duration = end_time - start_time
    
    print("=" * 60)
    print("KẾT QUẢ GIÁM SÁT")
    print("=" * 60)
    print(f"Thời gian thực hiện: {duration:.2f} giây")
    print(f"Thiết bị phát hiện: {len(available_hosts)}")
    print(f"Dữ liệu thu thập: {len(all_data)}")
    print(f"Tỷ lệ thành công: {len(all_data)}/{len(available_hosts)} ({len(all_data)/len(available_hosts)*100:.1f}%)")
    
    if duration > 0:
        throughput = len(available_hosts) / duration
        print(f"Hiệu suất: {throughput:.2f} thiết bị/giây")
    
    print("=" * 60)
