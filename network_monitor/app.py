from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from sheets import get_devices, get_unauthorized_devices, get_security_logs, get_system_logs, add_to_trusted_devices, remove_from_trusted_devices, add_to_blocked_devices, check_admin_role, get_rdp_logs
from dotenv import load_dotenv
import os
import hashlib

# Tải biến môi trường từ file .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  # Lấy SECRET_KEY từ file .env

# Route cho trang chính (dashboard)
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    devices = get_devices()
    unauthorized = get_unauthorized_devices()
    online_count = sum(1 for device in devices if device['is_online'])
    offline_count = sum(1 for device in devices if not device['is_online'])
    unauthorized_count = len(unauthorized)
    is_admin = check_admin_role(session['username'])
    return render_template('index.html', online_count=online_count, offline_count=offline_count, unauthorized_count=unauthorized_count, devices=devices, is_admin=is_admin)

# Route cho trang danh sách thiết bị
@app.route('/devices')
def devices():
    if 'username' not in session:
        return redirect(url_for('login'))
    devices = get_devices()
    is_admin = check_admin_role(session['username'])
    return render_template('devices.html', devices=devices, is_admin=is_admin)

# Route cho trang lịch sử log RDP
@app.route('/history_logRDP')
def history_logRDP():
    if 'username' not in session:
        return redirect(url_for('login'))
    logs = get_rdp_logs()
    is_admin = check_admin_role(session['username'])
    return render_template('history_logRDP.html', logs=logs, is_admin=is_admin)

# Route cho trang thiết bị lạ
@app.route('/unauthorized')
def unauthorized():
    if 'username' not in session:
        return redirect(url_for('login'))
    unauthorized = get_unauthorized_devices()
    is_admin = check_admin_role(session['username'])
    return render_template('unauthorized.html', unauthorized=unauthorized, is_admin=is_admin)

# Route cho trang SecurityLog
@app.route('/security_logs')
def security_logs():
    if 'username' not in session:
        return redirect(url_for('login'))
    logs = get_security_logs()
    is_admin = check_admin_role(session['username'])
    return render_template('security_logs.html', logs=logs, is_admin=is_admin)

# Route cho trang SystemLog
@app.route('/system_logs')
def system_logs():
    if 'username' not in session:
        return redirect(url_for('login'))
    logs = get_system_logs()
    is_admin = check_admin_role(session['username'])
    return render_template('system_logs.html', logs=logs, is_admin=is_admin)

# Route cho trang lịch sử hoạt động của một MAC address
@app.route('/device_history/<mac>')
def device_history(mac):
    if 'username' not in session:
        return redirect(url_for('login'))
    from sheets import get_data_from_sheet
    data = get_data_from_sheet("SNMPData", max_rows=100)
    history = [item for item in data if item['mac_address'].strip().upper() == mac.strip().upper()]
    is_admin = check_admin_role(session['username'])
    return render_template('device_history.html', history=history, mac=mac, is_admin=is_admin)

# Route để đăng ký tài khoản
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        from sheets import users_sheet
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        users = users_sheet.get_all_records()
        if any(user['username'] == username for user in users):
            return jsonify({"status": "error", "message": "Tên người dùng đã tồn tại"}), 400
        users_sheet.append_row([username, hashed_password, role])
        return jsonify({"status": "success", "message": f"Đăng ký thành công cho {username} với vai trò {role}"})
    return render_template('register.html')

# Route để đăng nhập
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        from sheets import users_sheet
        users = users_sheet.get_all_records()
        for user in users:
            if user['username'] == username and user['password'] == hashed_password:
                session['username'] = username
                return redirect(url_for('index'))
        return jsonify({"status": "error", "message": "Tên người dùng hoặc mật khẩu không đúng"}), 401
    return render_template('login.html')

# Route để đăng xuất
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# Route để thêm một thiết bị vào danh sách đăng ký (TrustDevices) với tên
@app.route('/register/<mac>', methods=['POST'])
def register_device(mac):
    if not check_admin_role(session.get('username', '')):
        return jsonify({"status": "error", "message": "Bạn không có quyền thực hiện hành động này"}), 403
    try:
        from sheets import trust_devices_sheet
        mac = mac.strip().upper()
        data = trust_devices_sheet.get_all_values()
        if not any(row[0].strip().upper() == mac for row in data if row):
            # Mở popup để nhập tên thiết bị
            return jsonify({"status": "prompt", "message": "Vui lòng nhập tên cho thiết bị", "mac": mac})
        return jsonify({"status": "error", "message": f"Thiết bị {mac} đã tồn tại"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Đã xảy ra lỗi khi đăng ký: {str(e)}"}), 500

# Route để lưu tên thiết bị sau khi nhập
@app.route('/save_device_name', methods=['POST'])
def save_device_name():
    if not check_admin_role(session.get('username', '')):
        return jsonify({"status": "error", "message": "Bạn không có quyền thực hiện hành động này"}), 403
    try:
        data = request.get_json()
        mac = data.get('mac').strip().upper()
        device_name = data.get('device_name', '').strip()
        from sheets import trust_devices_sheet, add_to_trusted_devices
        # Kiểm tra và thêm thiết bị với tên
        add_to_trusted_devices(mac, device_name)  # Sử dụng hàm đã cập nhật
        return jsonify({"status": "success", "message": f"Đã đăng ký thiết bị {mac} với tên {device_name}"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Đã xảy ra lỗi khi lưu tên: {str(e)}"}), 500

# Route để xóa một thiết bị khỏi danh sách đăng ký (TrustDevices)
@app.route('/unregister/<mac>', methods=['POST'])
def unregister_device(mac):
    if not check_admin_role(session.get('username', '')):
        return jsonify({"status": "error", "message": "Bạn không có quyền thực hiện hành động này"}), 403
    try:
        from sheets import remove_from_trusted_devices
        remove_from_trusted_devices(mac)
        return jsonify({"status": "success", "message": f"Đã xóa thiết bị {mac} khỏi danh sách đăng ký"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Đã xảy ra lỗi khi xóa: {str(e)}"}), 500

# Route để chặn một thiết bị (thêm vào BlockedDevices)
@app.route('/block/<mac>', methods=['POST'])
def block_device(mac):
    if not check_admin_role(session.get('username', '')):
        return jsonify({"status": "error", "message": "Bạn không có quyền thực hiện hành động này"}), 403
    try:
        from sheets import add_to_blocked_devices
        add_to_blocked_devices(mac)
        return jsonify({"status": "success", "message": f"Đã chặn thiết bị {mac}"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Đã xảy ra lỗi khi chặn: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)