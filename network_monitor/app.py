from flask import Flask, render_template, jsonify
from sheets import get_data_from_sheet, get_devices, get_network_stats, get_unauthorized_devices, get_security_logs, get_system_logs, add_to_trusted_devices, remove_from_trusted_devices, add_to_blocked_devices

app = Flask(__name__)

# Route cho trang chính (dashboard)
@app.route('/')
def index():
    devices = get_devices()
    unauthorized = get_unauthorized_devices()
    online_count = sum(1 for device in devices if device['is_online'])
    offline_count = sum(1 for device in devices if not device['is_online'])
    unauthorized_count = len(unauthorized)
    return render_template('index.html', online_count=online_count, offline_count=offline_count, unauthorized_count=unauthorized_count, devices=devices)

# Route cho trang danh sách thiết bị
@app.route('/devices')
def devices():
    devices = get_devices()
    return render_template('devices.html', devices=devices)

# Route cho trang tốc độ mạng
@app.route('/network_stats')
def network_stats():
    stats = get_network_stats()
    return render_template('network_stats.html', stats=stats)

# Route cho trang thiết bị lạ
@app.route('/unauthorized')
def unauthorized():
    unauthorized = get_unauthorized_devices()
    return render_template('unauthorized.html', unauthorized=unauthorized)

# Route cho trang SecurityLog
@app.route('/security_logs')
def security_logs():
    logs = get_security_logs()
    return render_template('security_logs.html', logs=logs)

# Route cho trang SystemLog
@app.route('/system_logs')
def system_logs():
    logs = get_system_logs()
    return render_template('system_logs.html', logs=logs)

# Route cho trang lịch sử hoạt động của một MAC address
@app.route('/device_history/<mac>')
def device_history(mac):
    data = get_data_from_sheet("SNMPData", max_rows=100)
    history = [item for item in data if item['mac_address'].strip().upper() == mac.strip().upper()]
    return render_template('device_history.html', history=history, mac=mac)

# Route để thêm một thiết bị vào danh sách đăng ký (TrustDevices)
@app.route('/register/<mac>', methods=['POST'])
def register_device(mac):
    try:
        add_to_trusted_devices(mac)
        return jsonify({"status": "success", "message": f"Đã đăng ký thiết bị {mac}"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Route để xóa một thiết bị khỏi danh sách đăng ký (TrustDevices)
@app.route('/unregister/<mac>', methods=['POST'])
def unregister_device(mac):
    try:
        remove_from_trusted_devices(mac)
        return jsonify({"status": "success", "message": f"Đã xóa thiết bị {mac} khỏi danh sách đăng ký"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Route để chặn một thiết bị (thêm vào BlockedDevices)
@app.route('/block/<mac>', methods=['POST'])
def block_device(mac):
    try:
        add_to_blocked_devices(mac)
        return jsonify({"status": "success", "message": f"Đã chặn thiết bị {mac}"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)