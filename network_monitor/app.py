from flask import Flask, render_template
from sheets import get_data_from_sheet, get_devices, get_network_stats, get_unauthorized_devices, get_security_logs, get_system_logs

app = Flask(__name__)

# Danh sách thiết bị được phép
ALLOWED_DEVICES = [
    ("192.168.1.10", "AA:BB:CC:DD:EE:FF"),
    ("192.168.1.11", "11:22:33:44:55:66")
]

# Route cho trang chính (dashboard)
@app.route('/')
def index():
    devices = get_devices()
    unauthorized = get_unauthorized_devices(ALLOWED_DEVICES)
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
    unauthorized = get_unauthorized_devices(ALLOWED_DEVICES)
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

# Route cho trang lịch sử hoạt động của một IP
@app.route('/device_history/<ip>')
def device_history(ip):
    data = get_data_from_sheet("SNMPData", max_rows=100)
    history = [item for item in data if item['ip_address'] == ip]
    return render_template('device_history.html', history=history, ip=ip)

if __name__ == '__main__':
    app.run(debug=True)