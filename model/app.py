from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from py4j.java_gateway import JavaGateway
from pwn import process
import json

status = 'off'
reset = 0
reset_boolean = False

EMPTY_DATA = {
    "Benign": 0,
    "Analysis": 0,
    "Backdoor": 0,
    "DoS": 0,
    "Exploits": 0,
    "Fuzzers": 0,
    "Generic": 0,
    "Reconnaissance": 0,
    "Shellcode": 0,
    "Worms": 0,
}

# Biến toàn cục để quản lý luồng gửi dữ liệu duy nhất
background_thread = None

def create_app(test_config=None):
    global app_get
    global model_server
    global req
    global data
    global config

    import copy
    data = copy.deepcopy(EMPTY_DATA)

    req = False
    model_server = process('./server.py')
    geteway = JavaGateway()
    app_get = geteway.entry_point
    app = Flask(__name__, instance_relative_config=True)
    
    # FIX LỖI 1: Thêm allow_eio3=True để chấp nhận các script cũ và xử lý CORS
    socketio = SocketIO(app, logger=True, cors_allowed_origins="*", allow_eio3=True)
    
    f = open('config.json', 'r')
    config = json.load(f)

    # Hàm chạy ngầm duy nhất: Tự động gửi dữ liệu cho AI/Dashboard mỗi 3 giây nếu IDS đang bật
    def send_predictions_background():
        global data, status
        while True:
            # Gửi đè (Broadcast) tới tất cả các Client đang kết nối mà không bị trùng lặp
            socketio.emit('predection', {'result': data})
            socketio.sleep(3)

    @app.route('/',)
    def index():
        global status, app_get, config
        if config['auto-start'] == 1:
            status = 'on'
            print("Starting IDS")
            app_get.startTrafficFlow()
        d = {"status": status,
             "auto_start": config["auto-start"],
             "level_threat": config["level-threat"],
             "reset_level": config["reset-level"]}
        return render_template("index.html", **d)

    @app.route('/start', methods=['POST'])
    def start():
        global app_get, status
        status = 'on'
        print("Starting IDS")
        app_get.startTrafficFlow()
        return "0"

    @app.route('/stop', methods=['POST'])
    def stop():
        global app_get, status
        status = 'off'
        print("Stopping")
        app_get.stopTrafficFlow()
        return "0"

    @app.route('/info/<attack>',)
    def info(attack):
        return render_template(f"{attack}.html")

    @app.route('/reset_traffic', methods=['POST'])
    def reset_traffic():
        global data, reset, reset_boolean
        import copy
        reset += 1
        reset_boolean = True
        print("Data reset!")
        data = copy.deepcopy(EMPTY_DATA)
        return "0"

    @app.route('/update_settings', methods=['GET', 'POST'])
    def update_settings():
        global config
        d = request.get_json()
        f = open('config.json', 'w')
        json.dump(d, f)
        f.close()
        config = d
        return jsonify(status="success")

    @app.route('/post-predict', methods=['POST'])
    def postpredict():
        global data, config
        received = request.get_json()
        print("Data received!")
        for key in received:
            if key in data:
                data[key] = received[key]
        print(data)
        return "1"

    @app.route('/reset_status', methods=['GET', 'POST'])
    def reset_status():
        global reset_boolean
        if request.method == 'POST':
            reset_boolean = False
            return '1'
        else:
            return jsonify(reset_boolean=str(reset_boolean))

    @socketio.on('connect')
    def test_connect():
        global background_thread
        print('client connected')
        # FIX LỖI 2: Khởi chạy luồng gửi dữ liệu hệ thống duy nhất khi có người kết nối đầu tiên
        if background_thread is None:
            background_thread = socketio.start_background_task(target=send_predictions_background)

    @socketio.on('disconnect')
    def test_disconnect():
        print('Client disconnected')

    # Các hàm cũ không còn cần vòng lặp while riêng nữa, tránh rò rỉ bộ nhớ
    @socketio.on('request_predection')
    def request_handle():
        print("Client requested prediction stream")
        emit('predection', {'result': data})

    @socketio.on('stop_predection')
    def stopping():
        print("Client stopped prediction stream")

    return [socketio, app]

if __name__ == '__main__':
    socketio, app = create_app()
    socketio.run(app, host='0.0.0.0', port=7777)