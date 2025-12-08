"""Flask web application for dashboard"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import logging
from pathlib import Path

app = Flask(__name__,
           template_folder=str(Path(__file__).parent / 'templates'),
           static_folder=str(Path(__file__).parent / 'static'))
app.config['SECRET_KEY'] = 'netport-anomaly-detector-secret'

socketio = SocketIO(app, cors_allowed_origins="*")
logger = logging.getLogger(__name__)

# Global state
dashboard_state = {
    'packets': [],
    'anomalies': [],
    'statistics': {
        'total_packets': 0,
        'total_anomalies': 0,
        'detection_rate': 0.0,
        'top_sources': [],
        'top_ports': [],
        'protocol_distribution': {},
        'anomaly_types': {}
    },
    'is_running': False
}

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/status')
def get_status():
    return jsonify({
        'is_running': dashboard_state['is_running'],
        'total_packets': dashboard_state['statistics']['total_packets'],
        'total_anomalies': dashboard_state['statistics']['total_anomalies']
    })

@app.route('/api/anomalies')
def get_anomalies():
    # Ten endpoint pozwala Dashboardowi pobrać historię po odświeżeniu
    limit = request.args.get('limit', 200, type=int)
    # Zwracamy ostatnie N anomalii
    return jsonify(dashboard_state['anomalies'][-limit:])

@app.route('/api/statistics')
def get_statistics():
    return jsonify(dashboard_state['statistics'])

@app.route('/api/clear')
def clear_data_api():
    clear_dashboard()
    return jsonify({'status': 'ok'})

def update_dashboard(packets, anomalies):
    """Update dashboard state with new data"""
    packet_dicts = [p.to_dict() for p in packets]
    anomaly_dicts = [a.to_dict() for a in anomalies]

    # 1. Aktualizacja globalnego stanu (dla nowych klientów / PCAP)
    dashboard_state['statistics']['total_packets'] += len(packets)
    dashboard_state['statistics']['total_anomalies'] += len(anomalies)

    dashboard_state['packets'].extend(packet_dicts)
    dashboard_state['anomalies'].extend(anomaly_dicts)

    # Przycinanie bufora (żeby nie zapchać pamięci RAM przy długim Live)
    if len(dashboard_state['packets']) > 2000:
        dashboard_state['packets'] = dashboard_state['packets'][-2000:]
    if len(dashboard_state['anomalies']) > 1000:
        dashboard_state['anomalies'] = dashboard_state['anomalies'][-1000:]

    # Przelicz statystyki
    _recalc_statistics()

    # 2. Wysyłka WebSocket (dla podłączonych klientów - Live/Symulator)
    socketio.emit('update', {
        'packets': packet_dicts, # Wysyłamy tylko nowe pakiety
        'anomalies': dashboard_state['anomalies'][-100:], # Ostatnie 100 anomalii do wykresów
        'statistics': dashboard_state['statistics']
    })

def _recalc_statistics():
    from collections import Counter

    total_packets = dashboard_state['statistics']['total_packets']
    total_anomalies = dashboard_state['statistics']['total_anomalies']
    all_anomalies = dashboard_state['anomalies']

    if total_packets > 0:
        dashboard_state['statistics']['detection_rate'] = (total_anomalies / total_packets * 100)

    # Top Sources & Ports (tylko z anomalii)
    src_ips = [a['source_ip'] for a in all_anomalies if a.get('source_ip')]
    dashboard_state['statistics']['top_sources'] = [
        {'ip': ip, 'count': count} for ip, count in Counter(src_ips).most_common(10)
    ]

    dst_ports = [a['port'] for a in all_anomalies if a.get('port')]
    dashboard_state['statistics']['top_ports'] = [
        {'port': p, 'count': c} for p, c in Counter(dst_ports).most_common(10)
    ]

    types = [a['type'] for a in all_anomalies if a.get('type')]
    dashboard_state['statistics']['anomaly_types'] = dict(Counter(types))

def set_running_state(is_running: bool):
    dashboard_state['is_running'] = is_running
    socketio.emit('status_change', {'is_running': is_running})

def clear_dashboard():
    dashboard_state['packets'] = []
    dashboard_state['anomalies'] = []
    dashboard_state['statistics'] = {
        'total_packets': 0, 'total_anomalies': 0, 'detection_rate': 0.0,
        'top_sources': [], 'top_ports': [], 'protocol_distribution': {}, 'anomaly_types': {}
    }
    socketio.emit('clear')

def run_dashboard(host='127.0.0.1', port=5000, debug=False):
    # Ukryj logi startowe Flask
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    logger.info(f"Starting dashboard on http://{host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)