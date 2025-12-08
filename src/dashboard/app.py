"""Flask web application for dashboard"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import json
import logging
from datetime import datetime
from pathlib import Path


app = Flask(__name__,
           template_folder=str(Path(__file__).parent / 'templates'),
           static_folder=str(Path(__file__).parent / 'static'))
app.config['SECRET_KEY'] = 'netport-anomaly-detector-secret'
socketio = SocketIO(app, cors_allowed_origins="*")

logger = logging.getLogger(__name__)

# Global state for dashboard
dashboard_state = {
    'packets': [],
    'anomalies': [],
    'statistics': {
        'total_packets': 0,
        'total_anomalies': 0,
        'detection_rate': 0.0,
        'top_sources': [],
        'top_ports': [],
        'protocol_distribution': {}
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


@app.route('/api/statistics')
def get_statistics():
    return jsonify(dashboard_state['statistics'])


@app.route('/api/anomalies')
def get_anomalies():
    limit = request.args.get('limit', 50, type=int)
    return jsonify(dashboard_state['anomalies'][-limit:])


@app.route('/api/packets')
def get_packets():
    limit = request.args.get('limit', 100, type=int)
    return jsonify(dashboard_state['packets'][-limit:])


def update_dashboard(packets, anomalies):
    """Update dashboard state with new data"""
    packet_dicts = [p.to_dict() for p in packets]
    anomaly_dicts = [a.to_dict() for a in anomalies]

    # ZWIĘKSZ LICZNIKI (zanim przytniemy listy!)
    dashboard_state['statistics']['total_packets'] += len(packets)
    dashboard_state['statistics']['total_anomalies'] += len(anomalies)

    # Update buffers
    dashboard_state['packets'].extend(packet_dicts)
    dashboard_state['anomalies'].extend(anomaly_dicts)

    # Keep only last 1000 packets for display
    if len(dashboard_state['packets']) > 1000:
        dashboard_state['packets'] = dashboard_state['packets'][-1000:]

    if len(dashboard_state['anomalies']) > 500:
        dashboard_state['anomalies'] = dashboard_state['anomalies'][-500:]

    # Update other statistics
    update_statistics(packets, anomalies)

    # Emit to connected clients
    socketio.emit('update', {
        'packets': packet_dicts,
        'anomalies': anomaly_dicts,
        'statistics': dashboard_state['statistics']
    })


def update_statistics(packets, anomalies):
    """Update dashboard statistics"""
    from collections import Counter

    all_packets = dashboard_state['packets']

    # Używamy globalnych liczników, a nie długości bufora!
    total_packets = dashboard_state['statistics']['total_packets']
    total_anomalies = dashboard_state['statistics']['total_anomalies']

    if total_packets > 0:
        dashboard_state['statistics']['detection_rate'] = (
            total_anomalies / total_packets * 100
        )

    # Top stats based on current buffer (approximation is fine for live view)
    src_ips = [p['src_ip'] for p in all_packets if 'src_ip' in p]
    src_counter = Counter(src_ips)
    dashboard_state['statistics']['top_sources'] = [
        {'ip': ip, 'count': count}
        for ip, count in src_counter.most_common(10)
    ]

    dst_ports = [p['dst_port'] for p in all_packets if 'dst_port' in p and p['dst_port'] > 0]
    port_counter = Counter(dst_ports)
    dashboard_state['statistics']['top_ports'] = [
        {'port': port, 'count': count}
        for port, count in port_counter.most_common(10)
    ]

    protocols = [p['protocol'] for p in all_packets if 'protocol' in p]
    proto_counter = Counter(protocols)
    dashboard_state['statistics']['protocol_distribution'] = dict(proto_counter)


def set_running_state(is_running: bool):
    dashboard_state['is_running'] = is_running
    socketio.emit('status_change', {'is_running': is_running})


def clear_dashboard():
    """Clear all dashboard data"""
    dashboard_state['packets'] = []
    dashboard_state['anomalies'] = []
    dashboard_state['statistics'] = {
        'total_packets': 0,
        'total_anomalies': 0,
        'detection_rate': 0.0,
        'top_sources': [],
        'top_ports': [],
        'protocol_distribution': {}
    }
    socketio.emit('clear')


@socketio.on('connect')
def handle_connect():
    logger.info("Client connected to dashboard")
    emit('status_change', {'is_running': dashboard_state['is_running']})


@socketio.on('disconnect')
def handle_disconnect():
    logger.info("Client disconnected from dashboard")


def run_dashboard(host='127.0.0.1', port=5000, debug=False):
    logger.info(f"Starting dashboard on http://{host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)