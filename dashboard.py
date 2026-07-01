from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
import threading
import queue
import json
import os
import time
from collections import defaultdict

from scapy.all import IP, TCP
from packet_capture_engine import PacketCapture
from traffic_analysis_module import TrafficAnalyzer
from detection_engine import DetectionEngine
from alert_system import AlertSystem

app = Flask(__name__)
CORS(app)


class CaptureManager:
    def __init__(self):
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()

        self._packet_capture = None
        self._capture_thread = None
        self._processing_thread = None
        self.running = False

        self._stats = {
            'total': 0,
            'normal': 0,
            'attacks': 0,
            'anomalies': 0
        }
        self._traffic_history = []  # [{t: ISO, pps: float}]
        self._lock = threading.Lock()

    # ── Live capture ─────────────────────────────────────

    def start_capture(self, interface="eth0"):
        if self.running:
            return False

        self._reset_stats()
        self._packet_capture = PacketCapture()
        self.running = True

        self._packet_capture.start_capture(interface)
        self._processing_thread = threading.Thread(
            target=self._processing_loop, daemon=True
        )
        self._processing_thread.start()

        self._capture_thread = threading.Thread(
            target=self._rate_tracker, daemon=True
        )
        self._capture_thread.start()
        return True

    def stop_capture(self):
        if not self.running:
            return False
        self.running = False
        if self._packet_capture:
            self._packet_capture.stop()
        return True

    def _processing_loop(self):
        while self.running:
            try:
                packet = self._packet_capture.packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            features = self.traffic_analyzer.analyze_packet(packet)
            if not features:
                continue

            with self._lock:
                self._stats['total'] += 1

            threats = self.detection_engine.detect_threats(features)
            if threats:
                for t in threats:
                    if t['type'] == 'signature':
                        with self._lock:
                            self._stats['attacks'] += 1
                    elif t['type'] == 'anomaly':
                        with self._lock:
                            self._stats['anomalies'] += 1

                packet_info = {
                    'source_ip': packet[IP].src,
                    'destination_ip': packet[IP].dst,
                    'source_port': packet[TCP].sport,
                    'destination_port': packet[TCP].dport,
                }
                for t in threats:
                    self.alert_system.generate_alert(t, packet_info)
            else:
                with self._lock:
                    self._stats['normal'] += 1

    def _rate_tracker(self):
        last_time = time.time()
        count = 0
        while self.running:
            time.sleep(1)
            now = time.time()
            elapsed = now - last_time
            pps = count / elapsed if elapsed > 0 else 0
            with self._lock:
                self._traffic_history.append({
                    't': time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(now)),
                    'pps': round(pps, 1),
                })
                if len(self._traffic_history) > 60:
                    self._traffic_history.pop(0)
            count = 0
            last_time = now

        # Drain remaining count on stop
        if count > 0:
            with self._lock:
                self._traffic_history.append({
                    't': time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(time.time())),
                    'pps': 0,
                })

    # ── Test mode (offline, synchronous) ─────────────────

    def run_test(self):
        self._reset_stats()

        def _p(src, dst, sport, dport, flags, count):
            return [IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
                    for _ in range(count)]

        packets = (
            _p("192.168.1.1", "192.168.1.2", 1234, 80,  "A", 1) +
            _p("192.168.1.1", "192.168.1.2", 1234, 80,  "P", 2) +
            _p("192.168.1.3", "192.168.1.4", 1235, 443, "A", 1) +
            _p("192.168.1.3", "192.168.1.4", 1235, 443, "P", 1) +
            _p("10.0.0.1",   "192.168.1.2", 5678, 80,  "S", 12) +
            _p("192.168.1.100", "192.168.1.2", 4321, 22, "S", 12)
        )

        # Use a fresh analyzer + detector for test isolation
        analyzer = TrafficAnalyzer()
        detector = DetectionEngine()

        for packet in packets:
            features = analyzer.analyze_packet(packet)
            if not features:
                continue
            with self._lock:
                self._stats['total'] += 1
            threats = detector.detect_threats(features)
            if threats:
                for t in threats:
                    if t['type'] == 'signature':
                        with self._lock:
                            self._stats['attacks'] += 1
                    elif t['type'] == 'anomaly':
                        with self._lock:
                            self._stats['anomalies'] += 1
                packet_info = {
                    'source_ip': packet[IP].src,
                    'destination_ip': packet[IP].dst,
                    'source_port': packet[TCP].sport,
                    'destination_port': packet[TCP].dport,
                }
                for t in threats:
                    self.alert_system.generate_alert(t, packet_info)
            else:
                with self._lock:
                    self._stats['normal'] += 1

        # Synthesize traffic history for test mode
        with self._lock:
            self._traffic_history = [
                {'t': time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(time.time() - (29 - i))),
                 'pps': round(5 + (15 if 10 <= i < 20 else 0) + (80 if 10 <= i < 20 else 0) + (2 if i >= 20 else 0) * (i % 3), 1)}
                for i in range(30)
            ]

    # ── Internal ─────────────────────────────────────────

    def _reset_stats(self):
        with self._lock:
            self._stats = {'total': 0, 'normal': 0, 'attacks': 0, 'anomalies': 0}
            self._traffic_history.clear()

    def get_stats(self):
        with self._lock:
            return dict(self._stats)

    def get_traffic_history(self):
        with self._lock:
            return list(self._traffic_history)

    def get_alerts(self, limit=100):
        log_file = "ids_alerts.log"
        if not os.path.exists(log_file):
            return []
        alerts = []
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(" - ", 2)
                    if len(parts) == 3:
                        alert = json.loads(parts[2])
                        alerts.append(alert)
        except (json.JSONDecodeError, OSError):
            pass
        return alerts[-limit:]

    def clear(self):
        with self._lock:
            self._stats = {'total': 0, 'normal': 0, 'attacks': 0, 'anomalies': 0}
            self._traffic_history.clear()
        open("ids_alerts.log", 'w').close()


capture_manager = CaptureManager()


# ── Routes ───────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('dashboard.html')


@app.route('/api/status')
def api_status():
    return jsonify({
        'running': capture_manager.running,
        'mode': 'live',
    })


@app.route('/api/start', methods=['POST'])
def api_start():
    interface = request.json.get('interface', 'eth0')
    success = capture_manager.start_capture(interface)
    return jsonify({'success': success})


@app.route('/api/stop', methods=['POST'])
def api_stop():
    capture_manager.stop_capture()
    return jsonify({'success': True})


@app.route('/api/test', methods=['POST'])
def api_test():
    capture_manager.run_test()
    return jsonify({'success': True})


@app.route('/api/stats')
def api_stats():
    return jsonify(capture_manager.get_stats())


@app.route('/api/traffic')
def api_traffic():
    return jsonify(capture_manager.get_traffic_history())


@app.route('/api/alerts')
def api_alerts():
    limit = request.args.get('limit', 100, type=int)
    return jsonify(capture_manager.get_alerts(limit))


@app.route('/api/clear', methods=['POST'])
def api_clear():
    capture_manager.clear()
    return jsonify({'success': True})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
