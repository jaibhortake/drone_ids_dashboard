"""Flask + Socket.IO server for the Drone IDS dashboard.

Environment variables:
  IDS_TOKEN            shared access token (random one generated and logged if unset)
  IDS_HOST / IDS_PORT  bind address (default 127.0.0.1:5000)
  IDS_DEBUG            "1" to enable Flask debug (never on an untrusted network)
  IDS_SECRET_KEY       Flask secret key (random if unset)
  IDS_CONFIG           YAML config path (default backend/config.yaml)
  IDS_DB               SQLite path (default backend/alerts.db)
  IDS_ALLOWED_ORIGINS  comma-separated extra Socket.IO origins (default: same origin only)
"""

import csv
import hmac
import io
import json
import logging
import os
import secrets
import threading
import time
from functools import wraps
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory
from flask_socketio import SocketIO, disconnect

from ids import IDS, AlertStore, ConfigError, ThreatLevel, load_config
from ids.monitor import MavlinkMonitor
from ids.scenarios import SCENARIOS, run_scenarios

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger("ids.app")

BACKEND_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BACKEND_DIR.parent / 'frontend'
MAX_CONNECTION_STRING = 200


def create_app(token: str, config_path: str | None = None, db_path: str | None = None,
               allowed_origins: list | None = None):
    app = Flask(__name__, static_folder=None)
    app.config['SECRET_KEY'] = os.environ.get('IDS_SECRET_KEY') or secrets.token_hex(32)
    socketio = SocketIO(app, async_mode='threading', cors_allowed_origins=allowed_origins or None)

    ids = IDS(load_config(config_path), AlertStore(db_path or ':memory:'))
    state = {'monitor': None}
    monitor_lock = threading.Lock()

    def emit(event: str, data: dict) -> None:
        socketio.emit(event, data)

    def on_alert(alert):
        emit('new_alert', alert.to_dict())
        emit('status_update', ids.get_status())

    ids.register_handler(on_alert)

    def token_ok(candidate: str | None) -> bool:
        return bool(candidate) and hmac.compare_digest(candidate.encode(), token.encode())

    def require_token(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            header = request.headers.get('Authorization', '')
            if not token_ok(header.removeprefix('Bearer ').strip()):
                return jsonify({'error': 'unauthorized'}), 401
            return view(*args, **kwargs)
        return wrapper

    def monitor_running() -> bool:
        return state['monitor'] is not None and state['monitor'].running

    # ---- frontend (static, holds no data) ------------------------------
    @app.route('/')
    def index():
        return send_from_directory(FRONTEND_DIR, 'index.html')

    @app.route('/<path:path>')
    def frontend_files(path):
        return send_from_directory(FRONTEND_DIR, path)

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
        resp.headers.setdefault('X-Frame-Options', 'DENY')
        resp.headers.setdefault('Referrer-Policy', 'no-referrer')
        resp.headers.setdefault(
            'Content-Security-Policy',
            "default-src 'self'; img-src 'self' data: https://*.tile.openstreetmap.org; "
            "connect-src 'self' ws: wss:; style-src 'self'; script-src 'self'")
        return resp

    # ---- REST API -------------------------------------------------------
    @app.get('/api/status')
    @require_token
    def status():
        return jsonify({**ids.get_status(), 'monitoring_active': monitor_running()})

    @app.get('/api/config')
    @require_token
    def get_config():
        return jsonify(ids.config)

    @app.post('/api/config')
    @require_token
    def post_config():
        try:
            return jsonify(ids.update_config(request.get_json(silent=True)))
        except ConfigError as exc:
            return jsonify({'error': str(exc)}), 400

    @app.get('/api/alerts')
    @require_token
    def list_alerts():
        limit = min(request.args.get('limit', 50, type=int), 500)
        level = request.args.get('min_level', '').upper()
        if level and level not in ThreatLevel.__members__:
            return jsonify({'error': 'invalid min_level'}), 400
        alerts = ids.recent_alerts(limit, ThreatLevel[level] if level else None)
        return jsonify([a.to_dict() for a in alerts])

    @app.post('/api/alerts/<int:alert_id>/ack')
    @require_token
    def ack_alert(alert_id):
        if not ids.acknowledge(alert_id):
            return jsonify({'error': 'not found'}), 404
        emit('status_update', ids.get_status())
        return jsonify({'id': alert_id, 'acknowledged': True})

    @app.get('/api/alerts/export')
    @require_token
    def export_alerts():
        fmt = request.args.get('format', 'json')
        rows = [a.to_dict() for a in ids.store.all()]
        if fmt == 'json':
            return Response(json.dumps(rows, indent=2), mimetype='application/json',
                            headers={'Content-Disposition': 'attachment; filename=alerts.json'})
        if fmt == 'csv':
            buf = io.StringIO()
            fields = ['id', 'timestamp', 'threat_level', 'attack_type', 'source',
                      'description', 'recommended_action', 'acknowledged', 'sensor_data']
            writer = csv.DictWriter(buf, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                writer.writerow({**row, 'sensor_data': json.dumps(row['sensor_data'])})
            return Response(buf.getvalue(), mimetype='text/csv',
                            headers={'Content-Disposition': 'attachment; filename=alerts.csv'})
        return jsonify({'error': 'format must be json or csv'}), 400

    @app.post('/api/test')
    @require_token
    def run_test():
        test_type = (request.get_json(silent=True) or {}).get('test_type', 'all')
        if test_type != 'all' and test_type not in SCENARIOS:
            return jsonify({'error': f'unknown test_type; choose all or one of {sorted(SCENARIOS)}'}), 400
        raised = run_scenarios(ids, test_type, time.monotonic())
        return jsonify({'status': 'completed', 'test_type': test_type, 'alerts_raised': len(raised)})

    @app.get('/api/scenarios')
    @require_token
    def list_scenarios():
        return jsonify(sorted(SCENARIOS))

    # ---- Socket.IO ------------------------------------------------------
    @socketio.on('connect')
    def on_connect(auth):
        if not token_ok((auth or {}).get('token')):
            logger.warning("rejected socket connection with bad token")
            return False
        socketio.emit('status_update', ids.get_status(), to=request.sid)
        socketio.emit('monitor_state', {'running': monitor_running()}, to=request.sid)

    @socketio.on('start_monitoring')
    def on_start(data):
        conn = (data or {}).get('connection_string', '')
        if not isinstance(conn, str) or not conn or len(conn) > MAX_CONNECTION_STRING:
            socketio.emit('monitor_error', {'message': 'Invalid connection string'}, to=request.sid)
            return
        with monitor_lock:
            if monitor_running():
                socketio.emit('monitor_error', {'message': 'Monitoring already running'}, to=request.sid)
                return
            state['monitor'] = MavlinkMonitor(ids, conn, emit)
            state['monitor'].start()
        logger.info("monitoring started on %s", conn)

    @socketio.on('stop_monitoring')
    def on_stop():
        with monitor_lock:
            monitor, state['monitor'] = state['monitor'], None
        if monitor:
            monitor.stop()

    @socketio.on_error_default
    def on_socket_error(exc):
        logger.exception("socket handler error: %s", exc)
        disconnect()

    app.extensions['ids'] = ids
    return app, socketio


def main():
    token = os.environ.get('IDS_TOKEN')
    if not token:
        token = secrets.token_urlsafe(24)
        logger.warning("IDS_TOKEN not set; generated one for this run: %s", token)
    host = os.environ.get('IDS_HOST', '127.0.0.1')
    port = int(os.environ.get('IDS_PORT', '5000'))
    debug = os.environ.get('IDS_DEBUG') == '1'
    origins = [o.strip() for o in os.environ.get('IDS_ALLOWED_ORIGINS', '').split(',') if o.strip()]
    app, socketio = create_app(
        token,
        config_path=os.environ.get('IDS_CONFIG', str(BACKEND_DIR / 'config.yaml')),
        db_path=os.environ.get('IDS_DB', str(BACKEND_DIR / 'alerts.db')),
        allowed_origins=origins,
    )
    logger.info("Dashboard: http://%s:%d/#token=%s", host, port, token)
    # Werkzeug is acceptable for this single-operator tool; debug stays off unless IDS_DEBUG=1.
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    main()
