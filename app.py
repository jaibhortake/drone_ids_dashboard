"""
Flask Web Server for Drone IDS Dashboard
Real-time monitoring with WebSocket support
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import time
import json
import asyncio
from datetime import datetime
from typing import Dict, Optional
import logging

# Import IDS components
try:
    from demo_ids import (
        IDS, ThreatLevel, AttackType, Alert,
        DEFAULT_CONFIG
    )
except ImportError as e:
    print(f"Error: demo_ids.py not found. {e}")
    print("Please ensure demo_ids.py is in the same directory.")
    exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'drone_ids_secret_key_2024'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global IDS instance
ids_system = None
monitoring_thread = None
monitoring_active = False
real_time_mode = False


@app.route('/')
def index():
    """Serve the dashboard"""
    return render_template('dashboard.html')


@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current IDS status"""
    if ids_system is None:
        return jsonify({
            'running': False,
            'connected': False,
            'total_alerts': 0,
            'threat_levels': {},
            'attack_types': {}
        })
    
    status = ids_system.get_status()
    status['real_time_mode'] = real_time_mode
    status['monitoring_active'] = monitoring_active
    return jsonify(status)


@app.route('/api/config', methods=['GET', 'POST'])
def config():
    """Get or update configuration"""
    global ids_system
    
    if request.method == 'POST':
        config_data = request.json
        logger.info(f"Config update: {config_data}")
        return jsonify({'status': 'success'})
    
    return jsonify(DEFAULT_CONFIG)


@app.route('/api/test', methods=['POST'])
def run_test():
    """Run test scenarios"""
    global ids_system
    
    if ids_system is None:
        ids_system = IDS(DEFAULT_CONFIG)
        ids_system.register_response_handler(create_socket_alert_handler())
    
    test_type = request.json.get('test_type', 'all')
    
    # Run tests in background
    thread = threading.Thread(target=run_test_scenarios, args=(test_type,))
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'test_started', 'test_type': test_type})


@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info('Client connected')
    emit('status', {'message': 'Connected to IDS Server'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info('Client disconnected')


@socketio.on('start_real_time')
def handle_start_real_time(data):
    """Start real-time monitoring"""
    global monitoring_active, real_time_mode, ids_system
    
    connection_string = data.get('connection_string', 'udp:127.0.0.1:14550')
    
    if ids_system is None:
        ids_system = IDS(DEFAULT_CONFIG)
        ids_system.register_response_handler(create_socket_alert_handler())
    
    real_time_mode = True
    monitoring_active = True
    
    # Start monitoring in background thread
    thread = threading.Thread(
        target=start_real_time_monitoring,
        args=(connection_string,),
        daemon=True
    )
    thread.start()
    
    emit('status', {'message': f'Starting real-time monitoring: {connection_string}'})
    logger.info(f'Real-time monitoring started: {connection_string}')


@socketio.on('stop_real_time')
def handle_stop_real_time():
    """Stop real-time monitoring"""
    global monitoring_active, real_time_mode
    
    monitoring_active = False
    real_time_mode = False
    
    emit('status', {'message': 'Real-time monitoring stopped'})
    logger.info('Real-time monitoring stopped')


def create_socket_alert_handler():
    """Create alert handler that emits to WebSocket"""
    def handler(alert: Alert):
        alert_data = alert.to_dict()
        socketio.emit('new_alert', alert_data)
        logger.warning(f"Alert emitted: {alert.attack_type.value}")
    return handler


def run_test_scenarios(test_type: str):
    """Run test scenarios"""
    global ids_system
    
    if test_type == 'all' or test_type == 'unauthorized':
        time.sleep(0.5)
        alert = ids_system.network_monitor.check_connection('192.168.1.105', 'TCP')
        if alert:
            asyncio.run(ids_system.handle_alert(alert))
    
    if test_type == 'all' or test_type == 'gps_low':
        time.sleep(0.5)
        gps_data = {'lat': 407128000, 'lon': -74006000, 'satellites_visible': 2, 'fix_type': 2}
        alert = ids_system.gps_detector.analyze_gps_message(gps_data)
        if alert:
            asyncio.run(ids_system.handle_alert(alert))
    
    if test_type == 'all' or test_type == 'gps_jump':
        time.sleep(0.5)
        ids_system.gps_detector.analyze_gps_message({
            'lat': 407128000, 'lon': -74006000, 'satellites_visible': 12, 'fix_type': 3
        })
        time.sleep(0.3)
        gps_data2 = {'lat': 407128000 + 5000000, 'lon': -74006000 + 5000000, 
                    'satellites_visible': 12, 'fix_type': 3}
        alert = ids_system.gps_detector.analyze_gps_message(gps_data2)
        if alert:
            asyncio.run(ids_system.handle_alert(alert))
    
    if test_type == 'all' or test_type == 'attitude':
        time.sleep(0.5)
        attitude_data = {'roll': 1.2, 'pitch': 0.8, 'yaw': 0.5}
        alert = ids_system.behavioral_analyzer.analyze_attitude(attitude_data)
        if alert:
            asyncio.run(ids_system.handle_alert(alert))
    
    if test_type == 'all' or test_type == 'dos':
        time.sleep(0.5)
        for i in range(15):
            alert = ids_system.network_monitor.check_command_rate('192.168.1.105')
            if alert:
                asyncio.run(ids_system.handle_alert(alert))
                break
            time.sleep(0.05)
    
    if test_type == 'all' or test_type == 'mode':
        time.sleep(0.5)
        alert = ids_system.behavioral_analyzer.analyze_mode_change('ACRO', 'Unknown')
        if alert:
            asyncio.run(ids_system.handle_alert(alert))
    
    # Emit status update
    if ids_system:
        status = ids_system.get_status()
        socketio.emit('status_update', status)


def start_real_time_monitoring(connection_string: str):
    """Start real-time MAVLink monitoring"""
    global ids_system, monitoring_active
    
    try:
        # Try to import pymavlink
        try:
            from pymavlink import mavutil
            MAVLINK_AVAILABLE = True
        except ImportError:
            logger.error("pymavlink not installed. Install with: pip install pymavlink")
            socketio.emit('error', {
                'message': 'pymavlink not installed. Install with: pip install pymavlink'
            })
            return
        
        # Connect to drone
        logger.info(f"Connecting to drone: {connection_string}")
        socketio.emit('status', {'message': f'Connecting to {connection_string}...'})
        
        mav_connection = mavutil.mavlink_connection(connection_string)
        mav_connection.wait_heartbeat(timeout=10)
        
        socketio.emit('status', {'message': 'Connected to drone successfully'})
        logger.info("Connected to drone")
        
        # Monitor messages
        last_heartbeat = time.time()
        while monitoring_active:
            try:
                msg = mav_connection.recv_match(timeout=1.0)
                
                if msg is None:
                    if time.time() - last_heartbeat > 5.0:
                        socketio.emit('warning', {'message': 'Heartbeat timeout'})
                    continue
                
                msg_type = msg.get_type()
                
                if msg_type == 'HEARTBEAT':
                    last_heartbeat = time.time()
                    socketio.emit('heartbeat', {'timestamp': time.time()})
                
                elif msg_type == 'GPS_RAW_INT':
                    gps_data = {
                        'lat': msg.lat,
                        'lon': msg.lon,
                        'alt': msg.alt,
                        'satellites_visible': msg.satellites_visible,
                        'fix_type': msg.fix_type,
                    }
                    alert = ids_system.gps_detector.analyze_gps_message(gps_data)
                    if alert:
                        asyncio.run(ids_system.handle_alert(alert))
                
                elif msg_type == 'ATTITUDE':
                    attitude_data = {
                        'roll': msg.roll,
                        'pitch': msg.pitch,
                        'yaw': msg.yaw,
                        'rollspeed': msg.rollspeed,
                        'pitchspeed': msg.pitchspeed,
                        'yawspeed': msg.yawspeed,
                    }
                    alert = ids_system.behavioral_analyzer.analyze_attitude(attitude_data)
                    if alert:
                        asyncio.run(ids_system.handle_alert(alert))
                    
                    # Emit sensor data
                    socketio.emit('sensor_data', {
                        'type': 'attitude',
                        'data': attitude_data
                    })
                
            except Exception as e:
                logger.error(f"Error processing message: {e}")
                time.sleep(0.1)
        
        mav_connection.close()
        logger.info("Real-time monitoring stopped")
        
    except Exception as e:
        logger.error(f"Error in real-time monitoring: {e}")
        socketio.emit('error', {'message': str(e)})


if __name__ == '__main__':
    logger.info("Starting Drone IDS Web Server...")
    logger.info("Access dashboard at: http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
