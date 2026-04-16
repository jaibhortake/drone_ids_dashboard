"""
Standalone Demo: Real-Time Drone Intrusion Detection System
This script demonstrates the IDS functionality with simulated scenarios
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from collections import deque
from math import radians, cos, sin, asin, sqrt

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AttackType(Enum):
    GPS_SPOOFING = "GPS Spoofing"
    UNAUTHORIZED_ACCESS = "Unauthorized Access"
    COMMAND_INJECTION = "Command Injection"
    DOS_ATTACK = "Denial of Service"
    ANOMALOUS_BEHAVIOR = "Anomalous Behavior"
    UNAUTHORIZED_MODE_CHANGE = "Unauthorized Mode Change"


@dataclass
class Alert:
    timestamp: datetime
    threat_level: ThreatLevel
    attack_type: AttackType
    source: str
    description: str
    sensor_data: Dict
    recommended_action: str
    
    def to_dict(self):
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['threat_level'] = self.threat_level.name
        data['attack_type'] = self.attack_type.value
        return data


class NetworkMonitor:
    """Real-time network traffic monitoring"""
    
    def __init__(self, config: Dict):
        self.authorized_ips = set(config.get('authorized_ips', []))
        self.command_frequency = {}
        self.max_commands_per_second = config.get('max_commands_per_second', 10)
        
    def check_connection(self, source_ip: str, protocol: str) -> Optional[Alert]:
        if source_ip not in self.authorized_ips:
            return Alert(
                timestamp=datetime.now(),
                threat_level=ThreatLevel.HIGH,
                attack_type=AttackType.UNAUTHORIZED_ACCESS,
                source=source_ip,
                description=f"Unauthorized connection from {source_ip} via {protocol}",
                sensor_data={'ip': source_ip, 'protocol': protocol},
                recommended_action="Block connection immediately"
            )
        return None
    
    def check_command_rate(self, source_ip: str) -> Optional[Alert]:
        current_time = datetime.now()
        
        if source_ip not in self.command_frequency:
            self.command_frequency[source_ip] = deque(maxlen=100)
        
        self.command_frequency[source_ip].append(current_time)
        
        one_second_ago = current_time.timestamp() - 1.0
        recent_count = sum(
            1 for ts in self.command_frequency[source_ip]
            if ts.timestamp() > one_second_ago
        )
        
        if recent_count > self.max_commands_per_second:
            return Alert(
                timestamp=current_time,
                threat_level=ThreatLevel.CRITICAL,
                attack_type=AttackType.DOS_ATTACK,
                source=source_ip,
                description=f"Command flooding: {recent_count} commands/second",
                sensor_data={'ip': source_ip, 'frequency': recent_count},
                recommended_action="Rate limit or block source immediately"
            )
        return None


class GPSSpoofingDetector:
    """GPS spoofing detection"""
    
    def __init__(self, config: Dict):
        self.max_position_jump = config.get('max_position_jump', 100.0)
        self.min_satellites = config.get('min_satellites', 4)
        self.last_position = None
        
    def analyze_gps_message(self, gps_msg: Dict) -> Optional[Alert]:
        current_time = datetime.now()
        lat = gps_msg.get('lat', 0) / 1e7
        lon = gps_msg.get('lon', 0) / 1e7
        satellites = gps_msg.get('satellites_visible', 0)
        fix_type = gps_msg.get('fix_type', 0)
        
        if satellites < self.min_satellites:
            return Alert(
                timestamp=current_time,
                threat_level=ThreatLevel.MEDIUM,
                attack_type=AttackType.GPS_SPOOFING,
                source="GPS",
                description=f"Low satellite count: {satellites} (minimum: {self.min_satellites})",
                sensor_data={'satellites': satellites, 'fix_type': fix_type},
                recommended_action="Cross-reference with IMU data"
            )
        
        if self.last_position:
            distance = self._haversine_distance(
                self.last_position['lat'], self.last_position['lon'], lat, lon
            )
            time_delta = (current_time - self.last_position['timestamp']).total_seconds()
            
            if time_delta > 0 and distance > self.max_position_jump:
                return Alert(
                    timestamp=current_time,
                    threat_level=ThreatLevel.HIGH,
                    attack_type=AttackType.GPS_SPOOFING,
                    source="GPS",
                    description=f"Suspicious position jump: {distance:.2f}m in {time_delta:.2f}s",
                    sensor_data={'distance': distance, 'time_delta': time_delta},
                    recommended_action="Cross-validate with IMU, consider GPS spoofing"
                )
        
        self.last_position = {'lat': lat, 'lon': lon, 'timestamp': current_time}
        return None
    
    @staticmethod
    def _haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        R = 6371000
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        dlat, dlon = lat2 - lat1, lon2 - lon1
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        return R * 2 * asin(sqrt(a))


class BehavioralAnalyzer:
    """Behavioral analysis"""
    
    def __init__(self, config: Dict):
        self.authorized_modes = set(config.get('authorized_modes', ['STABILIZE', 'GUIDED', 'AUTO']))
        self.last_attitude = None
        
    def analyze_attitude(self, attitude_msg: Dict) -> Optional[Alert]:
        current_time = datetime.now()
        roll = attitude_msg.get('roll', 0)
        pitch = attitude_msg.get('pitch', 0)
        roll_deg = roll * 180 / 3.14159
        pitch_deg = pitch * 180 / 3.14159
        
        if abs(roll_deg) > 60 or abs(pitch_deg) > 60:
            return Alert(
                timestamp=current_time,
                threat_level=ThreatLevel.HIGH,
                attack_type=AttackType.ANOMALOUS_BEHAVIOR,
                source="IMU",
                description=f"Extreme attitude: roll={roll_deg:.1f}°, pitch={pitch_deg:.1f}°",
                sensor_data={'roll': roll_deg, 'pitch': pitch_deg},
                recommended_action="Activate stabilization or emergency landing"
            )
        return None
    
    def analyze_mode_change(self, mode: str, source: str) -> Optional[Alert]:
        if mode not in self.authorized_modes:
            return Alert(
                timestamp=datetime.now(),
                threat_level=ThreatLevel.HIGH,
                attack_type=AttackType.UNAUTHORIZED_MODE_CHANGE,
                source=source,
                description=f"Unauthorized mode change: {mode}",
                sensor_data={'mode': mode},
                recommended_action="Revert to safe mode immediately"
            )
        return None


class IDS:
    """Intrusion Detection System"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.network_monitor = NetworkMonitor(config.get('network', {}))
        self.gps_detector = GPSSpoofingDetector(config.get('gps', {}))
        self.behavioral_analyzer = BehavioralAnalyzer(config.get('behavioral', {}))
        self.alerts = []
        self.response_handlers = []
    
    def register_response_handler(self, handler: Callable):
        self.response_handlers.append(handler)
    
    async def handle_alert(self, alert: Alert):
        self.alerts.append(alert)
        logger.warning(f"ALERT [{alert.threat_level.name}]: {alert.attack_type.value} - {alert.description}")
        
        for handler in self.response_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(alert)
                else:
                    handler(alert)
            except Exception as e:
                logger.error(f"Handler error: {e}")
    
    def get_status(self) -> Dict:
        threat_counts = {}
        attack_type_counts = {}
        
        for alert in self.alerts:
            threat_counts[alert.threat_level.name] = threat_counts.get(alert.threat_level.name, 0) + 1
            attack_type_counts[alert.attack_type.value] = attack_type_counts.get(alert.attack_type.value, 0) + 1
        
        return {
            'total_alerts': len(self.alerts),
            'threat_levels': threat_counts,
            'attack_types': attack_type_counts,
            'recent_alerts': [alert.to_dict() for alert in self.alerts[-10:]]
        }


# Response Handlers
def console_handler(alert: Alert):
    try:
        colors = {
            ThreatLevel.LOW: '\033[94m',
            ThreatLevel.MEDIUM: '\033[93m',
            ThreatLevel.HIGH: '\033[91m',
            ThreatLevel.CRITICAL: '\033[95m',
        }
        reset = '\033[0m'
        color = colors.get(alert.threat_level, '')
        warning_symbol = '[!]'
        print(f"{color}{warning_symbol} [{alert.threat_level.name}] {alert.attack_type.value}: {alert.description}{reset}")
    except UnicodeEncodeError:
        # Fallback for Windows console encoding issues
        warning_symbol = '[!]'
        print(f"{warning_symbol} [{alert.threat_level.name}] {alert.attack_type.value}: {alert.description}")


DEFAULT_CONFIG = {
    'network': {
        'authorized_ips': ['127.0.0.1', '192.168.1.100'],
        'max_commands_per_second': 10
    },
    'gps': {
        'max_position_jump': 100.0,
        'min_satellites': 4
    },
    'behavioral': {
        'authorized_modes': ['STABILIZE', 'GUIDED', 'AUTO', 'RTL', 'LAND']
    }
}
