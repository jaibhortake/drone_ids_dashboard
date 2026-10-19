"""Stateful detectors. Each takes plain values plus an explicit monotonic `now`, so they are
deterministic under test and independent of pymavlink."""

import math
from collections import deque

from .models import Alert, AttackType, ThreatLevel

# MAVLink messages that change vehicle state; only ground stations should send these.
COMMAND_MESSAGES = frozenset({
    'COMMAND_LONG', 'COMMAND_INT', 'SET_MODE', 'PARAM_SET',
    'MISSION_ITEM', 'MISSION_ITEM_INT', 'MISSION_COUNT', 'MISSION_CLEAR_ALL', 'MISSION_SET_CURRENT',
    'SET_POSITION_TARGET_LOCAL_NED', 'SET_POSITION_TARGET_GLOBAL_INT', 'SET_ATTITUDE_TARGET',
    'MANUAL_CONTROL', 'RC_CHANNELS_OVERRIDE',
})


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    lat1, lon1, lat2, lon2 = map(math.radians, (lat1, lon1, lat2, lon2))
    a = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 6371000 * 2 * math.asin(math.sqrt(a))


class NetworkMonitor:
    """Source allow-listing, command authorization and command-rate (DoS) detection."""

    def __init__(self, config: dict):
        self.authorized_ips = set(config.get('authorized_ips', []))
        self.authorized_system_ids = set(config.get('authorized_system_ids', []))
        self.authorized_gcs_ids = set(config.get('authorized_gcs_ids', []))
        self.max_commands_per_second = config.get('max_commands_per_second', 10)
        self._command_times: dict[str, deque] = {}

    def check_source(self, system_id: int | None = None, ip: str | None = None) -> Alert | None:
        if ip is not None and ip not in self.authorized_ips:
            return Alert(
                threat_level=ThreatLevel.HIGH,
                attack_type=AttackType.UNAUTHORIZED_ACCESS,
                source=ip,
                description=f"MAVLink traffic from unauthorized IP {ip}",
                sensor_data={'ip': ip, 'system_id': system_id},
                recommended_action="Block the address at the link/firewall",
            )
        if system_id is not None and system_id not in self.authorized_system_ids:
            return Alert(
                threat_level=ThreatLevel.HIGH,
                attack_type=AttackType.UNAUTHORIZED_ACCESS,
                source=f"sysid:{system_id}",
                description=f"Unknown MAVLink system ID {system_id} on the link",
                sensor_data={'system_id': system_id, 'ip': ip},
                recommended_action="Identify the transmitter; enable MAVLink2 message signing",
            )
        return None

    def check_command(self, msg_type: str, system_id: int) -> Alert | None:
        if msg_type in COMMAND_MESSAGES and system_id not in self.authorized_gcs_ids:
            return Alert(
                threat_level=ThreatLevel.CRITICAL,
                attack_type=AttackType.COMMAND_INJECTION,
                source=f"sysid:{system_id}",
                description=f"{msg_type} sent by unauthorized system ID {system_id}",
                sensor_data={'message': msg_type, 'system_id': system_id},
                recommended_action="Reject command; switch vehicle to failsafe/RTL",
            )
        return None

    def check_command_rate(self, source: str, now: float) -> Alert | None:
        times = self._command_times.setdefault(source, deque())
        times.append(now)
        while times and times[0] <= now - 1.0:
            times.popleft()
        if len(times) > self.max_commands_per_second:
            return Alert(
                threat_level=ThreatLevel.CRITICAL,
                attack_type=AttackType.DOS_ATTACK,
                source=source,
                description=f"Command flooding: {len(times)} commands/second",
                sensor_data={'source': source, 'frequency': len(times)},
                recommended_action="Rate limit or block source immediately",
            )
        return None


class GPSSpoofingDetector:
    """Signal quality, implied-speed jumps and raw-GPS vs fused-estimate divergence."""

    def __init__(self, config: dict):
        self.max_speed_mps = config.get('max_speed_mps', 30.0)
        self.min_satellites = config.get('min_satellites', 4)
        self.max_divergence_m = config.get('max_divergence_m', 50.0)
        self.last_position: dict | None = None
        self.last_fused: dict | None = None

    def analyze_gps(self, gps: dict, now: float) -> Alert | None:
        lat, lon = gps.get('lat', 0) / 1e7, gps.get('lon', 0) / 1e7
        satellites = gps.get('satellites_visible', 0)
        fix_type = gps.get('fix_type', 0)

        if satellites < self.min_satellites or fix_type < 3:
            # No usable fix: don't treat this sample as a reference position.
            return Alert(
                threat_level=ThreatLevel.MEDIUM,
                attack_type=AttackType.GPS_DEGRADATION,
                source="GPS",
                description=f"Weak GPS: {satellites} satellites, fix type {fix_type}",
                sensor_data={'satellites': satellites, 'fix_type': fix_type},
                recommended_action="Monitor; fall back to IMU/optical navigation if it persists",
            )

        previous, self.last_position = self.last_position, {'lat': lat, 'lon': lon, 't': now}

        if self.last_fused and now - self.last_fused['t'] < 2.0:
            divergence = haversine_m(lat, lon, self.last_fused['lat'], self.last_fused['lon'])
            if divergence > self.max_divergence_m:
                return Alert(
                    threat_level=ThreatLevel.HIGH,
                    attack_type=AttackType.GPS_SPOOFING,
                    source="GPS",
                    description=f"GPS disagrees with fused estimate by {divergence:.0f} m",
                    sensor_data={'divergence_m': round(divergence, 1)},
                    recommended_action="Distrust GPS; switch to non-GPS navigation and RTL",
                )

        if previous:
            dt = now - previous['t']
            distance = haversine_m(previous['lat'], previous['lon'], lat, lon)
            if dt > 0 and distance / dt > self.max_speed_mps:
                return Alert(
                    threat_level=ThreatLevel.HIGH,
                    attack_type=AttackType.GPS_SPOOFING,
                    source="GPS",
                    description=f"Position jump of {distance:.0f} m in {dt:.2f} s ({distance / dt:.0f} m/s)",
                    sensor_data={'distance_m': round(distance, 1), 'dt_s': round(dt, 3)},
                    recommended_action="Cross-validate with IMU; consider GPS spoofing",
                )
        return None

    def update_fused(self, position: dict, now: float) -> None:
        """Record GLOBAL_POSITION_INT (the autopilot's fused estimate) for divergence checks."""
        self.last_fused = {'lat': position.get('lat', 0) / 1e7, 'lon': position.get('lon', 0) / 1e7, 't': now}


class BehavioralAnalyzer:
    """Attitude envelope and flight-mode authorization."""

    def __init__(self, config: dict):
        self.authorized_modes = set(config.get('authorized_modes', []))
        self.max_tilt_deg = config.get('max_tilt_deg', 60.0)
        self.current_mode: str | None = None

    def analyze_attitude(self, attitude: dict) -> Alert | None:
        roll_deg = math.degrees(attitude.get('roll', 0))
        pitch_deg = math.degrees(attitude.get('pitch', 0))
        if abs(roll_deg) > self.max_tilt_deg or abs(pitch_deg) > self.max_tilt_deg:
            return Alert(
                threat_level=ThreatLevel.MEDIUM,
                attack_type=AttackType.FLIGHT_ANOMALY,
                source="IMU",
                description=f"Extreme attitude: roll={roll_deg:.1f}°, pitch={pitch_deg:.1f}°",
                sensor_data={'roll': round(roll_deg, 1), 'pitch': round(pitch_deg, 1)},
                recommended_action="Check for control takeover; stabilize or land",
            )
        return None

    def analyze_mode(self, mode: str, source: str) -> Alert | None:
        """Alert only on a transition into a mode that isn't authorized."""
        previous, self.current_mode = self.current_mode, mode
        if mode != previous and mode not in self.authorized_modes:
            return Alert(
                threat_level=ThreatLevel.HIGH,
                attack_type=AttackType.UNAUTHORIZED_MODE_CHANGE,
                source=source,
                description=f"Mode changed {previous or '?'} -> {mode}",
                sensor_data={'mode': mode, 'previous_mode': previous},
                recommended_action="Revert to a safe mode (RTL/LAND)",
            )
        return None


class LinkMonitor:
    """Raises one alert per heartbeat outage."""

    def __init__(self, config: dict):
        self.timeout_s = config.get('heartbeat_timeout_s', 5.0)
        self.last_heartbeat: float | None = None
        self.in_outage = False

    def heartbeat(self, now: float) -> None:
        self.last_heartbeat = now
        self.in_outage = False

    def check(self, now: float) -> Alert | None:
        if self.last_heartbeat is None or self.in_outage:
            return None
        silent = now - self.last_heartbeat
        if silent > self.timeout_s:
            self.in_outage = True
            return Alert(
                threat_level=ThreatLevel.HIGH,
                attack_type=AttackType.LINK_LOSS,
                source="link",
                description=f"No vehicle heartbeat for {silent:.1f} s (jamming or link failure)",
                sensor_data={'silent_s': round(silent, 1)},
                recommended_action="Confirm vehicle failsafe engaged; check for RF jamming",
            )
        return None
