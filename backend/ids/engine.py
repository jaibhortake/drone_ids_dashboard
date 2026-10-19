"""IDS engine: routes MAVLink messages to detectors, de-duplicates, persists and fans out alerts."""

import logging
import threading
import time
from collections import deque
from collections.abc import Callable

from pymavlink import mavutil

from .config import merge_config
from .detectors import COMMAND_MESSAGES, BehavioralAnalyzer, GPSSpoofingDetector, LinkMonitor, NetworkMonitor
from .models import Alert, ThreatLevel
from .store import AlertStore

logger = logging.getLogger(__name__)
mavlink = mavutil.mavlink


class IDS:
    def __init__(self, config: dict, store: AlertStore | None = None):
        self._lock = threading.RLock()
        self.store = store
        self._handlers: list[Callable[[Alert], None]] = []
        self._last_fired: dict[tuple, float] = {}
        self.apply_config(config)

    # ---- configuration -------------------------------------------------
    def apply_config(self, config: dict) -> None:
        """Rebuild detectors from config (detector state resets; alert history is kept)."""
        with self._lock:
            self.config = config
            self.network = NetworkMonitor(config['network'])
            self.gps = GPSSpoofingDetector(config['gps'])
            self.behavior = BehavioralAnalyzer(config['behavioral'])
            self.link = LinkMonitor(config['link'])
            old = list(getattr(self, 'alerts', []))
            self.alerts: deque = deque(old, maxlen=config['alerts']['max_in_memory'])

    def update_config(self, override: dict) -> dict:
        self.apply_config(merge_config(self.config, override))
        return self.config

    def register_handler(self, handler: Callable[[Alert], None]) -> None:
        self._handlers.append(handler)

    # ---- alert pipeline ------------------------------------------------
    def handle_alert(self, alert: Alert, now: float | None = None) -> bool:
        """Record and broadcast an alert unless an identical one fired within the cooldown."""
        now = time.monotonic() if now is None else now
        key = (alert.attack_type, alert.source)
        with self._lock:
            last = self._last_fired.get(key)
            if last is not None and now - last < self.config['alerts']['cooldown_s']:
                return False
            self._last_fired[key] = now
            if self.store:
                self.store.add(alert)
            self.alerts.append(alert)
        logger.warning("ALERT [%s] %s - %s", alert.threat_level.name, alert.attack_type.value, alert.description)
        for handler in self._handlers:
            try:
                handler(alert)
            except Exception:
                logger.exception("alert handler failed")
        return True

    def process_message(self, msg, now: float | None = None, src_ip: str | None = None) -> list[Alert]:
        """Run every relevant detector on one decoded MAVLink message. Returns alerts actually raised."""
        now = time.monotonic() if now is None else now
        msg_type = msg.get_type()
        if msg_type == 'BAD_DATA':
            return []
        sysid = msg.get_srcSystem()
        candidates: list[Alert | None] = []

        with self._lock:
            candidates.append(self.network.check_source(sysid, src_ip))

            if msg_type in COMMAND_MESSAGES:
                candidates.append(self.network.check_command(msg_type, sysid))
                candidates.append(self.network.check_command_rate(f"sysid:{sysid}", now))

            if msg_type == 'HEARTBEAT' and self._is_vehicle(msg):
                self.link.heartbeat(now)
                candidates.append(self.behavior.analyze_mode(mavutil.mode_string_v10(msg), f"sysid:{sysid}"))
            elif msg_type == 'GPS_RAW_INT':
                candidates.append(self.gps.analyze_gps({
                    'lat': msg.lat, 'lon': msg.lon,
                    'satellites_visible': msg.satellites_visible, 'fix_type': msg.fix_type,
                }, now))
            elif msg_type == 'GLOBAL_POSITION_INT':
                self.gps.update_fused({'lat': msg.lat, 'lon': msg.lon}, now)
            elif msg_type == 'ATTITUDE':
                candidates.append(self.behavior.analyze_attitude({'roll': msg.roll, 'pitch': msg.pitch}))

        return [a for a in candidates if a is not None and self.handle_alert(a, now)]

    def tick(self, now: float | None = None) -> list[Alert]:
        """Time-based checks; call periodically while monitoring."""
        now = time.monotonic() if now is None else now
        with self._lock:
            alert = self.link.check(now)
        return [alert] if alert and self.handle_alert(alert, now) else []

    @staticmethod
    def _is_vehicle(msg) -> bool:
        return msg.type != mavlink.MAV_TYPE_GCS and msg.autopilot != mavlink.MAV_AUTOPILOT_INVALID

    # ---- queries -------------------------------------------------------
    def recent_alerts(self, limit: int = 50, min_level: ThreatLevel | None = None) -> list[Alert]:
        if self.store:
            return self.store.recent(limit, min_level)
        with self._lock:
            items = [a for a in reversed(self.alerts)
                     if min_level is None or a.threat_level.value >= min_level.value]
        return items[:limit]

    def acknowledge(self, alert_id: int) -> bool:
        with self._lock:
            for a in self.alerts:
                if a.id == alert_id:
                    a.acknowledged = True
        return self.store.acknowledge(alert_id) if self.store else False

    def get_status(self) -> dict:
        if self.store:
            counts = self.store.counts()
        else:
            with self._lock:
                alerts = list(self.alerts)
            counts = {'threat_levels': {}, 'attack_types': {},
                      'unacknowledged': sum(not a.acknowledged for a in alerts)}
            for a in alerts:
                counts['threat_levels'][a.threat_level.name] = counts['threat_levels'].get(a.threat_level.name, 0) + 1
                counts['attack_types'][a.attack_type.value] = counts['attack_types'].get(a.attack_type.value, 0) + 1
        return {
            'total_alerts': sum(counts['threat_levels'].values()),
            **counts,
            'flight_mode': self.behavior.current_mode,
        }
