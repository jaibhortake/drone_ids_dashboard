"""Live MAVLink monitoring loop running in a background thread."""

import logging
import math
import threading
import time
from collections.abc import Callable

from pymavlink import mavutil

from .engine import IDS

logger = logging.getLogger(__name__)

Emit = Callable[[str, dict], None]


class MavlinkMonitor:
    TELEMETRY_INTERVAL_S = 0.2

    def __init__(self, ids: IDS, connection_string: str, emit: Emit, heartbeat_wait_s: float = 10.0):
        self.ids = ids
        self.connection_string = connection_string
        self.emit = emit
        self.heartbeat_wait_s = heartbeat_wait_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_telemetry = 0.0

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="mavlink-monitor", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)

    def _run(self) -> None:
        conn = None
        try:
            self.emit('status', {'message': f'Connecting to {self.connection_string}...'})
            conn = mavutil.mavlink_connection(self.connection_string, source_system=254)
            if conn.wait_heartbeat(timeout=self.heartbeat_wait_s) is None:
                self.emit('monitor_error', {'message': 'No heartbeat received; check the connection string'})
                return
            self.emit('status', {'message': 'Connected to vehicle'})
            self.emit('monitor_state', {'running': True})
            while not self._stop.is_set():
                msg = conn.recv_match(blocking=True, timeout=0.5)
                now = time.monotonic()
                if msg is not None:
                    address = getattr(conn, 'last_address', None)
                    self.ids.process_message(msg, now, src_ip=address[0] if address else None)
                    self._telemetry(msg, now)
                self.ids.tick(now)
        except Exception as exc:
            logger.exception("monitor failed")
            self.emit('monitor_error', {'message': f'Monitoring error: {exc}'})
        finally:
            if conn is not None:
                conn.close()
            self.emit('monitor_state', {'running': False})
            logger.info("monitoring stopped")

    def _telemetry(self, msg, now: float) -> None:
        msg_type = msg.get_type()
        if msg_type == 'HEARTBEAT' and self.ids._is_vehicle(msg):
            self.emit('vehicle', {'mode': mavutil.mode_string_v10(msg), 'sysid': msg.get_srcSystem()})
        elif msg_type == 'GLOBAL_POSITION_INT':
            self.emit('position', {'lat': msg.lat / 1e7, 'lon': msg.lon / 1e7, 'alt': msg.relative_alt / 1000})
        elif msg_type == 'ATTITUDE' and now - self._last_telemetry >= self.TELEMETRY_INTERVAL_S:
            self._last_telemetry = now
            self.emit('attitude', {'roll': round(math.degrees(msg.roll), 1),
                                   'pitch': round(math.degrees(msg.pitch), 1),
                                   'yaw': round(math.degrees(msg.yaw), 1)})
