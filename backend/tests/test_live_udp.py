"""End-to-end over a real UDP socket: simulator -> MAVLink -> MavlinkMonitor -> IDS."""

import socket
import threading
import time

import simulator
from ids import IDS
from ids.config import DEFAULT_CONFIG, merge_config
from ids.models import AttackType
from ids.monitor import MavlinkMonitor


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def test_simulated_attacks_detected_over_udp():
    port = free_udp_port()
    ids = IDS(merge_config(DEFAULT_CONFIG, {'alerts': {'cooldown_s': 0.5}, 'link': {'heartbeat_timeout_s': 2}}))
    events = []
    monitor = MavlinkMonitor(ids, f'udpin:127.0.0.1:{port}', lambda e, d: events.append((e, d)))
    monitor.start()
    time.sleep(0.3)

    attacks = ['rogue_gcs', 'injection', 'flood', 'mode', 'gps_jump', 'jamming']
    sim = threading.Thread(target=simulator.run, kwargs={
        'target': f'udpout:127.0.0.1:{port}', 'attacks': attacks, 'duration': 12,
        'rate_hz': 10, 'attack_delay': 1.0, 'attack_spacing': 0.8})
    sim.start()
    sim.join()
    monitor.stop()

    seen = {a.attack_type for a in ids.alerts}
    assert {AttackType.UNAUTHORIZED_ACCESS, AttackType.COMMAND_INJECTION, AttackType.DOS_ATTACK,
            AttackType.UNAUTHORIZED_MODE_CHANGE, AttackType.GPS_SPOOFING, AttackType.LINK_LOSS} <= seen
    names = {e for e, _ in events}
    assert {'vehicle', 'position', 'attitude', 'monitor_state'} <= names
    assert not monitor.running
