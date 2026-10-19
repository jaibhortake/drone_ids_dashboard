"""Built-in attack scenarios, fed through the same IDS.process_message path as live traffic."""

import math

from . import mavlink_util as mu
from .engine import IDS
from .models import Alert

HOME = (40.7128, -74.0060)


def _unauthorized(ids: IDS, t: float) -> list[Alert]:
    return ids.process_message(mu.gcs_heartbeat(src_system=42), t)


def _gps_low(ids: IDS, t: float) -> list[Alert]:
    return ids.process_message(mu.gps_raw(*HOME, satellites=2, fix_type=2), t)


def _gps_jump(ids: IDS, t: float) -> list[Alert]:
    ids.process_message(mu.gps_raw(*HOME), t)
    return ids.process_message(mu.gps_raw(HOME[0] + 0.05, HOME[1] + 0.05), t + 0.3)


def _gps_divergence(ids: IDS, t: float) -> list[Alert]:
    ids.process_message(mu.global_position(*HOME), t)
    return ids.process_message(mu.gps_raw(HOME[0] + 0.01, HOME[1]), t + 0.1)


def _attitude(ids: IDS, t: float) -> list[Alert]:
    return ids.process_message(mu.attitude(roll=math.radians(70), pitch=math.radians(45)), t)


def _injection(ids: IDS, t: float) -> list[Alert]:
    return ids.process_message(mu.command_long(src_system=1), t)


def _dos(ids: IDS, t: float) -> list[Alert]:
    raised: list[Alert] = []
    for i in range(20):
        raised += ids.process_message(mu.command_long(src_system=255), t + i * 0.01)
    return raised


def _mode(ids: IDS, t: float) -> list[Alert]:
    ids.process_message(mu.heartbeat('STABILIZE'), t)
    return ids.process_message(mu.heartbeat('ACRO'), t + 1)


SCENARIOS: dict = {
    'unauthorized': _unauthorized,
    'gps_low': _gps_low,
    'gps_jump': _gps_jump,
    'gps_divergence': _gps_divergence,
    'attitude': _attitude,
    'injection': _injection,
    'dos': _dos,
    'mode': _mode,
}


def run_scenarios(ids: IDS, name: str, start: float) -> list[Alert]:
    """Run one scenario or 'all'. `start` is a monotonic time; scenarios are spaced 100 s apart
    so detector state and alert cooldowns from one don't affect the next."""
    names = list(SCENARIOS) if name == 'all' else [name]
    raised: list[Alert] = []
    for i, n in enumerate(names):
        raised += SCENARIOS[n](ids, start + i * 100)
    return raised
