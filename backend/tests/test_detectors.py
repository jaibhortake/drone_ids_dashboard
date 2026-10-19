import math

from ids.config import DEFAULT_CONFIG
from ids.detectors import BehavioralAnalyzer, GPSSpoofingDetector, LinkMonitor, NetworkMonitor
from ids.models import AttackType


def gps(lat, lon, sats=12, fix=3):
    return {'lat': int(lat * 1e7), 'lon': int(lon * 1e7), 'satellites_visible': sats, 'fix_type': fix}


class TestNetworkMonitor:
    net = NetworkMonitor(DEFAULT_CONFIG['network'])

    def test_known_sources_pass(self):
        assert self.net.check_source(1, '127.0.0.1') is None
        assert self.net.check_source(255) is None

    def test_unknown_system_id(self):
        alert = self.net.check_source(42)
        assert alert.attack_type is AttackType.UNAUTHORIZED_ACCESS and alert.source == 'sysid:42'

    def test_unknown_ip(self):
        assert self.net.check_source(1, '10.9.9.9').source == '10.9.9.9'

    def test_command_from_non_gcs_is_injection(self):
        assert self.net.check_command('COMMAND_LONG', 1).attack_type is AttackType.COMMAND_INJECTION
        assert self.net.check_command('COMMAND_LONG', 255) is None
        assert self.net.check_command('ATTITUDE', 1) is None

    def test_command_rate_uses_sliding_window(self):
        net = NetworkMonitor({'max_commands_per_second': 3})
        assert all(net.check_command_rate('s', t) is None for t in (0.0, 0.1, 0.2))
        assert net.check_command_rate('s', 0.3).attack_type is AttackType.DOS_ATTACK
        # A second later the window has drained.
        assert net.check_command_rate('s', 1.5) is None


class TestGPS:
    def test_weak_fix_is_degradation_not_spoofing(self):
        alert = GPSSpoofingDetector({}).analyze_gps(gps(40, -74, sats=2, fix=2), 0)
        assert alert.attack_type is AttackType.GPS_DEGRADATION

    def test_fast_flight_is_not_a_jump(self):
        det = GPSSpoofingDetector({'max_speed_mps': 30})
        assert det.analyze_gps(gps(40.0, -74.0), 0) is None
        # ~111 m in 5 s = 22 m/s: legitimate, although > old fixed 100 m threshold.
        assert det.analyze_gps(gps(40.001, -74.0), 5) is None

    def test_teleport_is_spoofing_and_baseline_moves(self):
        det = GPSSpoofingDetector({'max_speed_mps': 30})
        det.analyze_gps(gps(40.0, -74.0), 0)
        assert det.analyze_gps(gps(40.05, -74.0), 1).attack_type is AttackType.GPS_SPOOFING
        # The new position becomes the reference, so it doesn't re-alert forever.
        assert det.analyze_gps(gps(40.05, -74.0), 2) is None

    def test_divergence_from_fused_estimate(self):
        det = GPSSpoofingDetector({'max_divergence_m': 50})
        det.update_fused({'lat': int(40.0 * 1e7), 'lon': int(-74.0 * 1e7)}, 0)
        assert det.analyze_gps(gps(40.0, -74.0), 0.1) is None
        alert = det.analyze_gps(gps(40.01, -74.0), 0.2)
        assert alert.attack_type is AttackType.GPS_SPOOFING and 'fused' in alert.description

    def test_stale_fused_estimate_ignored(self):
        det = GPSSpoofingDetector({'max_divergence_m': 50, 'max_speed_mps': 1e9})
        det.update_fused({'lat': int(40.0 * 1e7), 'lon': int(-74.0 * 1e7)}, 0)
        assert det.analyze_gps(gps(40.01, -74.0), 10) is None


class TestBehavior:
    def test_attitude(self):
        b = BehavioralAnalyzer({'max_tilt_deg': 60})
        assert b.analyze_attitude({'roll': math.radians(30)}) is None
        assert b.analyze_attitude({'roll': math.radians(70)}).attack_type is AttackType.FLIGHT_ANOMALY

    def test_mode_alerts_only_on_transition(self):
        b = BehavioralAnalyzer({'authorized_modes': ['STABILIZE']})
        assert b.analyze_mode('STABILIZE', 'sysid:1') is None
        alert = b.analyze_mode('ACRO', 'sysid:1')
        assert alert.attack_type is AttackType.UNAUTHORIZED_MODE_CHANGE
        assert alert.sensor_data['previous_mode'] == 'STABILIZE'
        assert b.analyze_mode('ACRO', 'sysid:1') is None


class TestLink:
    def test_one_alert_per_outage(self):
        link = LinkMonitor({'heartbeat_timeout_s': 5})
        assert link.check(100) is None  # never connected
        link.heartbeat(0)
        assert link.check(4) is None
        assert link.check(6).attack_type is AttackType.LINK_LOSS
        assert link.check(7) is None
        link.heartbeat(8)
        assert link.check(14).attack_type is AttackType.LINK_LOSS
