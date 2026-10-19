import copy

import pytest

from ids import IDS, AlertStore, ConfigError, load_config, merge_config
from ids import mavlink_util as mu
from ids.config import DEFAULT_CONFIG
from ids.models import AttackType, ThreatLevel
from ids.scenarios import SCENARIOS, run_scenarios

EXPECTED = {
    'unauthorized': AttackType.UNAUTHORIZED_ACCESS,
    'gps_low': AttackType.GPS_DEGRADATION,
    'gps_jump': AttackType.GPS_SPOOFING,
    'gps_divergence': AttackType.GPS_SPOOFING,
    'attitude': AttackType.FLIGHT_ANOMALY,
    'injection': AttackType.COMMAND_INJECTION,
    'dos': AttackType.DOS_ATTACK,
    'mode': AttackType.UNAUTHORIZED_MODE_CHANGE,
}


def make_ids(store=None, **overrides):
    return IDS(merge_config(DEFAULT_CONFIG, overrides), store)


@pytest.mark.parametrize('name', sorted(SCENARIOS))
def test_each_scenario_raises_its_alert(name):
    raised = run_scenarios(make_ids(), name, 1000.0)
    assert EXPECTED[name] in {a.attack_type for a in raised}


def test_all_scenarios():
    raised = run_scenarios(make_ids(), 'all', 1000.0)
    assert set(EXPECTED.values()) <= {a.attack_type for a in raised}


def test_clean_traffic_raises_nothing():
    ids = make_ids()
    msgs = [mu.heartbeat('GUIDED'), mu.gcs_heartbeat(), mu.global_position(40.0, -74.0),
            mu.gps_raw(40.0, -74.0), mu.attitude(0.1, 0.1), mu.command_long(255)]
    assert [a for i, m in enumerate(msgs) for a in ids.process_message(m, i * 0.2)] == []


def test_mode_read_from_heartbeat():
    ids = make_ids()
    ids.process_message(mu.heartbeat('LOITER'), 0)
    assert ids.get_status()['flight_mode'] == 'LOITER'


def test_gcs_heartbeat_does_not_count_as_vehicle_link():
    ids = make_ids()
    ids.process_message(mu.gcs_heartbeat(), 0)
    assert ids.tick(100) == []


def test_link_loss_via_tick():
    ids = make_ids()
    ids.process_message(mu.heartbeat(), 0)
    assert [a.attack_type for a in ids.tick(10)] == [AttackType.LINK_LOSS]


def test_cooldown_suppresses_repeats():
    ids = make_ids(alerts={'cooldown_s': 5})
    assert len(ids.process_message(mu.gcs_heartbeat(42), 0)) == 1
    assert ids.process_message(mu.gcs_heartbeat(42), 1) == []
    assert len(ids.process_message(mu.gcs_heartbeat(42), 6)) == 1


def test_handlers_receive_alerts_and_errors_are_isolated():
    ids = make_ids()
    seen = []
    ids.register_handler(lambda a: 1 / 0)
    ids.register_handler(seen.append)
    ids.process_message(mu.gcs_heartbeat(42), 0)
    assert len(seen) == 1


def test_in_memory_history_is_bounded():
    ids = make_ids(alerts={'max_in_memory': 3, 'cooldown_s': 0})
    for i in range(10):
        ids.process_message(mu.gcs_heartbeat(100 + i), i)
    assert len(ids.alerts) == 3


def test_alerts_persist_across_restart(tmp_path):
    db = str(tmp_path / 'alerts.db')
    ids = make_ids(AlertStore(db))
    run_scenarios(ids, 'all', 1000.0)
    total = ids.get_status()['total_alerts']
    first = ids.recent_alerts(1)[0]
    assert ids.acknowledge(first.id)
    ids.store.close()

    reopened = make_ids(AlertStore(db))
    status = reopened.get_status()
    assert status['total_alerts'] == total
    assert status['unacknowledged'] == total - 1
    assert reopened.recent_alerts(1)[0].acknowledged
    assert all(a.threat_level.value >= 4 for a in reopened.recent_alerts(50, ThreatLevel.CRITICAL))


def test_update_config_applies():
    ids = make_ids()
    ids.update_config({'network': {'authorized_system_ids': [1, 42, 255]}})
    assert ids.process_message(mu.gcs_heartbeat(42), 0) == []


@pytest.mark.parametrize('bad', [
    {'nope': {}}, {'gps': {'nope': 1}}, {'gps': {'min_satellites': 'four'}},
    {'gps': {'min_satellites': -1}}, {'alerts': {'cooldown_s': True}}, ['list'],
])
def test_invalid_config_rejected(bad):
    with pytest.raises(ConfigError):
        merge_config(DEFAULT_CONFIG, bad)


def test_load_config_yaml(tmp_path):
    path = tmp_path / 'c.yaml'
    path.write_text('gps:\n  min_satellites: 6\n')
    cfg = load_config(str(path))
    assert cfg['gps']['min_satellites'] == 6
    assert cfg['network'] == DEFAULT_CONFIG['network']
    assert load_config(str(tmp_path / 'missing.yaml')) == copy.deepcopy(DEFAULT_CONFIG)
