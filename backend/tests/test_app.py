import csv
import io
import json

import pytest

from app import create_app

TOKEN = 'test-token'
AUTH = {'Authorization': f'Bearer {TOKEN}'}


@pytest.fixture
def server(tmp_path):
    app, socketio = create_app(TOKEN, db_path=str(tmp_path / 'a.db'))
    return app, socketio


@pytest.fixture
def client(server):
    return server[0].test_client()


def test_frontend_served_without_token_with_security_headers(client):
    resp = client.get('/')
    assert resp.status_code == 200 and b'<html' in resp.data
    assert 'script-src' in resp.headers['Content-Security-Policy']
    assert resp.headers['X-Frame-Options'] == 'DENY'
    assert client.get('/js/app.js').status_code == 200


def test_path_traversal_blocked(client):
    assert client.get('/../backend/app.py').status_code == 404


@pytest.mark.parametrize('method,url', [
    ('get', '/api/status'), ('get', '/api/config'), ('post', '/api/config'), ('get', '/api/alerts'),
    ('get', '/api/alerts/export'), ('post', '/api/test'), ('post', '/api/alerts/1/ack'),
])
def test_api_requires_token(client, method, url):
    assert getattr(client, method)(url).status_code == 401
    assert getattr(client, method)(url, headers={'Authorization': 'Bearer wrong'}).status_code == 401


def test_run_tests_then_query_ack_export(client):
    resp = client.post('/api/test', json={'test_type': 'all'}, headers=AUTH)
    assert resp.status_code == 200 and resp.json['alerts_raised'] >= 8

    status = client.get('/api/status', headers=AUTH).json
    assert status['total_alerts'] == resp.json['alerts_raised']
    assert status['monitoring_active'] is False

    alerts = client.get('/api/alerts?limit=5', headers=AUTH).json
    assert len(alerts) == 5
    critical = client.get('/api/alerts?min_level=critical', headers=AUTH).json
    assert critical and all(a['threat_level'] == 'CRITICAL' for a in critical)

    alert_id = alerts[0]['id']
    assert client.post(f'/api/alerts/{alert_id}/ack', headers=AUTH).status_code == 200
    assert client.post('/api/alerts/99999/ack', headers=AUTH).status_code == 404
    assert client.get('/api/status', headers=AUTH).json['unacknowledged'] == status['total_alerts'] - 1

    exported = json.loads(client.get('/api/alerts/export?format=json', headers=AUTH).data)
    assert len(exported) == status['total_alerts']
    rows = list(csv.DictReader(io.StringIO(client.get('/api/alerts/export?format=csv', headers=AUTH).text)))
    assert len(rows) == status['total_alerts'] and 'attack_type' in rows[0]


def test_bad_inputs(client):
    assert client.post('/api/test', json={'test_type': 'rm -rf'}, headers=AUTH).status_code == 400
    assert client.get('/api/alerts?min_level=bogus', headers=AUTH).status_code == 400
    assert client.get('/api/alerts/export?format=xml', headers=AUTH).status_code == 400


def test_config_update_validated(client):
    resp = client.post('/api/config', json={'gps': {'min_satellites': 6}}, headers=AUTH)
    assert resp.json['gps']['min_satellites'] == 6
    assert client.get('/api/config', headers=AUTH).json['gps']['min_satellites'] == 6
    assert client.post('/api/config', json={'gps': {'evil': 1}}, headers=AUTH).status_code == 400


def test_socket_rejects_bad_token(server):
    app, socketio = server
    assert not socketio.test_client(app, auth={'token': 'wrong'}).is_connected()
    assert not socketio.test_client(app).is_connected()


def test_socket_receives_status_and_alerts(server):
    app, socketio = server
    sc = socketio.test_client(app, auth={'token': TOKEN})
    assert sc.is_connected()
    names = [e['name'] for e in sc.get_received()]
    assert 'status_update' in names and 'monitor_state' in names

    app.test_client().post('/api/test', json={'test_type': 'mode'}, headers=AUTH)
    received = sc.get_received()
    alerts = [e['args'][0] for e in received if e['name'] == 'new_alert']
    assert alerts and alerts[0]['attack_type'] == 'Unauthorized Mode Change'


def test_socket_rejects_invalid_connection_string(server):
    app, socketio = server
    sc = socketio.test_client(app, auth={'token': TOKEN})
    sc.get_received()
    sc.emit('start_monitoring', {'connection_string': 'x' * 500})
    assert any(e['name'] == 'monitor_error' for e in sc.get_received())
