"""SQLite persistence for alerts."""

import json
import sqlite3
import threading

from .models import Alert, ThreatLevel

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    threat_level TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    source TEXT NOT NULL,
    description TEXT NOT NULL,
    sensor_data TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
)
"""


class AlertStore:
    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute(_SCHEMA)
            self._conn.commit()

    def add(self, alert: Alert) -> Alert:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts (timestamp, threat_level, attack_type, source, description,"
                " sensor_data, recommended_action, acknowledged) VALUES (?,?,?,?,?,?,?,?)",
                (alert.timestamp.isoformat(), alert.threat_level.name, alert.attack_type.value,
                 alert.source, alert.description, json.dumps(alert.sensor_data),
                 alert.recommended_action, int(alert.acknowledged)),
            )
            self._conn.commit()
        alert.id = cur.lastrowid
        return alert

    def recent(self, limit: int = 100, min_level: ThreatLevel | None = None) -> list[Alert]:
        levels = [lvl.name for lvl in ThreatLevel if min_level is None or lvl.value >= min_level.value]
        placeholders = ",".join("?" * len(levels))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM alerts WHERE threat_level IN ({placeholders}) ORDER BY id DESC LIMIT ?",
                (*levels, limit),
            ).fetchall()
        return [self._to_alert(r) for r in rows]

    def all(self) -> list[Alert]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM alerts ORDER BY id").fetchall()
        return [self._to_alert(r) for r in rows]

    def counts(self) -> dict[str, dict[str, int]]:
        with self._lock:
            levels = self._conn.execute(
                "SELECT threat_level, COUNT(*) FROM alerts GROUP BY threat_level").fetchall()
            types = self._conn.execute(
                "SELECT attack_type, COUNT(*) FROM alerts GROUP BY attack_type").fetchall()
            unacked = self._conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0").fetchone()[0]
        return {
            'threat_levels': {k: v for k, v in levels},
            'attack_types': {k: v for k, v in types},
            'unacknowledged': unacked,
        }

    def acknowledge(self, alert_id: int) -> bool:
        with self._lock:
            cur = self._conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
            self._conn.commit()
        return cur.rowcount == 1

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @staticmethod
    def _to_alert(row: sqlite3.Row) -> Alert:
        data = dict(row)
        data['sensor_data'] = json.loads(data['sensor_data'])
        return Alert.from_dict(data)
