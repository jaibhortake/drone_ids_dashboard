"""Alert data model shared by detectors, engine, store and web layer."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class ThreatLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AttackType(Enum):
    GPS_SPOOFING = "GPS Spoofing"
    GPS_DEGRADATION = "GPS Degradation"
    UNAUTHORIZED_ACCESS = "Unauthorized Access"
    COMMAND_INJECTION = "Command Injection"
    DOS_ATTACK = "Denial of Service"
    FLIGHT_ANOMALY = "Flight Anomaly"
    UNAUTHORIZED_MODE_CHANGE = "Unauthorized Mode Change"
    LINK_LOSS = "Link Loss"


@dataclass
class Alert:
    threat_level: ThreatLevel
    attack_type: AttackType
    source: str
    description: str
    sensor_data: dict
    recommended_action: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: int | None = None
    acknowledged: bool = False

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'threat_level': self.threat_level.name,
            'attack_type': self.attack_type.value,
            'source': self.source,
            'description': self.description,
            'sensor_data': self.sensor_data,
            'recommended_action': self.recommended_action,
            'acknowledged': self.acknowledged,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Alert":
        return cls(
            id=data.get('id'),
            timestamp=datetime.fromisoformat(data['timestamp']),
            threat_level=ThreatLevel[data['threat_level']],
            attack_type=AttackType(data['attack_type']),
            source=data['source'],
            description=data['description'],
            sensor_data=data.get('sensor_data') or {},
            recommended_action=data['recommended_action'],
            acknowledged=bool(data.get('acknowledged', False)),
        )
