"""IDS configuration: defaults, YAML loading and validation."""

import copy
from pathlib import Path

import yaml

DEFAULT_CONFIG: dict = {
    'network': {
        # IPs allowed to send MAVLink (checked when the transport exposes the sender, e.g. udpin)
        'authorized_ips': ['127.0.0.1', '192.168.1.100'],
        # MAVLink system IDs allowed on the link (1 = vehicle, 255 = ground station)
        'authorized_system_ids': [1, 255],
        # System IDs allowed to send commands (COMMAND_LONG, SET_MODE, PARAM_SET, ...)
        'authorized_gcs_ids': [255],
        'max_commands_per_second': 10,
    },
    'gps': {
        'max_speed_mps': 30.0,        # faster implied ground speed than this = position jump
        'min_satellites': 4,
        'max_divergence_m': 50.0,     # GPS_RAW_INT vs fused GLOBAL_POSITION_INT
    },
    'behavioral': {
        'authorized_modes': ['STABILIZE', 'GUIDED', 'AUTO', 'RTL', 'LAND', 'LOITER', 'ALT_HOLD'],
        'max_tilt_deg': 60.0,
    },
    'link': {
        'heartbeat_timeout_s': 5.0,
    },
    'alerts': {
        'cooldown_s': 5.0,            # suppress repeats of the same attack type from the same source
        'max_in_memory': 500,
    },
}

_SCHEMA = {
    'network': {
        'authorized_ips': list, 'authorized_system_ids': list,
        'authorized_gcs_ids': list, 'max_commands_per_second': (int, float),
    },
    'gps': {'max_speed_mps': (int, float), 'min_satellites': int, 'max_divergence_m': (int, float)},
    'behavioral': {'authorized_modes': list, 'max_tilt_deg': (int, float)},
    'link': {'heartbeat_timeout_s': (int, float)},
    'alerts': {'cooldown_s': (int, float), 'max_in_memory': int},
}


class ConfigError(ValueError):
    pass


def merge_config(base: dict, override: dict | None) -> dict:
    """Return base updated with a validated override. Unknown keys or wrong types raise ConfigError."""
    merged = copy.deepcopy(base)
    if not override:
        return merged
    if not isinstance(override, dict):
        raise ConfigError("config must be a mapping")
    for section, values in override.items():
        if section not in _SCHEMA:
            raise ConfigError(f"unknown section: {section}")
        if not isinstance(values, dict):
            raise ConfigError(f"section {section} must be a mapping")
        for key, value in values.items():
            expected = _SCHEMA[section].get(key)
            if expected is None:
                raise ConfigError(f"unknown key: {section}.{key}")
            if isinstance(value, bool) or not isinstance(value, expected):
                raise ConfigError(f"bad type for {section}.{key}")
            if isinstance(value, (int, float)) and value < 0:
                raise ConfigError(f"{section}.{key} must be >= 0")
            merged[section][key] = value
    return merged


def load_config(path: str | None) -> dict:
    """Defaults overlaid with the YAML file at path, if it exists."""
    if path and Path(path).is_file():
        with open(path, encoding='utf-8') as f:
            return merge_config(DEFAULT_CONFIG, yaml.safe_load(f))
    return copy.deepcopy(DEFAULT_CONFIG)
