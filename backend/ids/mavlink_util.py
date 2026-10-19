"""Build real, decoded MAVLink messages (packed then parsed) for scenarios and tests."""

from pymavlink import mavutil

mavlink = mavutil.mavlink

# ArduCopter custom_mode numbers
COPTER_MODES = {'STABILIZE': 0, 'ACRO': 1, 'ALT_HOLD': 2, 'AUTO': 3, 'GUIDED': 4,
                'LOITER': 5, 'RTL': 6, 'LAND': 9}


def make(name: str, src_system: int = 1, src_component: int = 1, **fields):
    """Encode `name` (e.g. 'gps_raw_int') with the given fields and decode it back."""
    sender = mavlink.MAVLink(None, srcSystem=src_system, srcComponent=src_component)
    msg = getattr(sender, f"{name}_encode")(**fields)
    return mavlink.MAVLink(None).decode(bytearray(msg.pack(sender)))


def heartbeat(mode: str = 'STABILIZE', src_system: int = 1):
    return make('heartbeat', src_system,
                type=mavlink.MAV_TYPE_QUADROTOR, autopilot=mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                base_mode=mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
                custom_mode=COPTER_MODES[mode], system_status=mavlink.MAV_STATE_ACTIVE)


def gcs_heartbeat(src_system: int = 255):
    return make('heartbeat', src_system, src_component=190,
                type=mavlink.MAV_TYPE_GCS, autopilot=mavlink.MAV_AUTOPILOT_INVALID,
                base_mode=0, custom_mode=0, system_status=mavlink.MAV_STATE_ACTIVE)


def gps_raw(lat: float, lon: float, satellites: int = 12, fix_type: int = 3, src_system: int = 1):
    return make('gps_raw_int', src_system, time_usec=0, fix_type=fix_type,
                lat=int(lat * 1e7), lon=int(lon * 1e7), alt=10000, eph=100, epv=100,
                vel=0, cog=0, satellites_visible=satellites)


def global_position(lat: float, lon: float, src_system: int = 1):
    return make('global_position_int', src_system, time_boot_ms=0,
                lat=int(lat * 1e7), lon=int(lon * 1e7), alt=10000, relative_alt=10000,
                vx=0, vy=0, vz=0, hdg=0)


def attitude(roll: float = 0.0, pitch: float = 0.0, yaw: float = 0.0, src_system: int = 1):
    return make('attitude', src_system, time_boot_ms=0, roll=roll, pitch=pitch, yaw=yaw,
                rollspeed=0, pitchspeed=0, yawspeed=0)


def command_long(src_system: int = 255, command: int = mavlink.MAV_CMD_COMPONENT_ARM_DISARM):
    return make('command_long', src_system, src_component=190, target_system=1, target_component=1,
                command=command, confirmation=0, param1=0, param2=0, param3=0, param4=0,
                param5=0, param6=0, param7=0)
