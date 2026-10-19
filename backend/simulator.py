"""MAVLink drone simulator with injectable attacks, for demos without hardware.

    python simulator.py                                   # normal flight to udp 127.0.0.1:14550
    python simulator.py --attack gps_jump --attack rogue_gcs
    python simulator.py --attack all --duration 60

Attacks start after --attack-delay seconds so the IDS first sees a clean baseline.
"""

import argparse
import math
import time

from pymavlink import mavutil

from ids.mavlink_util import COPTER_MODES

mavlink = mavutil.mavlink
ATTACKS = ['gps_jump', 'gps_low', 'rogue_gcs', 'injection', 'flood', 'mode', 'attitude', 'jamming']
HOME = (40.7128, -74.0060)


class SimulatedDrone:
    def __init__(self, target: str):
        self.conn = mavutil.mavlink_connection(target, source_system=1, source_component=1)
        self.mode = 'GUIDED'
        self.gps_offset = (0.0, 0.0)
        self.satellites = 14
        self.roll = 0.0
        self.silent_until = 0.0

    def position(self, t: float):
        # Slow 100 m-radius circle around HOME.
        lat = HOME[0] + 0.0009 * math.cos(t / 30)
        lon = HOME[1] + 0.0012 * math.sin(t / 30)
        return lat, lon

    def send_tick(self, t: float) -> None:
        if time.monotonic() < self.silent_until:
            return
        m = self.conn.mav
        m.srcSystem = 1
        lat, lon = self.position(t)
        m.heartbeat_send(mavlink.MAV_TYPE_QUADROTOR, mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                         mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, COPTER_MODES[self.mode],
                         mavlink.MAV_STATE_ACTIVE)
        m.global_position_int_send(int(t * 1000), int(lat * 1e7), int(lon * 1e7), 50000, 20000, 0, 0, 0, 0)
        glat, glon = lat + self.gps_offset[0], lon + self.gps_offset[1]
        m.gps_raw_int_send(int(t * 1e6), 3 if self.satellites >= 4 else 1, int(glat * 1e7), int(glon * 1e7),
                           50000, 80, 120, 300, 0, self.satellites)
        m.attitude_send(int(t * 1000), self.roll + 0.05 * math.sin(t), 0.03 * math.cos(t), t / 30 % (2 * math.pi),
                        0, 0, 0)

    def as_system(self, sysid: int):
        self.conn.mav.srcSystem = sysid
        return self.conn.mav

    def inject(self, attack: str) -> None:
        print(f"[sim] injecting {attack}")
        if attack == 'gps_jump':
            self.gps_offset = (0.02, 0.02)
        elif attack == 'gps_low':
            self.satellites = 2
        elif attack == 'rogue_gcs':
            self.as_system(66).heartbeat_send(mavlink.MAV_TYPE_GCS, mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
        elif attack == 'injection':
            self.as_system(66).command_long_send(1, 1, mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 0,
                                                 0, 0, 0, 0, 0, 0, 0)
        elif attack == 'flood':
            for _ in range(40):
                self.as_system(255).command_long_send(1, 1, mavlink.MAV_CMD_REQUEST_MESSAGE, 0,
                                                      0, 0, 0, 0, 0, 0, 0)
        elif attack == 'mode':
            self.mode = 'ACRO'
        elif attack == 'attitude':
            self.roll = math.radians(75)
        elif attack == 'jamming':
            self.silent_until = time.monotonic() + 8
        self.conn.mav.srcSystem = 1

    def recover(self) -> None:
        self.gps_offset, self.satellites, self.roll, self.mode = (0.0, 0.0), 14, 0.0, 'GUIDED'


def run(target: str, attacks, duration: float, rate_hz: float = 5.0, attack_delay: float = 3.0,
        attack_spacing: float = 3.0) -> None:
    drone = SimulatedDrone(target)
    schedule = {attack_delay + i * attack_spacing: a for i, a in enumerate(attacks)}
    start = time.monotonic()
    while (t := time.monotonic() - start) < duration:
        for at in [k for k in schedule if k <= t]:
            drone.recover()
            drone.inject(schedule.pop(at))
        drone.send_tick(t)
        time.sleep(1 / rate_hz)
    drone.conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--target', default='udpout:127.0.0.1:14550')
    parser.add_argument('--attack', action='append', default=[], choices=ATTACKS + ['all'])
    parser.add_argument('--duration', type=float, default=120)
    parser.add_argument('--attack-delay', type=float, default=5)
    args = parser.parse_args()
    attacks = ATTACKS if 'all' in args.attack else args.attack
    print(f"[sim] sending to {args.target} for {args.duration:.0f}s; attacks: {attacks or 'none'}")
    run(args.target, attacks, args.duration, attack_delay=args.attack_delay)


if __name__ == '__main__':
    main()
