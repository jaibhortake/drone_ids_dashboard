# 🚁 Drone Intrusion Detection System (IDS) Dashboard

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0.0-000000?style=for-the-badge&logo=flask&logoColor=white)
![WebSocket](https://img.shields.io/badge/WebSocket-SocketIO-010101?style=for-the-badge&logo=socket.io&logoColor=white)
![MAVLink](https://img.shields.io/badge/Protocol-MAVLink-FF6B35?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A real-time web dashboard for monitoring and detecting intrusions on MAVLink-based drone systems.**

[Features](#-features) • [Quick Start](#-quick-start) • [Architecture](#-architecture) • [API Reference](#-api-reference) • [Configuration](#-configuration)

</div>

---

## 📖 Overview

The **Drone IDS Dashboard** is a Final Year Project (FYP) implementation of a real-time **Intrusion Detection System** for unmanned aerial vehicles (UAVs/drones). It analyzes live MAVLink telemetry data to detect cyber threats such as GPS spoofing, unauthorized access, command injection, and anomalous flight behavior.

The system features a modern web-based dashboard built with Flask and WebSockets, providing instant alerts and threat visualizations in the browser.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🛡️ **GPS Spoofing Detection** | Detects suspicious position jumps and low satellite count scenarios |
| 🔒 **Unauthorized Access Detection** | Monitors and flags connections from unauthorized IP addresses |
| ⚡ **DoS Attack Detection** | Identifies command flooding using rate-limiting thresholds |
| 🎯 **Anomalous Behavior Analysis** | Flags extreme attitude (roll/pitch) and unauthorized flight mode changes |
| 📡 **Real-Time MAVLink Monitoring** | Live connection to drones over UDP, TCP, USB, or Radio |
| 📊 **Live Dashboard UI** | WebSocket-powered browser dashboard with charts and alert feed |
| 🧪 **Test Scenario Runner** | Built-in simulated attack scenarios for demonstration and testing |

---

## 🗂️ Project Structure

```
drone_ids_dashboard/
│
├── app.py                  # Flask web server with SocketIO and REST API
├── demo_ids.py             # Core IDS engine (detectors, analyzers, alert system)
├── requirements_web.txt    # Python dependencies
│
└── templates/
    └── dashboard.html      # Single-page web dashboard (HTML + CSS + JS)
```

---

## 🚀 Quick Start

### Prerequisites

- Python **3.8 or higher**
- pip (Python package manager)
- A MAVLink-compatible drone simulator or hardware (optional, for real-time mode)

### 1. Clone the Repository

```bash
git clone https://github.com/<your-username>/drone_ids_dashboard.git
cd drone_ids_dashboard
```

### 2. Install Dependencies

```bash
pip install -r requirements_web.txt
```

### 3. Run the Server

```bash
python app.py
```

### 4. Open the Dashboard

Navigate to **[http://localhost:5000](http://localhost:5000)** in your browser.

> 💡 Click **"Run Test Scenarios"** to see simulated attack alerts without any drone hardware.

---

## 📡 Real-Time Drone Monitoring

To monitor a live drone:

1. Connect your drone (via USB, UDP, TCP, or telemetry radio)
2. Enter the connection string in the dashboard's input field
3. Click **"▶️ Start Real-Time Monitoring"**

### Connection String Examples

| Connection Type | Example String |
|---|---|
| UDP (Simulator / SITL) | `udp:127.0.0.1:14550` |
| TCP | `tcp:192.168.1.100:5760` |
| USB Serial (Windows) | `COM3:57600` |
| USB Serial (Linux/macOS) | `/dev/ttyUSB0:57600` |

> ⚙️ Use [ArduPilot SITL](https://ardupilot.org/dev/docs/sitl-simulator-software-in-the-loop.html) or [Mission Planner](https://ardupilot.org/planner/) to simulate a drone connection for testing.

---

## 🏛️ Architecture

```
┌──────────────────────────────────────────────┐
│              Browser Dashboard               │
│         (dashboard.html + Chart.js)          │
│                                              │
│   REST API  ◄────────►  WebSocket (SocketIO) │
└────────────────┬────────────────▲────────────┘
                 │                │
                 ▼                │  Alerts / Events
         ┌──────────────────────────────┐
         │        Flask Web Server      │
         │            (app.py)          │
         └──────────────┬───────────────┘
                        │
                        ▼
         ┌──────────────────────────────┐
         │       IDS Engine             │
         │        (demo_ids.py)         │
         │                              │
         │  ┌──────────────────────┐    │
         │  │  NetworkMonitor      │    │
         │  │  GPSSpoofingDetector │    │
         │  │  BehavioralAnalyzer  │    │
         │  └──────────────────────┘    │
         └──────────────┬───────────────┘
                        │
                        ▼
            MAVLink Telemetry Stream
          (UDP / TCP / Serial / Radio)
```

---

## 🔧 IDS Detection Modules

### 🔒 NetworkMonitor
- Checks incoming connections against a whitelist of **authorized IP addresses**
- Monitors **command rate** to detect Denial-of-Service (DoS) flooding attacks
- Configurable `max_commands_per_second` threshold

### 📍 GPSSpoofingDetector
- Detects **low satellite count** (below configured minimum)
- Detects **sudden large position jumps** using the Haversine distance formula
- Configurable `max_position_jump` (in meters) and `min_satellites`

### 🤖 BehavioralAnalyzer
- Detects **extreme roll/pitch angles** (>60°) indicating anomalous flight
- Flags **unauthorized flight mode changes** (e.g., switching to ACRO mode)
- Configurable list of `authorized_modes`

---

## ⚙️ Configuration

Default configuration is defined in `demo_ids.py`:

```python
DEFAULT_CONFIG = {
    'network': {
        'authorized_ips': ['127.0.0.1', '192.168.1.100'],
        'max_commands_per_second': 10
    },
    'gps': {
        'max_position_jump': 100.0,   # meters
        'min_satellites': 4
    },
    'behavioral': {
        'authorized_modes': ['STABILIZE', 'GUIDED', 'AUTO', 'RTL', 'LAND']
    }
}
```

---

## 🌐 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serve the web dashboard |
| `GET` | `/api/status` | Get current IDS status and alert counts |
| `GET` | `/api/config` | Retrieve current IDS configuration |
| `POST` | `/api/config` | Update IDS configuration |
| `POST` | `/api/test` | Trigger test attack scenarios |

### WebSocket Events

| Event | Direction | Description |
|---|---|---|
| `start_real_time` | Client → Server | Start live MAVLink monitoring |
| `stop_real_time` | Client → Server | Stop live monitoring |
| `new_alert` | Server → Client | Push a new security alert |
| `status_update` | Server → Client | Push updated statistics |
| `heartbeat` | Server → Client | MAVLink heartbeat signal |
| `error` | Server → Client | Error notification |

---

## 📦 Dependencies

| Package | Version | Purpose |
|---|---|---|
| `Flask` | 3.0.0 | Web framework |
| `Flask-SocketIO` | 5.3.5 | WebSocket support |
| `Flask-CORS` | 4.0.0 | Cross-origin resource sharing |
| `python-socketio` | 5.10.0 | SocketIO engine |
| `eventlet` | 0.33.3 | Async networking |
| `pymavlink` | ≥2.4.37 | MAVLink protocol parser |
| `pyserial` | ≥3.5 | Serial port support |
| `numpy` | ≥1.21.0 | Numerical computing |

---

## 🧪 Test Scenarios

The built-in test suite simulates the following attack scenarios:

| Scenario | Attack Type | Threat Level |
|---|---|---|
| `unauthorized` | Unauthorized Access | HIGH |
| `gps_low` | GPS Spoofing (low satellites) | MEDIUM |
| `gps_jump` | GPS Spoofing (position jump) | HIGH |
| `attitude` | Anomalous Behavior (extreme angle) | HIGH |
| `dos` | Denial of Service (command flood) | CRITICAL |
| `mode` | Unauthorized Mode Change | HIGH |

Run all scenarios at once via the dashboard UI or via API:

```bash
curl -X POST http://localhost:5000/api/test \
     -H "Content-Type: application/json" \
     -d '{"test_type": "all"}'
```

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'Add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License**.

---

## 👤 Author

**Jai Bhortake**  
Final Year Project — Drone Intrusion Detection System  
📧 Connect on [GitHub](https://github.com/<your-username>)

---

<div align="center">
⭐ If you found this project useful, please give it a star!
</div>
