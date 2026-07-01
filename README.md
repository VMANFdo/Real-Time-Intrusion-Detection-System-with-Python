# IDS — Real-Time Intrusion Detection System

A lightweight, real-time intrusion detection system built with Python, **Scapy**, and **scikit-learn**. It captures live network traffic, extracts flow-level features, and detects threats using both **signature-based rules** (SYN flood, port scans) and **anomaly-based detection** (Isolation Forest).

## Architecture

| Module | Role |
|---|---|
| `packet_capture_engine.py` | Captures IP/TCP packets via Scapy in a background thread |
| `traffic_analysis_module.py` | Extracts per-flow features (packet size, rate, flags, etc.) |
| `detection_engine.py` | Applies signature rules and an Isolation Forest model to flag threats |
| `alert_system.py` | Logs structured JSON alerts to file and escalates high-confidence threats |
| `ids.py` | Orchestrates the pipeline: capture → analyze → detect → alert |
| `data.py` | Offline test harness with synthetic attack scenarios |
| `dashboard.py` | Flask web server + REST API for the dashboard |
| `templates/dashboard.html` | Single-page dashboard UI (also standalone for Vercel) |

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

> **Note:** Scapy requires [Npcap](https://npcap.com/) on Windows for live packet capture. Npcap's "WinPcap API-compatible Mode" must be enabled during installation.

### 2. Test with Synthetic Data (No Network Required)

The `data.py` script simulates normal traffic, a SYN flood, and a port scan using crafted Scapy packets — no network interface needed. Each scenario sends multiple packets within a single flow so that flow-level features (packet rate, byte rate) become meaningful and signature rules can trigger.

```bash
python data.py
```

**Expected output:**

```
[ 1] IP / TCP 192.168.1.1:1234 > 192.168.1.2:http A  >>> ['anomaly']
[ 2] IP / TCP 192.168.1.1:1234 > 192.168.1.2:http P  ✓ OK
[ 3] IP / TCP 192.168.1.1:1234 > 192.168.1.2:http P  ✓ OK
...
[ 7] IP / TCP 10.0.0.1:rrac > 192.168.1.2:http S  >>> ['syn_flood', 'port_scan', 'anomaly']
...
==================================================
  SUMMARY
==================================================
    normal       : 4
    syn_flood    : 22
    port_scan    : 25
    anomaly      : 29
==================================================
```

- **First packet of each flow** is always flagged as anomaly — it has zero duration so the Isolation Forest sees it as unusual.
- **Subsequent normal packets** (ACK/PSH, low rate) pass without alerts.
- **SYN flood & port scan packets** trigger both signature rules and anomaly alerts once the per-flow packet rate crosses the threshold.

### 3. Run the Web Dashboard

```bash
python dashboard.py
```

Open **http://localhost:5000** in your browser.

The dashboard works in two modes:

- **Live mode** — automatically enabled when the Flask backend is running. Click "Start Capture" to begin analyzing live traffic, or "Run Test" to replay the synthetic attack data.
- **Demo mode** — auto-falls back when no backend is detected. Uses embedded test data so you can see the UI in action. The `dashboard.html` file is fully self-contained for static deployment.

![Dashboard Preview](https://img.shields.io/badge/status-working-brightgreen)

**Dashboard features:**
- Start/Stop live packet capture (requires Npcap + admin)
- Run synthetic attack test offline
- 4 stat cards: Total, Normal, Attacks, Anomalies
- Real-time packet rate chart (Chart.js)
- Live scrolling alert feed
- Clear alerts & reset stats

### 4. Run Against Live Traffic (Safely)

The IDS is **read-only** — it captures packets with Scapy's `sniff()` in **promiscuous mode** but never transmits anything.

#### Find Your Network Interface

```bash
python -c "from scapy.all import get_windows_if_list; print(*[i['name'] for i in get_windows_if_list()], sep='\n')"
```

Common names: `eth0` (Linux), `en0` (macOS), `Wi-Fi` or `Ethernet` (Windows).

#### Using the Dashboard

1. Select your interface from the dropdown
2. Click **Start Capture**
3. Watch alerts appear in real time
4. Click **Stop** when done

#### Using the CLI

Edit the default interface in `ids.py:9` (the `interface="eth0"` parameter), then:

```bash
python ids.py
```

Press **Ctrl+C** to stop.

> **Safety Note:** The system acts as a passive network tap — it only **reads** packets and never injects traffic, modifies packets, or sends responses. Run it on your local machine or a test VM to observe real traffic without risk.

## Deploy Dashboard to Vercel (Demo Mode)

The `dashboard.html` file at the project root is a fully standalone static page with embedded demo data. Anyone can view it without a backend.

1. Go to [vercel.com](https://vercel.com) and sign in
2. Click **Add New → Project**
3. Import this repository or drag & drop `dashboard.html`
4. Vercel auto-detects it as a static site
5. Click **Deploy**

Visitors see the demo mode dashboard with pre-recorded test data. To enable live capture, they'd run `python dashboard.py` locally.

## API Endpoints

When the Flask backend is running (`python dashboard.py`):

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Dashboard UI |
| `/api/status` | GET | IDS running state |
| `/api/start` | POST | Start capture (body: `{"interface":"Wi-Fi"}`) |
| `/api/stop` | POST | Stop capture |
| `/api/test` | POST | Run synthetic attack test |
| `/api/stats` | GET | Packet statistics |
| `/api/traffic` | GET | Packet rate time series |
| `/api/alerts` | GET | Alert log (query: `?limit=100`) |
| `/api/clear` | POST | Clear all alerts and stats |

## Adding Custom Rules

Edit the `signature_rules` dictionary in `detection_engine.py:14`:

```python
'dns_tunneling': {
    'condition': lambda f: f['packet_size'] > 512 and f['tcp_flags'] == 16
}
```

## Retraining the Anomaly Detector

The Isolation Forest is pre-trained on 200 synthetic "normal" traffic samples (packet sizes 0–1500, rates 0–50 pps, byte rates 0–75000 B/s). For better accuracy with your own traffic, replace the call to `_train_default()` in `detection_engine.py:12` with training on real baseline data via the `train_anomaly_detector()` method.

## Extending Notifications

The `AlertSystem.generate_alert()` method in `alert_system.py:33` includes a placeholder for email, Slack, or SIEM integration.
