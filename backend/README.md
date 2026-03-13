# Real-Time Network Threat Detection Platform — Backend

FastAPI backend for real-time network threat detection:

- Packet capture via **Scapy** (optional; requires Npcap/admin privileges on Windows)
- Real-time streaming via **Redis** (Streams + Pub/Sub)
- Feature engineering to flow-level metrics
- 3-layer detection: **Rules** → **Isolation Forest** (anomaly) → **Random Forest** (attack class)
- Live alerts to frontend via **WebSockets**
- Automated response: add IP to **blocklist** (Redis set) + log incident (SQLite)

## Quickstart (demo mode)

Prereqs:
- Python 3.11+ recommended
- Redis running on `localhost:6379`

### Redis on Windows

You need a Redis server running locally. Common options:

- **WSL**: `sudo apt-get install redis-server` then `sudo service redis-server start`
- **Memurai** (Redis-compatible Windows service)
- If you have Docker, you can run `docker compose up` using `docker-compose.yml` in this folder

Install:

```bash
cd backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

Run API + worker:

```bash
uvicorn app.main:app --reload
```

Generate demo traffic (writes synthetic packets into Redis):

```bash
python -m app.simulator.run --mode mixed
```

Optional socket-based sender (generates real UDP/TCP packets; capture requires Npcap/admin):

```bash
python -m app.simulator.socket_sender --mode udp --host 127.0.0.1 --port 9999 --seconds 3 --pps 150
python -m app.simulator.socket_sender --mode tcp --host 127.0.0.1 --port 22 --attempts 120
```

Scapy attack simulator (port scan, brute force, DDoS burst, and normal traffic):

```bash
python -m app.simulator.attack_scapy --mode mixed --target <YOUR_MACHINE_LAN_IP> --seconds 12 --pps 120
```

Tip (Windows): packet capture typically requires **Npcap** + running the terminal **as Administrator**.

Open docs:
- http://127.0.0.1:8000/docs

## Live packet capture (optional)

On Windows, Scapy sniffing typically requires **Npcap** and running the terminal **as Administrator**.

Enable capture by setting:

- `CAPTURE_ENABLED=true`
- `CAPTURE_IFACE=<your interface name>` (example: `Wi-Fi`)

Then run the API.

## Environment variables

- `REDIS_URL` (default `redis://localhost:6379/0`)
- `SQLITE_PATH` (default `./data/threats.db`)
- `VITE_WS_URL` is on the frontend side; backend WS endpoint is `/ws/alerts`

## Streams/channels

- Redis stream: `packets.raw`
- Redis stream: `alerts.stream`
- Redis pubsub channel: `alerts.live`
- Redis set: `blocklist.ips`

## Offline ML training (CICIDS2018)

This repo includes an offline trainer that builds:

- **Isolation Forest** for anomaly detection (trained on normal traffic only)
- **Random Forest** for attack classification

The trainer performs:

- Missing value handling (median imputation)
- Normalization (standard scaling)
- Protocol encoding into `protocol_code`

### Train

Download / extract the CICIDS2018 CSV files, then run (one or many CSVs):

```bash
cd backend
python -m app.detection.train_cicids2018 --data path\to\cicids2018_part1.csv path\to\cicids2018_part2.csv
```

Models are saved to `./data/models` by default:

- `isolation_forest.joblib`
- `random_forest.joblib`

### Predict (single flow JSON)

Create a JSON file with at least the feature keys used online:

- `flow_duration_s`
- `total_packets`
- `total_bytes`
- `avg_packet_size`
- `protocol` (or `protocol_code`)
- `connection_count_10s`
- `distinct_dst_ports_10s`
- `syn_count_10s`
- `rst_count_10s`

Then run:

```bash
cd backend
python -m app.detection.predict_flow --input path\to\flow.json
```

Output includes `anomaly_score` and `attack_type`.

## Optional tooling

Extra packages are listed in `requirements-optional.txt`:

- **PyShark / dpkt**: parse PCAP files and extract packet features for ML
- **MaxMind GeoIP2** (`geoip2`): resolve attacker IP → country/city for map visualization
- **Imbalanced-learn** (`imbalanced-learn`): SMOTE and other techniques for class imbalance

Notes:

- **SVM** is available via scikit-learn but is not currently trained/saved by the provided trainer.
- **TensorFlow / PyTorch** (LSTM autoencoder for sequence-based anomaly detection) is not implemented in this codebase yet because it requires sequence feature extraction; install manually if you add a deep model.
- **Suricata** (signature-based rules) is optional and installed outside Python.
