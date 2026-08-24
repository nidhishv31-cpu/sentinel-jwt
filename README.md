# SentinelJWT - Security Suite & SIEM Engine

**SentinelJWT** is a full-stack security monitoring platform combining a JWT/Session Security Analyzer, a SIEM-lite Log Ingestion Engine, and a Network Packet Capture (PCAP) Analyzer. These components ingest diverse telemetry streams, normalize them into a unified SQLite schema, run rule-based and statistical threat detection algorithms, and stream live alerts and events in real time to a dark-themed glassmorphic dashboard.

---

## Technical Architecture

```
                                  [ TELEMETRY SOURCES ]
  ┌───────────────────────────┐ ┌───────────────────────────┐ ┌───────────────────────────┐
  │      JWT Token String     │ │   Access Logs (Nginx/AP)  │ │      PCAP/PCAPNG File     │
  └─────────────┬─────────────┘ └─────────────┬─────────────┘ └─────────────┬─────────────┘
                │                             │                             │
        (HTTP POST /analyze)         (HTTP POST /ingest)           (HTTP POST /upload)
                │                             │                             │
                ▼                             ▼                             ▼
  ┌───────────────────────────┐ ┌───────────────────────────┐ ┌───────────────────────────┐
  │    JWT Analyzer Module    │ │    Log Parser Module      │ │   PCAP Analyzer Module    │
  │  Safe Decode & Bruteforce │ │   Nginx / Apache / JSON   │ │   PyShark Field Extractor │
  └─────────────┬─────────────┘ └─────────────┬─────────────┘ └─────────────┬─────────────┘
                │                             │                             │
                │                             │                    (Cleartext Bearer JWT)
                │                             │                             │
                ▼                             ▼                             ▼
  ┌───────────────────────────────────────────────────────────────────────────────────────┐
  │                     Shared Database Schema & Event Pipeline (SQLite)                  │
  └───────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
  ┌───────────────────────────────────────────────────────────────────────────────────────┐
  │                           SIEM Detection Rules Engine                                 │
  │    Brute-force (Sliding Window & Poisson Process), Credential Stuffing, Impossible     │
  │    Travel, Off-hours Access, Port Scans, DNS Tunneling, ARP Spoofing, Beaconing       │
  └───────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                     (WebSocket /ws/live)
                                              │
                                              ▼
  ┌───────────────────────────────────────────────────────────────────────────────────────┐
  │                            React & TypeScript UI Dashboard                            │
  └───────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Core Detection Capabilities

SentinelJWT runs **10 threat detection models** over the normalized event pipeline:

### 1. JWT Security Analyzer
- **Algorithm Strength**: Flags insecure `alg: "none"` (Critical) and alerts on potential asymmetric key confusion (RS256 vs HS256) (Medium).
- **Expiration Audit**: Identifies tokens missing `exp` (High), expired tokens (High), or excessively long lifespans (`exp - iat > 24h`) (Medium).
- **Claim Compliance**: Validates the presence of standard claims: `iat`, `sub`, `aud` (Low).
- **Secret Brute Force**: Runs an automated check of HS256 signatures against a dictionary of weak/common secrets (Critical).
- **Entropy Score**: Computes the Shannon entropy of tested keys. If entropy < 3.5 bits/char or key length < 16, flags it (Medium).

### 2. SIEM Log Analysis
- **Sliding Window Brute Force**: Detects >5 failed logins (401/403) from a single IP within a rolling 5-minute window.
- **Statistical Poisson Anomaly**: Measures historical failed login rates per IP to compute baseline expected failures ($\lambda$). If the observed count ($k$) yields a Poisson probability $P(X \ge k) < 0.01$, flags an anomaly even if counts are below the fixed window threshold.
- **Credential Stuffing**: Detects single IPs targeting >3 distinct usernames in a 5-minute rolling window.
- **Impossible Travel**: Calculates the Great-Circle distance and travel velocity between consecutive successful logins for a single account. If velocity > 900 km/h, raises a High Alert.
- **Off-hours Access**: Flags logins outside a user's standard work hours (9 AM - 6 PM), weighted by their historical login hour distribution.
- **JWT Correlation (Token Attack)**: Escalates to a Critical Alert if an IP has >3 `jwt_finding` events combined with active failed login logs.

### 3. PCAP Packet Analyzer
- **Cleartext Credentials**: Decodes Basic Auth header blocks in unencrypted HTTP headers, parses FTP `USER`/`PASS` packet commands, and extracts transit Bearer JWTs (which are automatically audited via the JWT analyzer).
- **Port Scan**: Identifies a single source IP sending SYN packets (without ACK) to >20 distinct ports on a destination within a 10s window.
- **DNS Tunnel Heuristic**: Flags query domains with lengths > 50 characters or subdomain labels with Shannon entropy > 4.2.
- **ARP Spoofing**: Identifies when a single IP maps to multiple distinct MAC addresses in the capture.
- **Beaconing**: Measures inter-arrival times of connections from a source to an external IP. Highly regular intervals (CV = Standard Deviation / Mean < 0.08 over >= 6 packets) trigger alerts.

---

## Local Setup & Quick Start

### Prerequisites
- **Python**: Version 3.10 or higher (Tested on Python 3.14).
- **Node.js**: Version 18 or higher (with `npm`).
- **tshark**: Packet captures parsing requires `tshark` (Wireshark command-line engine).
  - **Windows**: Install Wireshark. It installs `tshark.exe` by default.
  - **Ubuntu/Debian**: Run `sudo apt-get install tshark`.

### Installation

1. Clone or navigate to the SentinelJWT folder:
   ```bash
   cd sentinel-jwt
   ```

2. Setup Backend Virtual Environment:
   ```bash
   cd backend
   python -m venv venv
   # Activate:
   # Windows PowerShell: .\venv\Scripts\Activate.ps1
   # Linux/macOS: source venv/bin/activate
   pip install -r requirements.txt
   ```

3. Setup Frontend Node Dependencies:
   ```bash
   cd ../frontend
   npm install
   ```

---

## Running the Application

SentinelJWT comes with a helper batch script for Windows to run both servers concurrently. From the root directory:

```bash
run.bat
```

Or start them manually in separate shells:

**Start FastAPI Backend:**
```bash
cd backend
# With venv activated:
uvicorn main:app --reload --port 8000
```

**Start Vite React Frontend:**
```bash
cd frontend
npm run dev
```
Open [http://localhost:5173/](http://localhost:5173/) to inspect the UI dashboard.

---

## Running Automated Tests

To execute the self-contained backend threat rules test suite:

```bash
cd backend
# With venv activated:
python test_backend.py
```

---

## Live Capture Mode & PCAP Guidelines

- **Hosted Uploads**: Uploading PCAP files works out of the box using remote file ingestion.
- **Live Capture Mode**: To execute live network captures (`tshark -i <interface>`), you must run the server locally with appropriate administrator privileges. On Linux, grant capabilities to dump traffic:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark
  ```
  Provide the `--enable-live-capture` flag when running the FastAPI server.
- **Generating Telemetry**: You can export your own test captures in Wireshark:
  1. Set the system environment variable `SSLKEYLOGFILE` to point to a file path.
  2. Start a browser and navigate to HTTP/HTTPS websites.
  3. Export packets from Wireshark via **File > Export Specified Packets**.
  
> [!CAUTION]
> Packet capture and analysis must only be performed on networks or traffic you own or have explicit authorization to monitor.
