# 🏛️ Technical Architecture & System Specifications

## 1. High-Level Architectural Principles
The platform is designed around **5 non-negotiable operational principles**:
1. **Non-Blocking Asynchronous I/O**: No synchronous blocking socket calls or subprocess waits inside async FastAPI routes.
2. **Deterministic Bounding & Timeouts**: Hard wall-clock limits and payload size streaming limits (e.g. 512KB HTTP repeater buffer, 10MB XML import cap, 180s Nmap scan timeout).
3. **Streaming over Buffering**: Incremental parsing of Nmap XML (`parse_nmap_xml_string`) and PCAP TCP streams so discoveries update live in the UI.
4. **Fail Loud & Safe**: Explicit error boundaries and defensive fallbacks (e.g. native connect-scan when Nmap binary is absent, browser-direct fetch when local daemon is unreachable).
5. **Unified Storage Schema**: Normalized findings table (`scan_findings`) utilized across DAST, SSL probes, Baseline Diffing, and Executive PDF/HTML reporting.

---

## 2. Component Breakdown & Data Flow

### A. Frontend Layer (Single Page Application)
* **Framework**: React 19 + TypeScript + Vite + Tailwind CSS.
* **State Management**: Zustand with `localStorage` persistent hydration.
* **Visualization Engine**:
  * **SVG Radial Topology Graph**: Concentric rings (Ring 0 = Scanner, Ring 1 = Intermediate Traceroute Hops, Ring 2 = Target Endpoints).
  * **Interactive HTTP Repeater**: Raw header/body builder with latency timers and SSRF guard confirmation modal.
  * **Packet Forensics**: TShark multi-stream reassembler with TLS keylog injection, Foremost/Scalpel magic-byte carver, and C2 beaconing jitter detector.
  * **Baseline Diff Tracker**: 4-way classification (`New`, `Resolved`, `Still-Open`, `Changed-Severity`).

### B. Gateway & Middleware Layer
* **FastAPI Backend (`backend/main.py`)**: Asynchronous REST & WebSocket coordinator running on port 8000.
* **Node Express Daemon (`backend/server.js`)**: Process manager and reverse-proxy on port 3001.
* **Security Middlewares**:
  * `WAFMiddleware`: SQLite-backed IP blocking filter.
  * `TokenBucketRateLimiter`: Per-host thread-safe token bucket enforcing concurrency and RPS limits.
  * `SSRFGuard`: Intercepts and warns when destination resolves to RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), Loopback (`127.0.0.1`), or Cloud Metadata (`169.254.169.254`).

### C. Core Processing Engines
```
┌────────────────────────┬─────────────────────────────────────────────────────────────┐
│ Module                 │ Internal Mechanism                                          │
├────────────────────────┼─────────────────────────────────────────────────────────────┤
│ Module 1: SSL Auditor  │ PyOpenSSL/cryptography X.509 cert parse + A+ to F rubric    │
│ Module 2: Orchestrator │ Async token-bucket rate limiter + declarative profiles     │
│ Module 3: Repeater     │ Exact socket-level header replay + 512KB streaming cap      │
│ Module 4: File Carver  │ Magic-byte offset scanning (PNG/JPG/PDF/ZIP/PE/ELF)         │
│ Module 5: GeoIP/ASN    │ Local cached IP resolution + precomputed spatial flow arcs  │
│ Module 6: C2 Beaconing │ Inter-arrival time deltas + Coefficient of Variation (CV)   │
│ Module 7: QUIC Decrypt │ TShark UDP/443 SSLKEYLOGFILE decryption pipeline            │
│ Module 8: CVSS 3.1     │ Official FIRST.org Base/Impact/Exploitability formula engine│
│ Module 9: Baseline Diff│ Deterministic (target, module, title, CWE) hash comparison  │
│ Module 13: Zenmap      │ Async subprocess exec + XML streaming parser + O(N) topology│
└────────────────────────┴─────────────────────────────────────────────────────────────┘
```

### D. Persistence Layer (SQLite WAL Mode)
* `scan_findings`: Consolidated vulnerability findings with consecutive count tracking.
* `carved_artifacts`: Extracted files, images, and binary blobs.
* `scan_reports`: Asynchronously generated executive reports and CVSS matrices.
* `security_events`: SIEM authentication logs and HTTP access events.
* `alerts`: Rule-triggered anomalous security alerts.

---

## 3. Security Boundary & Input Sanitization
* **Target Sanitization**: Strict regex validation `^[a-zA-Z0-9.\-_/:]+$` rejecting shell control characters.
* **Flag Immutability**: All scan parameters are typed into fixed string arrays passed directly to `asyncio.create_subprocess_exec(*cmd)`—strictly avoiding shell interpreters (`shell=True`).
* **XML Entity Defense**: External entity resolution is disabled across all XML parsers to prevent Billion Laughs / XXE exploits.