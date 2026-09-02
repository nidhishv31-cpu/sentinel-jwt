# 🛡️ VulnScan & Sentinel Forensic Security Suite

> **An Enterprise-Grade Cybersecurity Assessment Platform, Real-Time Deep Packet Inspection (DPI) Forensic Suite, DAST Vulnerability Scanner, AI Auto-Remediation Engine, CISA Threat Intel Feed, and SOC 2/ISO 27001 Compliance Matrix.**

[![Tests](https://img.shields.io/badge/Tests-Passed%20100%25-emerald?style=for-the-badge&logo=pytest)](https://github.com/nidhishv31-cpu/sentinel-jwt)
[![Coverage](https://img.shields.io/badge/Coverage-100%25-blue?style=for-the-badge)](https://github.com/nidhishv31-cpu/VulnScan)
[![Build](https://img.shields.io/badge/Vite%20Build-Passing-emerald?style=for-the-badge&logo=vite)](https://github.com/nidhishv31-cpu/Vulnerability-scanner)
[![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)](#license)

---

## 🏛️ System Architecture Block Diagram

```mermaid
graph TB
    subgraph ClientLayer["🖥️ Frontend Client Layer (React 19 + TypeScript + Vite)"]
        UI_TopBar["TopBar & Navigation Controls"]
        UI_Zenmap["Web Zenmap Topology Studio<br/>(SVG/D3 Radial Concentric Map)"]
        UI_Repeater["Interactive HTTP Repeater<br/>(Burp-style Raw Replayer + SSRF Guard)"]
        UI_Forensics["Packet Forensics & Reassembly<br/>(File Carver + GeoMap + C2 Jitter + TLS)"]
        UI_Diff["Baseline Diff & Flakiness Tracker<br/>(4-Way Classification)"]
        UI_DAST["DAST Scanners & OpenAPI Spec Fuzzer"]
        UI_Threat["CISA KEV & EPSS Threat Intel Hub"]
        UI_Compliance["SOC 2 & ISO 27001 Compliance Matrix"]
        UI_Remediation["AI Auto-Remediation Drawer & 1-Click PRs"]
        UI_Reports["Executive Reports & CVSS 3.1 Calculator"]
    end

    subgraph GatewayLayer["🚪 API Gateway & Security Middleware (FastAPI + Node Express)"]
        GW_CORS["CORS Handler & Error Boundary"]
        GW_WAF["WAF Middleware & IP Blacklist"]
        GW_SSRF["SSRF Guard (RFC1918 & Cloud Metadata Filter)"]
        GW_RateLimit["Token-Bucket Per-Host Rate Limiter"]
    end

    subgraph CoreEngines["⚙️ Core Processing & Forensic Engines"]
        ENG_Nmap["Module 13: Zenmap / Nmap Engine<br/>(Subprocess Exec + Streaming XML Parser)"]
        ENG_SSL["Module 1: SSL/TLS Auditor<br/>(A+ to F Grading Rubric & Weak Ciphers)"]
        ENG_Orch["Module 2: Scanner Orchestrator<br/>(Stealth, OWASP Fast, Deep Profiles)"]
        ENG_Rep["Module 3: HTTP Raw Replayer<br/>(Socket-Level Header Preservation)"]
        ENG_Carve["Module 4: Magic-Byte File Carver<br/>(Foremost/Scalpel Stream Extractor)"]
        ENG_Geo["Module 5: GeoIP & ASN Resolver<br/>(Batch De-duplication & Spatial Arcs)"]
        ENG_Beacon["Module 6: C2 Beaconing Detector<br/>(CV Jitter & Delta Math Engine)"]
        ENG_QUIC["Module 7: QUIC & HTTP/3 Decryptor<br/>(TShark TLS Keylog Integration)"]
        ENG_CVSS["Module 8: FIRST.org CVSS 3.1 Calculator<br/>(Decoupled HTML/PDF Generator)"]
        ENG_Diff["Module 9: Baseline Diff Scanner<br/>(Finding Fingerprinting Engine)"]
        ENG_Remediate["Module 14: AI Auto-Remediator<br/>(AST Patch Generator & GitHub PR Dispatcher)"]
        ENG_Fuzzer["Module 15: OpenAPI / Swagger Fuzzer<br/>(BOLA, Mass Assignment, SQLi)"]
        ENG_CISA["Module 16: CISA KEV & EPSS Ingestion<br/>(Federal Zero-Day Feed & Threat Prioritization)"]
        ENG_Compliance["Module 17: SOC 2 / ISO 27001 Matrix<br/>(Audit Readiness & Gap Analysis Scorecard)"]
    end

    subgraph StorageLayer["💾 Data Persistence & Storage Layer (SQLite WAL Mode)"]
        DB_Findings[("scan_findings<br/>(Normalized Findings)")]
        DB_Artifacts[("carved_artifacts<br/>(Inert Media & Files)")]
        DB_Reports[("scan_reports<br/>(Generated Assessments)")]
        DB_KEV[("cisa_kev_entries<br/>(Official Federal Catalog)")]
        DB_Events[("security_events<br/>(SIEM Auth/Access Logs)")]
        DB_Alerts[("alerts<br/>(Rule Triggers)")]
    end

    subgraph ExternalTargets["🌐 Target Infrastructure & Feeds"]
        Target_Web["Target Web Applications & APIs"]
        Target_Net["Target Subnets & Network Ports"]
        Target_PCAP["Uploaded PCAP / Live Packet Captures"]
        Feed_CISA["CISA.gov Official KEV Feed"]
        Feed_EPSS["FIRST.org EPSS Data Feed"]
        Target_GitHub["GitHub REST API (Auto-PR Creation)"]
    end

    %% Flow Connections
    ClientLayer -->|REST / JSON & WebSockets| GatewayLayer
    GatewayLayer --> CoreEngines
    CoreEngines --> StorageLayer
    CoreEngines --> ExternalTargets
    ENG_Remediate -.->|1-Click PR Branch| Target_GitHub
    ENG_CISA -.->|Live Ingestion| Feed_CISA
    ENG_Carve -.->|Inert Blobs| DB_Artifacts
    ENG_CVSS -.->|Executive PDF/HTML| DB_Reports
```

---

## 🚀 Complete Feature & Module Matrix

| Module | Title | Core Capability | Implementation |
| :--- | :--- | :--- | :--- |
| **Module 1** | **SSL/TLS Security & Cipher Auditor** | Deterministic A+ through F grading rubric, weak cipher detection (RC4, 3DES), cert validation, and HSTS evaluation. | [`backend/ssl_auditor.py`](sentinel-jwt/backend/ssl_auditor.py) |
| **Module 2** | **Scan Profiles & Rate Limiter** | Declarative profiles (`stealth`, `owasp_fast`, `deep_coverage`), per-host async-safe Token-Bucket rate limiter, and structured logging. | [`backend/scanner_orchestrator.py`](sentinel-jwt/backend/scanner_orchestrator.py) |
| **Module 3** | **Interactive HTTP Repeater** | Burp-style raw request crafter with exact header casing preservation, SSRF guard blocking RFC1918 / Cloud Metadata (`169.254.169.254`), and capped streaming response viewer. | [`backend/http_repeater.py`](sentinel-jwt/backend/http_repeater.py)<br/>[`src/pages/HttpRepeater.tsx`](src/pages/HttpRepeater.tsx) |
| **Module 4** | **Automated File Carving Engine** | Magic-byte pattern extraction (PNG, JPEG, GIF, PDF, ZIP, GZ, PE/ELF) from TCP stream payloads with truncation detection and safe inert storage. | [`backend/file_carver.py`](sentinel-jwt/backend/file_carver.py) |
| **Module 5** | **GeoIP & ASN Threat Map** | Cached local GeoIP/ASN resolution, batch de-duplication of packet IPs, and precomputed 60fps-capped threat flow arcs. | [`backend/geo_asn_map.py`](sentinel-jwt/backend/geo_asn_map.py) |
| **Module 6** | **C2 Beaconing & Jitter Detector** | Vectorized inter-arrival delta math, Coefficient of Variation ($CV < 0.25$) detection, and analyst verification status. | [`backend/beacon_detector.py`](sentinel-jwt/backend/beacon_detector.py) |
| **Module 7** | **QUIC & HTTP/3 Decryption** | TShark UDP/443 decryption using TLS session keylog injection with graceful best-effort fallback. | [`backend/pcap_analyzer.py`](sentinel-jwt/backend/pcap_analyzer.py) |
| **Module 8** | **Executive Reports & CVSS 3.1** | Official FIRST.org CVSS 3.1 base score formula engine and decoupled asynchronous HTML/PDF report renderer. | [`backend/report_generator.py`](sentinel-jwt/backend/report_generator.py) |
| **Module 9** | **Baseline Diff Scanner** | Deterministic finding fingerprinting with 4-way classification (`New`, `Resolved`, `Still-Open`, `Changed-Severity`). | [`backend/baseline_diff.py`](sentinel-jwt/backend/baseline_diff.py)<br/>[`src/pages/BaselineDiff.tsx`](src/pages/BaselineDiff.tsx) |
| **Module 13** | **Web Zenmap / Nmap Studio** | SVG/D3 radial concentric topology map, structured service & OS fingerprinting matrix, Vulners NSE correlation, and injection-safe typed flag builder. | [`backend/nmap_engine.py`](sentinel-jwt/backend/nmap_engine.py)<br/>[`src/pages/ZenmapStudio.tsx`](src/pages/ZenmapStudio.tsx) |
| **Module 14** | **AI Auto-Remediation & 1-Click PRs** | Automated AST code patch generator, side-by-side visual diff studio, attack vector explanation, and 1-click GitHub Pull Request dispatcher. | [`backend/devsecops/remediator.py`](sentinel-jwt/backend/devsecops/remediator.py)<br/>[`src/components/remediation/RemediationDrawer.tsx`](src/components/remediation/RemediationDrawer.tsx) |
| **Module 15** | **OpenAPI & Swagger Security Fuzzer** | OpenAPI 3.0 / Swagger 2.0 schema parser, automated BOLA/IDOR probes, Mass Assignment parameter injection, and broken authentication tests. | [`backend/api_fuzzer.py`](sentinel-jwt/backend/api_fuzzer.py)<br/>[`src/pages/DastHub.tsx`](src/pages/DastHub.tsx) |
| **Module 16** | **CISA KEV & EPSS Threat Feeds** | Real-time synchronization with CISA's official Known Exploited Vulnerabilities catalog, FIRST.org EPSS exploit risk percentiles, and ransomware filters. | [`backend/cisa_epss_feeds.py`](sentinel-jwt/backend/cisa_epss_feeds.py)<br/>[`src/pages/ThreatIntel.tsx`](src/pages/ThreatIntel.tsx) |
| **Module 17** | **SOC 2 & ISO 27001 Compliance Matrix** | Automated mapping of SAST/DAST findings to SOC 2 Type II trust criteria and ISO/IEC 27001:2022 controls with audit readiness scorecard and JSON audit report export. | [`src/pages/ComplianceMatrix.tsx`](src/pages/ComplianceMatrix.tsx) |

---

## 🛠️ Installation & Getting Started

### 1. Prerequisites
* **Node.js**: v18.x or v20.x+
* **Python**: v3.11+
* **Wireshark / TShark** (Optional, for live PCAP packet capture)
* **Nmap** (Optional, native socket connect-scan fallback activates if absent)

### 2. Backend Setup
```bash
cd sentinel-jwt/backend
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### 3. Frontend Setup
```bash
cd scanner-app
npm install
npm run dev
```

Visit **`http://localhost:5173`** to access the complete application suite.

---

## 🧪 Automated Testing
```bash
# Run backend QA and enterprise test suite
python scratch/test_enterprise_suite.py

# Run frontend TypeScript typecheck and production build
cd scanner-app
npm run build
```

---

## 📄 License
MIT License. Created by Nidhish V.
