# AegisVuln: Intelligent Vulnerability Assessment & Automated Risk Analysis Report Generator

## Overview
AegisVuln is a full-stack cybersecurity engineering platform built with **Python, Nmap, Flask, SQLite, ReportLab, and Vanilla JS/Chart.js**. It performs authorized, non-destructive service enumeration, correlates exact software versions against the **NIST NVD API v2.0**, separates **Confirmed CVEs** from **Potential Security Risks**, computes **Contextual Risk Priority Scores**, tracks historical remediation drift, supports optional **Tenable Nessus** imports, and generates executive-grade **PDF Assessment Reports**.

---

## Step-by-Step Installation & Setup

### 1. Prerequisites
* **Python 3.10+**
* **Nmap** (Required for live local network scans; optional if using Localhost Safe Demo Mode)
  * **Ubuntu/Debian:** `sudo apt update && sudo apt install -y nmap`
  * **macOS:** `brew install nmap`
  * **Windows:** Download the official Nmap installer from `https://nmap.org/download.html` and add `C:\Program Files (x86)\Nmap` to your System `PATH`.

### 2. Environment Setup
```bash
cd intelligent-vuln-scanner

python -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows PowerShell:
# .\venv\Scripts\Activate.ps1

pip install -r requirements.txt
cp .env.example .env
```

### 3. NVD & Nessus API Configuration (Optional)
* **NIST NVD API Key:** Request a free key at `https://nvd.nist.gov/developers/request-an-api-key` and set `NVD_API_KEY` in `.env` to increase throughput from 5 to 50 requests per 30 seconds.
* **Tenable Nessus:** Either configure `NESSUS_URL`, `NESSUS_ACCESS_KEY`, and `NESSUS_SECRET_KEY` in `.env` or upload exported `.nessus` XML files directly in the dashboard.

### 4. Initialize Baseline Demo Data & Run Application
```bash
python seed_demo_data.py
python app.py
```
Open **`http://127.0.0.1:5000`** in your browser.

### 5. Running Automated Tests
```bash
pytest -v
```

---

## Troubleshooting Guide
* **`Nmap executable 'nmap' was not found in PATH`**: Verify `nmap --version` works in your terminal or set the full executable path in `.env` (`NMAP_BINARY_PATH=C:\Program Files (x86)\Nmap\nmap.exe`). You can also use **Localhost Safe Demo Mode** without Nmap installed.
* **`Target IP is outside authorized RFC1918/localhost scope`**: By design, AegisVuln blocks scanning public internet IPs unless explicitly added to `ALLOWED_TARGET_CIDRS` in `.env`.
* **OS Detection shows `Unknown / Filtered`**: Nmap OS fingerprinting (`-O`) requires raw socket privileges (`sudo` on Linux/macOS or Administrator + Npcap on Windows). Standard service/version scans (`-sT -sV`) work without elevated privileges.
* **NVD API Rate Limit (HTTP 429)**: The correlator automatically enforces request spacing and falls back to its local SQLite cache and verified advisory baseline if NIST throttles unauthenticated traffic.
