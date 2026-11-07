# 🐍 Py-IOC-Enricher: Threat Intelligence & SOAR Triage Tool

![Python](https://img.shields.io/badge/Language-Python_3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![SOAR](https://img.shields.io/badge/Integration-Shuffle_SOAR_%7C_Wazuh-FF6C37?style=for-the-badge&logo=fireship&logoColor=white)
![Threat Intel](https://img.shields.io/badge/API-AbuseIPDB-005571?style=for-the-badge)
![Blue Team](https://img.shields.io/badge/Focus-SOC_Alert_Triage-2496ED?style=for-the-badge)

## 📌 Overview

**Py-IOC-Enricher** is a Python automation script built for **SOC Tier 1/2 Alert Triage** and **SOAR Playbooks**. It queries external IPv4 Indicators of Compromise (IoCs) against the **AbuseIPDB REST API**, calculates a risk verdict based on abuse confidence scores, automatically **defangs** malicious indicators for safe incident reporting, and outputs structured JSON ready for **Shuffle SOAR** or **Wazuh** active response pipelines.

---

## ⚙️ Core Features
- **Automated Threat Intel Lookup:** Queries AbuseIPDB v2 API for abuse confidence score, ISP, country, usage type, and total reports.
- **Safe IOC Handling (Defanging):** Automatically converts malicious IPs to defanged format (e.g., `185[.]220[.]101[.]4`) so they can be safely pasted into SOC tickets.
- **SOAR-Ready JSON Output:** Supports a `--json` flag to return structured payloads for **Shuffle SOAR** workflows.
- **Zero External Dependencies:** Built strictly with Python's standard library (`urllib.request`, `json`, `argparse`) for instant execution in isolated environments.

---

## 🚀 Usage

### 1. Clone the Repository
```bash
git clone https://github.com/rcybershield/py-ioc-enricher.git
cd py-ioc-enricher
```

### 2. Run Standard SOC Analyst Report
```bash
export ABUSEIPDB_API_KEY="your_api_key_here"
python3 enricher.py -i 185.220.101.4
```

### 📊 Example Output (CLI Mode)
```text
=============================================================
 🛡️  PY-IOC-ENRICHER | Threat Intelligence Triage
=============================================================
[*] Target IOC (Defanged): 185[.]220[.]101[.]4
[*] Country / ISP:         DE | Zwiebelfreunde e.V.
[*] Total Reports:         412
[*] Abuse Confidence:      100%
[*] SOC Verdict:           [CRITICAL - BLOCK & ESCALATE]
=============================================================
```

### ⚡ Example Output (Shuffle SOAR `--json` Mode)
```json
{
  "ip": "185.220.101.4",
  "defanged_ip": "185[.]220[.]101[.]4",
  "abuse_score": 100,
  "total_reports": 412,
  "country": "DE",
  "isp": "Zwiebelfreunde e.V.",
  "verdict": "CRITICAL - BLOCK & ESCALATE"
}
```

---
*Developed by **Rafael Laporte** – [LinkedIn](https://www.linkedin.com/in/rafaellaporte)*
