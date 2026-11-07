#!/usr/bin/env python3
"""
Py-IOC-Enricher: Automated IPv4 Threat Intelligence Triage Tool for SOC & Shuffle SOAR.
Author: Rafael Laporte (github.com/rcybershield)
"""

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def defang_ip(ip: str) -> str:
    """Replaces dots with [.] for safe inclusion in SOC incident tickets."""
    return ip.replace(".", "[.]")


def get_verdict(score: int) -> str:
    """Maps AbuseIPDB confidence score to a standardized SOC triage action."""
    if score >= 75:
        return "CRITICAL - BLOCK & ESCALATE"
    if score >= 25:
        return "SUSPICIOUS - INVESTIGATE LOGS"
    return "CLEAN / LOW RISK"


def query_abuseipdb(ip: str, api_key: str, max_age_days: int = 90) -> dict:
    """Queries the AbuseIPDB v2 API for a given IPv4 address."""
    query_params = urllib.parse.urlencode({
        "ipAddress": ip,
        "maxAgeInDays": str(max_age_days),
        "verbose": ""
    })
    url = f"{ABUSEIPDB_URL}?{query_params}"

    req = urllib.request.Request(url, method="GET")
    req.add_header("Key", api_key)
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
            data = payload.get("data", {})
            score = data.get("abuseConfidenceScore", 0)

            return {
                "ip": ip,
                "defanged_ip": defang_ip(ip),
                "abuse_score": score,
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "N/A"),
                "isp": data.get("isp", "Unknown"),
                "verdict": get_verdict(score)
            }
    except HTTPError as err:
        print(f"[!] HTTP Error {err.code}: Check your API key or rate limits.", file=sys.stderr)
        sys.exit(1)
    except URLError as err:
        print(f"[!] Network Error: {err.reason}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="SOC Triage Tool: Enrich IPv4 IOCs via AbuseIPDB API."
    )
    parser.add_argument("-i", "--ip", required=True, help="Target IPv4 address to inspect")
    parser.add_argument("-k", "--key", help="AbuseIPDB API Key (or set ABUSEIPDB_API_KEY env var)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON for Shuffle SOAR ingestion")
    args = parser.parse_args()

    api_key = args.key or os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        print("[!] Error: Provide an API key via --key or ABUSEIPDB_API_KEY environment variable.", file=sys.stderr)
        sys.exit(1)

    result = query_abuseipdb(args.ip, api_key)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("=============================================================")
        print(" 🛡️  PY-IOC-ENRICHER | Threat Intelligence Triage")
        print("=============================================================")
        print(f"[*] Target IOC (Defanged): {result['defanged_ip']}")
        print(f"[*] Country / ISP:         {result['country']} | {result['isp']}")
        print(f"[*] Total Reports:         {result['total_reports']}")
        print(f"[*] Abuse Confidence:      {result['abuse_score']}%")
        print(f"[*] SOC Verdict:           [{result['verdict']}]")
        print("=============================================================")


if __name__ == "__main__":
    main()
