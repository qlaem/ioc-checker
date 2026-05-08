# IOC Checker (PowerShell Threat Intelligence Tool)

## Overview
This PowerShell script analyzes a list of IP addresses against the AbuseIPDB threat intelligence API. It identifies malicious or suspicious IPs based on abuse confidence scores and exports results into a structured CSV report for further analysis or SIEM ingestion.

## Features
- Queries AbuseIPDB API for IP reputation data
- Flags IPs based on configurable confidence threshold
- Supports bulk IOC (IP) analysis
- Exports structured results to CSV for SIEM or reporting
- Handles API errors gracefully
- Built-in rate limiting for API compliance

## Use Cases
- Threat hunting
- Security incident response
- IOC validation
- Log enrichment for SIEM platforms (Splunk, Sentinel, etc.)
- Proactive environment scanning

## Requirements
- PowerShell 5.1+
- AbuseIPDB API Key (free tier available)
- Internet access for API requests

## Setup
1. Clone the repository
2. Set your API key as an environment variable:

```powershell
setx ABUSEIPDB_API_KEY "your_api_key_here"

# Executes the IOC checker to:
# - Query AbuseIPDB for IP reputation data
# - Evaluate IPs against abuse confidence threshold
# - Generate a CSV report for SIEM ingestion or threat hunting workflows

.\Invoke-IOCChecker.ps1


---

### After you paste it:
- Scroll down
- Click **Commit new file**

---

Once you’ve done that, reply:

**“done”**

and I’ll move you to Step 4 — which is where we make this look like a *real cybersecurity project recruiters actually respect* (badges, structure, and how to present it on your resume).
